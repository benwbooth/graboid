use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::Utc;
use futures::StreamExt;
use globset::{Glob, GlobSet, GlobSetBuilder};
use regex::Regex;
use reqwest::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use tokio::sync::{Mutex, Semaphore, broadcast, mpsc};
use tokio::{fs, io::AsyncWriteExt};
use tracing::{error, warn};

use crate::archives::{default_extract_dir, extract_archive, is_archive};
use crate::claude::{NavEvent, NavigationOutcome, run_navigation};
use crate::config::AppConfig;
use crate::db::JobDb;
use crate::events::ServerEvent;
use crate::models::{Job, JobPhase, JobStatus};
use crate::state::RuntimeState;
use crate::torrent;

// 1x1 PNG placeholder when we do not have a real browser frame available.
const PLACEHOLDER_PNG: &[u8] = &[
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x04, 0x00, 0x00, 0x00, 0xB5, 0x1C, 0x0C,
    0x02, 0x00, 0x00, 0x00, 0x0B, 0x49, 0x44, 0x41, 0x54, 0x78, 0xDA, 0x63, 0x60, 0x60, 0x00, 0x00,
    0x00, 0x03, 0x00, 0x01, 0x2B, 0x09, 0x4D, 0x84, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44,
    0xAE, 0x42, 0x60, 0x82,
];

const MAX_BROWSE_ATTEMPTS: usize = 3;

#[derive(Clone)]
pub struct JobRunner {
    db: Arc<JobDb>,
    events: broadcast::Sender<ServerEvent>,
    runtime: Arc<RuntimeState>,
    queue_tx: mpsc::Sender<String>,
    handles: Arc<Mutex<HashMap<String, tokio::task::JoinHandle<()>>>>,
    config: Arc<AppConfig>,
    http_client: reqwest::Client,
}

impl JobRunner {
    pub fn new(
        db: Arc<JobDb>,
        events: broadcast::Sender<ServerEvent>,
        runtime: Arc<RuntimeState>,
        config: Arc<AppConfig>,
    ) -> Arc<Self> {
        let (queue_tx, queue_rx) = mpsc::channel::<String>(1024);

        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.download_timeout_seconds))
            .danger_accept_invalid_certs(config.download_allow_insecure)
            .user_agent("graboid-rs/0.1")
            .build()
            .expect("reqwest client init should not fail");

        let runner = Arc::new(Self {
            db,
            events,
            runtime,
            queue_tx,
            handles: Arc::new(Mutex::new(HashMap::new())),
            config,
            http_client,
        });

        runner.clone().spawn_dispatcher(queue_rx);
        runner
    }

    fn spawn_dispatcher(self: Arc<Self>, mut queue_rx: mpsc::Receiver<String>) {
        tokio::spawn(async move {
            let semaphore = Arc::new(Semaphore::new(self.config.jobs_max_concurrent.max(1)));

            while let Some(job_id) = queue_rx.recv().await {
                let permit = match semaphore.clone().acquire_owned().await {
                    Ok(permit) => permit,
                    Err(err) => {
                        error!("dispatcher semaphore closed: {err}");
                        break;
                    }
                };

                let runner = self.clone();
                let job_id_for_task = job_id.clone();

                let handle = tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(err) = runner.execute_job(job_id_for_task.clone()).await {
                        error!(job_id = %job_id_for_task, "job execution failed: {err:#}");
                    }
                    runner.handles.lock().await.remove(&job_id_for_task);
                });

                self.handles.lock().await.insert(job_id, handle);
            }
        });
    }

    pub async fn enqueue(&self, job_id: String) -> Result<()> {
        self.queue_tx
            .send(job_id)
            .await
            .context("job queue is closed")
    }

    pub async fn cancel(&self, job_id: &str) -> Result<bool> {
        let mut maybe_job = self.db.get_job(job_id).await?;
        let Some(mut job) = maybe_job.take() else {
            return Ok(false);
        };

        if job.status.is_terminal() {
            return Ok(false);
        }

        if let Some(handle) = self.handles.lock().await.remove(job_id) {
            handle.abort();
        }

        job.set_status(JobStatus::Cancelled);
        job.set_phase(JobPhase::Done);
        job.set_progress(job.progress_percent, "Cancelled");
        job.error_message = "Cancelled by request".to_string();

        self.db.update_job(&job).await?;
        self.broadcast(ServerEvent::JobUpdate(job.clone()));
        self.log(&job.id, "WARNING", "runner", "Job cancelled")
            .await?;

        Ok(true)
    }

    async fn execute_job(&self, job_id: String) -> Result<()> {
        let Some(mut job) = self.db.get_job(&job_id).await? else {
            return Ok(());
        };

        if job.status == JobStatus::Cancelled {
            return Ok(());
        }

        self.set_runtime_status(true, format!("Job {}", job.id))
            .await;

        self.log(&job.id, "INFO", "runner", "Job started").await?;
        job.set_status(JobStatus::Running);
        job.set_phase(JobPhase::Init);
        job.set_progress(1.0, "Initializing");
        self.persist_job(&job).await?;

        let credential = if let Some(name) = job.credential_name.as_ref() {
            match self.db.get_credential(name).await? {
                Some(entry) => {
                    self.log(
                        &job.id,
                        "INFO",
                        "browse",
                        &format!("Using credential profile '{}'", name),
                    )
                    .await?;
                    Some((entry.username, entry.password))
                }
                None => {
                    self.log(
                        &job.id,
                        "WARNING",
                        "browse",
                        &format!("Credential '{}' not found; continuing without it", name),
                    )
                    .await?;
                    None
                }
            }
        } else {
            None
        };

        let mut failed_urls: Vec<String> = Vec::new();
        for browse_attempt in 1..=MAX_BROWSE_ATTEMPTS {
            let browse_message = if browse_attempt == 1 {
                "Launching browser and searching for sources".to_string()
            } else {
                format!(
                    "Searching for alternative sources ({browse_attempt}/{MAX_BROWSE_ATTEMPTS})"
                )
            };
            job.set_status(JobStatus::Browsing);
            job.set_phase(JobPhase::Browse);
            job.set_progress(10.0, browse_message);
            self.persist_job(&job).await?;

            let prompt = augment_prompt_with_failed_urls(&job.prompt, &failed_urls);
            let navigation = match self
                .run_navigation_attempt(&mut job, &prompt, credential.clone())
                .await
            {
                Ok(outcome) => outcome,
                Err(err) => {
                    self.log(
                        &job.id,
                        "WARNING",
                        "browse",
                        &format!(
                            "Browse attempt {browse_attempt}/{MAX_BROWSE_ATTEMPTS} failed: {err}"
                        ),
                    )
                    .await?;

                    if browse_attempt < MAX_BROWSE_ATTEMPTS {
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        continue;
                    }

                    job.fail(format!(
                        "Browse failed after {MAX_BROWSE_ATTEMPTS} attempts: {err}"
                    ));
                    self.persist_job(&job).await?;
                    self.log(&job.id, "ERROR", "browse", &job.error_message)
                        .await?;
                    self.set_runtime_status(false, String::new()).await;
                    return Ok(());
                }
            };

            self.apply_navigation_outcome(&mut job, &navigation).await?;
            self.persist_job(&job).await?;

            if job.downloaded_files.is_empty() && job.found_urls.is_empty() {
                if browse_attempt < MAX_BROWSE_ATTEMPTS {
                    self.log(
                        &job.id,
                        "WARNING",
                        "browse",
                        "No download links found; retrying source discovery",
                    )
                    .await?;
                    continue;
                }

                job.fail("No download links or files were found");
                self.persist_job(&job).await?;
                self.log(&job.id, "ERROR", "browse", &job.error_message)
                    .await?;
                self.set_runtime_status(false, String::new()).await;
                return Ok(());
            }

            if job.downloaded_files.is_empty() {
                job.set_status(JobStatus::Downloading);
                job.set_phase(JobPhase::Download);
                job.set_progress(45.0, "Downloading files");
                self.persist_job(&job).await?;

                let mut downloaded = Vec::new();
                let mut failed_this_attempt = Vec::new();
                let urls = job.found_urls.clone();
                let total_items = urls.len().max(1);
                let total = total_items as f64;
                let mut completed = 0usize;

                let mut torrent_urls = Vec::new();
                let mut direct_urls = Vec::new();
                for url in urls {
                    if url.starts_with("magnet:") || url.ends_with(".torrent") {
                        torrent_urls.push(url);
                    } else {
                        direct_urls.push(url);
                    }
                }

                for url in torrent_urls {
                    match torrent::add_torrent(self.config.as_ref(), &url).await {
                        Ok(torrent_id) => {
                            self.log(
                                &job.id,
                                "INFO",
                                "download",
                                &format!("Queued torrent {torrent_id} from {url}"),
                            )
                            .await?;
                            downloaded.push(format!("torrent:{url}"));
                        }
                        Err(err) => {
                            failed_this_attempt.push(url.clone());
                            self.log(
                                &job.id,
                                "WARNING",
                                "download",
                                &format!("Failed to queue torrent {url}: {err}"),
                            )
                            .await?;
                        }
                    }

                    completed += 1;
                    let pct = 45.0 + ((completed as f64) / total) * 35.0;
                    job.set_progress(pct, format!("Downloading {completed}/{total_items}"));
                    self.persist_job(&job).await?;
                }

                if !direct_urls.is_empty() {
                    let parallelism = self.config.download_max_parallel.max(1);
                    let job_id_for_download = job.id.clone();

                    let mut stream = futures::stream::iter(direct_urls.into_iter().map(|url| {
                        let job_id = job_id_for_download.clone();
                        async move {
                            let result = self.download_with_retries(&job_id, &url).await;
                            (url, result)
                        }
                    }))
                    .buffer_unordered(parallelism);

                    while let Some((url, result)) = stream.next().await {
                        match result {
                            Ok(path) => downloaded.push(path.display().to_string()),
                            Err(err) => {
                                failed_this_attempt.push(url.clone());
                                self.log(
                                    &job.id,
                                    "WARNING",
                                    "download",
                                    &format!("Failed {url}: {err}"),
                                )
                                .await?;
                            }
                        }

                        completed += 1;
                        let pct = 45.0 + ((completed as f64) / total) * 35.0;
                        job.set_progress(pct, format!("Downloading {completed}/{total_items}"));
                        self.persist_job(&job).await?;
                    }
                }

                job.downloaded_files = downloaded;
                self.persist_job(&job).await?;

                if job.downloaded_files.is_empty() {
                    self.record_source_notes(&job.found_urls, false, Some("all downloads failed"))
                        .await;
                    merge_unique_strings(&mut failed_urls, &job.found_urls);
                    merge_unique_strings(&mut failed_urls, &failed_this_attempt);

                    if browse_attempt < MAX_BROWSE_ATTEMPTS {
                        self.log(
                            &job.id,
                            "WARNING",
                            "runner",
                            "Downloads failed; retrying with alternative sources",
                        )
                        .await?;
                        job.found_urls.clear();
                        continue;
                    }
                }
            }

            if !job.downloaded_files.is_empty() {
                break;
            }
        }

        if job.downloaded_files.is_empty() {
            job.fail("All downloads failed");
            self.persist_job(&job).await?;
            self.log(&job.id, "ERROR", "download", &job.error_message)
                .await?;
            self.set_runtime_status(false, String::new()).await;
            return Ok(());
        }

        self.record_source_notes(&job.found_urls, true, None).await;

        job.set_status(JobStatus::Extracting);
        job.set_phase(JobPhase::Extract);
        job.set_progress(75.0, "Extracting archives");
        self.persist_job(&job).await?;

        let mut extracted_files = Vec::new();
        for file in &job.downloaded_files {
            if file.starts_with("torrent:") {
                extracted_files.push(file.clone());
                continue;
            }

            let path = PathBuf::from(file);
            if !path.exists() {
                self.log(
                    &job.id,
                    "WARNING",
                    "extract",
                    &format!("Skipping missing file {}", path.display()),
                )
                .await?;
                continue;
            }

            if is_archive(&path) {
                let extract_dir = default_extract_dir(&path);
                self.log(
                    &job.id,
                    "INFO",
                    "extract",
                    &format!(
                        "Extracting archive {} -> {}",
                        path.display(),
                        extract_dir.display()
                    ),
                )
                .await?;

                match extract_archive(path.clone(), extract_dir.clone(), job.file_filter.clone())
                    .await
                {
                    Ok(paths) if !paths.is_empty() => {
                        for extracted in paths {
                            extracted_files.push(extracted.display().to_string());
                        }
                    }
                    Ok(_) => {
                        self.log(
                            &job.id,
                            "WARNING",
                            "extract",
                            &format!("Archive {} extracted no matching files", path.display()),
                        )
                        .await?;
                    }
                    Err(err) => {
                        self.log(
                            &job.id,
                            "WARNING",
                            "extract",
                            &format!("Failed to extract {}: {err}", path.display()),
                        )
                        .await?;
                        extracted_files.push(file.clone());
                    }
                }
            } else {
                extracted_files.push(file.clone());
            }
        }

        job.downloaded_files = extracted_files;
        self.persist_job(&job).await?;

        if !job.file_filter.is_empty() {
            let matcher = build_file_filter_matcher(&job.file_filter);
            let before = job.downloaded_files.len();
            job.downloaded_files
                .retain(|path| filter_matches(&matcher, path));
            let kept = job.downloaded_files.len();

            self.log(
                &job.id,
                "INFO",
                "extract",
                &format!(
                    "Applied file filter patterns: kept {kept}/{before} files ({} removed)",
                    before.saturating_sub(kept)
                ),
            )
            .await?;
            self.persist_job(&job).await?;
        }

        if job.downloaded_files.is_empty() {
            job.fail("No files matched the requested file filters");
            self.persist_job(&job).await?;
            self.log(&job.id, "ERROR", "extract", &job.error_message)
                .await?;
            self.set_runtime_status(false, String::new()).await;
            return Ok(());
        }

        job.set_status(JobStatus::Copying);
        job.set_phase(JobPhase::Copy);
        job.set_progress(85.0, "Copying files to destination");
        self.persist_job(&job).await?;

        job.final_paths = self
            .copy_outputs(
                &job.id,
                &job.downloaded_files,
                &job.destination_path,
                &job.file_operation,
            )
            .await?;

        job.set_status(JobStatus::Complete);
        job.set_phase(JobPhase::Done);
        job.set_progress(100.0, "Job complete");
        job.error_message.clear();
        job.updated_at = Utc::now();

        self.persist_job(&job).await?;
        self.log(&job.id, "INFO", "runner", "Job complete").await?;

        self.set_runtime_status(false, String::new()).await;
        Ok(())
    }

    async fn run_navigation_attempt(
        &self,
        job: &mut Job,
        prompt: &str,
        credential: Option<(String, String)>,
    ) -> Result<NavigationOutcome> {
        let step_offset = self
            .db
            .list_steps(&job.id)
            .await?
            .last()
            .map(|step| step.step_number)
            .unwrap_or(0);

        let (nav_tx, mut nav_rx) = mpsc::unbounded_channel::<NavEvent>();
        let cfg = self.config.clone();
        let job_id_for_nav = job.id.clone();
        let source_url = job.source_url.clone();
        let prompt_for_nav = prompt.to_string();
        let credential_for_nav = credential.clone();

        let nav_handle = tokio::spawn(async move {
            run_navigation(
                &job_id_for_nav,
                &source_url,
                &prompt_for_nav,
                credential_for_nav,
                cfg.as_ref(),
                nav_tx,
            )
            .await
        });

        let mut emitted_steps = 0usize;
        let heartbeat = tokio::time::sleep(Duration::from_secs(12));
        tokio::pin!(heartbeat);

        loop {
            tokio::select! {
                maybe_event = nav_rx.recv() => {
                    let Some(event) = maybe_event else {
                        break;
                    };

                    match event {
                        NavEvent::Log {
                            level,
                            source,
                            message,
                        } => {
                            let _ = self.log(&job.id, &level, &source, &message).await;
                        }
                        NavEvent::Progress { percent, message } => {
                            let clamped = percent.clamp(10.0, 44.0);
                            let progress = if clamped < job.progress_percent {
                                job.progress_percent
                            } else {
                                clamped
                            };

                            if message != job.progress_message
                                || (progress - job.progress_percent).abs() > f64::EPSILON
                            {
                                job.set_progress(progress, message);
                                self.persist_job(job).await?;
                            }
                        }
                        NavEvent::Step {
                            step_number,
                            action,
                            observation,
                            url,
                            is_error,
                            notes,
                        } => {
                            emitted_steps += 1;
                            let adjusted_step = step_number + step_offset;
                            let step = self
                                .db
                                .append_step(
                                    &job.id,
                                    adjusted_step,
                                    &action,
                                    &observation,
                                    &url,
                                    is_error,
                                    &notes,
                                )
                                .await?;
                            self.broadcast(ServerEvent::JobStep(step.clone()));

                            let screenshot = self
                                .db
                                .append_screenshot(
                                    &job.id,
                                    PLACEHOLDER_PNG,
                                    &url,
                                    &format!("Step {}: {}", adjusted_step, action),
                                    Some(adjusted_step),
                                )
                                .await?;
                            self.broadcast(ServerEvent::JobScreenshot(screenshot.clone()));

                            let screenshot_b64 = STANDARD.encode(&screenshot.screenshot_data);
                            self.runtime
                                .set_screenshot(screenshot_b64.clone(), screenshot.url.clone())
                                .await;
                            self.broadcast(ServerEvent::Screenshot {
                                data_base64: screenshot_b64,
                                url: screenshot.url,
                            });

                            let progress = (10.0 + (emitted_steps as f64 * 1.5)).min(40.0);
                            let detail = if action.trim().is_empty() {
                                format!("Browsing (step {adjusted_step})")
                            } else {
                                format!("Browsing: {action}")
                            };
                            job.set_progress(progress, detail);
                            self.persist_job(job).await?;
                        }
                    }
                }
                _ = &mut heartbeat => {
                    let detail = if emitted_steps == 0 {
                        if job.progress_message.trim().is_empty() {
                            "Browsing in progress".to_string()
                        } else {
                            job.progress_message.clone()
                        }
                    } else {
                        format!("Browsing in progress ({emitted_steps} steps)")
                    };
                    let progress = if emitted_steps == 0 {
                        job.progress_percent.clamp(10.0, 39.0)
                    } else {
                        (10.0 + (emitted_steps as f64)).min(39.0)
                    };
                    job.set_progress(progress, detail);
                    self.persist_job(job).await?;
                    heartbeat.as_mut().reset(tokio::time::Instant::now() + Duration::from_secs(12));
                }
            }
        }

        match nav_handle.await {
            Ok(Ok(outcome)) => Ok(outcome),
            Ok(Err(err)) => Err(err),
            Err(err) => Err(anyhow::anyhow!("Browse task crashed: {err}")),
        }
    }

    async fn apply_navigation_outcome(
        &self,
        job: &mut Job,
        navigation: &NavigationOutcome,
    ) -> Result<()> {
        job.found_urls = navigation.found_urls.clone();

        if !navigation.downloaded_files.is_empty() {
            job.downloaded_files = navigation.downloaded_files.clone();
            self.log(
                &job.id,
                "INFO",
                "browse",
                &format!(
                    "Browser downloaded {} files directly",
                    job.downloaded_files.len()
                ),
            )
            .await?;
        }

        if !job.found_urls.is_empty() {
            self.log(
                &job.id,
                "INFO",
                "browse",
                &format!("Found {} candidate URLs", job.found_urls.len()),
            )
            .await?;
        }

        if !navigation.raw_output.is_empty() {
            let excerpt = if navigation.raw_output.len() > 1000 {
                format!("{}...", &navigation.raw_output[..1000])
            } else {
                navigation.raw_output.clone()
            };
            self.log(&job.id, "DEBUG", "claude_output", &excerpt)
                .await?;

            let learning_domain = domain_from_url(&job.source_url).or_else(|| {
                job.found_urls
                    .iter()
                    .find_map(|candidate| domain_from_url(candidate))
            });
            let url_pattern = if job.source_url.trim().is_empty() {
                None
            } else {
                Some(job.source_url.as_str())
            };

            for (note_type, content) in extract_learning_entries(&navigation.raw_output) {
                self.log(
                    &job.id,
                    "INFO",
                    "learning",
                    &format!("[{note_type}] {content}"),
                )
                .await?;

                if let Some(domain) = learning_domain.as_deref() {
                    let _ = self
                        .db
                        .add_note(
                            domain,
                            &note_type,
                            &content,
                            Some("learning"),
                            url_pattern,
                            None,
                        )
                        .await;
                }
            }
        }

        Ok(())
    }

    async fn persist_job(&self, job: &Job) -> Result<()> {
        self.db.update_job(job).await?;
        self.broadcast(ServerEvent::JobUpdate(job.clone()));
        Ok(())
    }

    fn broadcast(&self, event: ServerEvent) {
        let _ = self.events.send(event);
    }

    async fn set_runtime_status(&self, is_running: bool, task: String) {
        self.runtime.set_status(is_running, task.clone()).await;
        self.broadcast(ServerEvent::Status { is_running, task });
    }

    async fn log(&self, job_id: &str, level: &str, source: &str, message: &str) -> Result<()> {
        let entry = self.db.append_log(job_id, level, source, message).await?;

        self.runtime
            .add_message(
                if source.is_empty() { "log" } else { source },
                message.to_string(),
            )
            .await;
        self.runtime
            .push_log(
                level,
                if source.is_empty() { "runtime" } else { source },
                message,
            )
            .await;

        self.broadcast(ServerEvent::JobLog(entry));
        self.broadcast(ServerEvent::Message {
            role: if source.is_empty() {
                "log".to_string()
            } else {
                source.to_string()
            },
            content: message.to_string(),
        });

        Ok(())
    }

    async fn record_source_notes(&self, urls: &[String], success: bool, error: Option<&str>) {
        for url in urls {
            if url.starts_with("magnet:") {
                continue;
            }
            let domain = reqwest::Url::parse(url)
                .ok()
                .and_then(|u| u.host_str().map(str::to_string))
                .unwrap_or_else(|| url.clone());
            let content = if success {
                format!("Download succeeded from {domain}")
            } else {
                format!(
                    "Download failed from {domain}: {}",
                    error.unwrap_or("unknown error")
                )
            };
            let _ = self
                .db
                .add_note(
                    &domain,
                    "source_quality",
                    &content,
                    Some(if success { "success" } else { "failure" }),
                    Some(url),
                    Some(success),
                )
                .await;
        }
    }

    async fn download_with_retries(&self, job_id: &str, url: &str) -> Result<PathBuf> {
        let attempts = self.config.download_retry_attempts.max(1);
        let mut last_error: Option<anyhow::Error> = None;

        for attempt in 1..=attempts {
            if attempt > 1 {
                self.log(
                    job_id,
                    "INFO",
                    "download",
                    &format!("Retry {attempt}/{attempts} for {url}"),
                )
                .await?;
            }

            match self.download_url(url).await {
                Ok(path) => {
                    self.log(
                        job_id,
                        "INFO",
                        "download",
                        &format!("Downloaded {}", path.display()),
                    )
                    .await?;
                    return Ok(path);
                }
                Err(err) => {
                    warn!(job_id = %job_id, "download failed for {url}: {err:#}");
                    self.log(
                        job_id,
                        "WARNING",
                        "download",
                        &format!("Attempt {attempt}/{attempts} failed for {url}: {err}"),
                    )
                    .await?;
                    last_error = Some(err);

                    if attempt < attempts {
                        let backoff = self.config.download_retry_backoff_sec
                            * 2f64.powi((attempt - 1) as i32);
                        tokio::time::sleep(Duration::from_secs_f64(backoff.max(0.0))).await;
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("download failed for {url}")))
    }

    async fn download_url(&self, url: &str) -> Result<PathBuf> {
        let response = self
            .http_client
            .get(url)
            .send()
            .await
            .with_context(|| format!("GET failed for {url}"))?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "http status {} for {}",
                response.status(),
                url
            ));
        }

        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if content_type.starts_with("text/html") {
            return Err(anyhow::anyhow!(
                "server returned html instead of file for {}",
                url
            ));
        }

        let disposition = response
            .headers()
            .get(CONTENT_DISPOSITION)
            .and_then(|h| h.to_str().ok())
            .unwrap_or_default()
            .to_string();

        let filename = infer_filename(url, &disposition);
        let full_path = self.config.download_dir().join(filename);

        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        let mut file = fs::File::create(&full_path)
            .await
            .with_context(|| format!("creating output file {}", full_path.display()))?;

        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.context("error reading download stream")?;
            file.write_all(&chunk).await?;
        }
        file.flush().await?;

        Ok(full_path)
    }

    async fn copy_outputs(
        &self,
        job_id: &str,
        downloaded_files: &[String],
        destination_path: &str,
        file_operation: &str,
    ) -> Result<Vec<String>> {
        let destination = if destination_path.trim().is_empty() {
            self.config.download_dir()
        } else {
            PathBuf::from(destination_path)
        };
        fs::create_dir_all(&destination).await?;

        let mut outputs = Vec::new();

        for file in downloaded_files {
            if file.starts_with("torrent:") {
                outputs.push(file.clone());
                continue;
            }

            let source = PathBuf::from(file);
            if !source.exists() {
                self.log(
                    job_id,
                    "WARNING",
                    "copy",
                    &format!("Skipping missing file {file}"),
                )
                .await?;
                continue;
            }

            let name = source
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "downloaded_file".to_string());
            let target = destination.join(name);

            match file_operation {
                "hardlink" => {
                    let src = source.clone();
                    let dst = target.clone();
                    tokio::task::spawn_blocking(move || std::fs::hard_link(src, dst)).await??;
                }
                "symlink" => {
                    symlink_file(&source, &target).await?;
                }
                "path_only" => {
                    outputs.push(source.display().to_string());
                    continue;
                }
                "reflink" => {
                    fs::copy(&source, &target).await?;
                }
                _ => {
                    fs::copy(&source, &target).await?;
                }
            }

            outputs.push(target.display().to_string());
        }

        Ok(outputs)
    }
}

fn extract_learning_entries(raw_output: &str) -> Vec<(String, String)> {
    let Ok(re) = Regex::new(r"(?is)\[LEARNING:\s*type=(\w+)\]\s*(.+?)(?=\[LEARNING:|$)") else {
        return Vec::new();
    };

    let actionable = [
        "navigation_tip",
        "workaround",
        "download_method",
        "site_structure",
    ];

    re.captures_iter(raw_output)
        .filter_map(|cap| {
            let note_type = cap.get(1)?.as_str().trim().to_ascii_lowercase();
            if !actionable.contains(&note_type.as_str()) {
                return None;
            }
            let content = cap.get(2)?.as_str().trim().to_string();
            if content.is_empty() {
                None
            } else {
                Some((note_type, content))
            }
        })
        .collect()
}

fn domain_from_url(input: &str) -> Option<String> {
    if input.trim().is_empty() {
        return None;
    }
    reqwest::Url::parse(input)
        .ok()
        .and_then(|url| url.host_str().map(str::to_string))
}

fn augment_prompt_with_failed_urls(prompt: &str, failed_urls: &[String]) -> String {
    if failed_urls.is_empty() {
        return prompt.to_string();
    }

    let mut lines = Vec::new();
    for url in failed_urls.iter().take(50) {
        lines.push(format!("  - {url}"));
    }

    format!(
        "{prompt}\n\n\
         IMPORTANT: The URLs below were already tried and failed. You must find different sources.\n\
         Failed URLs to avoid:\n{}\n",
        lines.join("\n")
    )
}

fn merge_unique_strings(target: &mut Vec<String>, values: &[String]) {
    for value in values {
        if !target.iter().any(|existing| existing == value) {
            target.push(value.clone());
        }
    }
}

fn build_file_filter_matcher(patterns: &[String]) -> Option<GlobSet> {
    if patterns.is_empty() {
        return None;
    }

    let mut builder = GlobSetBuilder::new();
    let mut added = 0usize;
    for pattern in patterns {
        let trimmed = pattern.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(glob) = Glob::new(trimmed) {
            builder.add(glob);
            added += 1;
        }
    }

    if added == 0 {
        None
    } else {
        builder.build().ok()
    }
}

fn filter_matches(matcher: &Option<GlobSet>, path: &str) -> bool {
    let Some(matcher) = matcher else {
        return true;
    };

    let full_path = Path::new(path);
    if matcher.is_match(full_path) {
        return true;
    }

    full_path
        .file_name()
        .map(|name| matcher.is_match(name))
        .unwrap_or(false)
}

fn infer_filename(url: &str, content_disposition: &str) -> String {
    if !content_disposition.is_empty() {
        for part in content_disposition.split(';') {
            let part = part.trim();
            if let Some(rest) = part.strip_prefix("filename=") {
                let cleaned = rest.trim_matches('"').trim();
                if !cleaned.is_empty() {
                    return sanitize_filename(cleaned);
                }
            }
        }
    }

    let from_url = reqwest::Url::parse(url)
        .ok()
        .and_then(|u| {
            u.path_segments()
                .and_then(|mut s| s.next_back())
                .map(str::to_string)
        })
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "download.bin".to_string());

    sanitize_filename(&from_url)
}

fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            _ => c,
        })
        .collect()
}

async fn symlink_file(source: &Path, target: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let src = source.to_path_buf();
        let dst = target.to_path_buf();
        tokio::task::spawn_blocking(move || std::os::unix::fs::symlink(src, dst)).await??;
        return Ok(());
    }

    #[cfg(not(unix))]
    {
        fs::copy(source, target).await?;
        Ok(())
    }
}
