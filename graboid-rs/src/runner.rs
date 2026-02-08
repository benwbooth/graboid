use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::Utc;
use futures::{SinkExt, StreamExt};
use globset::{Glob, GlobSet, GlobSetBuilder};
use regex::Regex;
use reqwest::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::{Mutex, Semaphore, broadcast, mpsc};
use tokio::{fs, io::AsyncWriteExt};
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMessage};
use tracing::{error, warn};

use crate::archives::{default_extract_dir, extract_archive, is_archive};
use crate::claude::{NavEvent, NavigationOutcome, run_navigation};
use crate::config::AppConfig;
use crate::db::JobDb;
use crate::events::ServerEvent;
use crate::models::{Job, JobPhase, JobStatus};
use crate::state::RuntimeState;
use crate::torrent;

const MAX_BROWSE_ATTEMPTS: usize = 2;
const MAX_BROWSE_STEPS_PER_ATTEMPT: usize = 32;
const MAX_BROWSE_STEPS_PER_JOB: i64 = 72;
const BROWSE_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(80);
const BROWSE_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(4);
const MAX_FAST_SCAN_CANDIDATES: usize = 80;

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

        let source_preferences = match self.db.preferred_source_domains(12).await {
            Ok(domains) => domains,
            Err(err) => {
                warn!(job_id = %job.id, "failed loading source preferences: {err:#}");
                Vec::new()
            }
        };
        if !source_preferences.is_empty() {
            self.log(
                &job.id,
                "INFO",
                "browse",
                &format!(
                    "Loaded source memory ranking: {}",
                    source_preferences
                        .iter()
                        .take(6)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            )
            .await?;
        }

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

            let prompt = augment_prompt_with_source_context(
                &job.prompt,
                &job.source_url,
                &source_preferences,
                &failed_urls,
            );
            let task_prompt = job.prompt.clone();
            let navigation = match self
                .run_navigation_attempt(&mut job, &prompt, &task_prompt, credential.clone())
                .await
            {
                Ok(outcome) => Some(outcome),
                Err(err) => {
                    let err_text = err.to_string();
                    let fatal_step_budget = err_text.contains("Step budget exceeded");
                    self.log(
                        &job.id,
                        "WARNING",
                        "browse",
                        &format!(
                            "Browse attempt {browse_attempt}/{MAX_BROWSE_ATTEMPTS} failed: {err}"
                        ),
                    )
                    .await?;

                    if !job.found_urls.is_empty() {
                        self.log(
                            &job.id,
                            "WARNING",
                            "browse",
                            &format!(
                                "Proceeding with {} discovered URL(s) despite browse error",
                                job.found_urls.len()
                            ),
                        )
                        .await?;
                        None
                    } else if browse_attempt < MAX_BROWSE_ATTEMPTS && !fatal_step_budget {
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        continue;
                    } else {
                        job.fail(format!(
                            "Browse failed after {MAX_BROWSE_ATTEMPTS} attempts: {err}"
                        ));
                        self.persist_job(&job).await?;
                        self.log(&job.id, "ERROR", "browse", &job.error_message)
                            .await?;
                        self.set_runtime_status(false, String::new()).await;
                        return Ok(());
                    }
                }
            };

            if let Some(navigation) = navigation {
                self.apply_navigation_outcome(&mut job, &navigation).await?;
                self.persist_job(&job).await?;
            }

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
                    let mut handled = false;
                    if !job.file_filter.is_empty() {
                        match torrent::selective_fetch_from_torrent(
                            self.config.as_ref(),
                            &url,
                            &job.prompt,
                            &job.file_filter,
                        )
                        .await
                        {
                            Ok(paths) if !paths.is_empty() => {
                                let selected_count = paths.len();
                                for path in paths {
                                    downloaded.push(path.display().to_string());
                                }
                                self.log(
                                    &job.id,
                                    "INFO",
                                    "download",
                                    &format!(
                                        "Selective torrent fetch succeeded for {url} ({} file(s))",
                                        selected_count
                                    ),
                                )
                                .await?;
                                handled = true;
                            }
                            Ok(_) => {}
                            Err(err) => {
                                self.log(
                                    &job.id,
                                    "DEBUG",
                                    "download",
                                    &format!(
                                        "Selective torrent fetch unavailable for {url}: {err}; falling back to queue mode"
                                    ),
                                )
                                .await?;
                            }
                        }
                    }

                    if !handled {
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
        task_prompt: &str,
        credential: Option<(String, String)>,
    ) -> Result<NavigationOutcome> {
        let step_offset = self
            .db
            .list_steps(&job.id)
            .await?
            .last()
            .map(|step| step.step_number)
            .unwrap_or(0);

        if step_offset >= MAX_BROWSE_STEPS_PER_JOB {
            return Err(anyhow::anyhow!(
                "Step budget exceeded: job already has {step_offset} steps (limit {MAX_BROWSE_STEPS_PER_JOB})"
            ));
        }

        let (nav_tx, mut nav_rx) = mpsc::unbounded_channel::<NavEvent>();
        let cfg = self.config.clone();
        let job_id_for_nav = job.id.clone();
        let source_url = job.source_url.clone();
        let prompt_for_nav = prompt.to_string();
        let file_filter_for_nav = job.file_filter.clone();
        let destination_path_for_nav = job.destination_path.clone();
        let file_operation_for_nav = job.file_operation.clone();
        let credential_for_nav = credential.clone();

        let nav_handle = tokio::spawn(async move {
            run_navigation(
                &job_id_for_nav,
                &source_url,
                &prompt_for_nav,
                &file_filter_for_nav,
                &destination_path_for_nav,
                &file_operation_for_nav,
                credential_for_nav,
                cfg.as_ref(),
                nav_tx,
            )
            .await
        });

        let mut emitted_steps = 0usize;
        let mut screenshot_capture_enabled = true;
        let mut scanned_page_urls = HashSet::new();
        let mut fast_scan_candidate_urls = Vec::new();
        let mut recent_navigate_urls = Vec::new();
        let heartbeat = tokio::time::sleep(BROWSE_HEARTBEAT_INTERVAL);
        tokio::pin!(heartbeat);
        let attempt_timeout = tokio::time::sleep(BROWSE_ATTEMPT_TIMEOUT);
        tokio::pin!(attempt_timeout);

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
                        NavEvent::FoundUrl { url } => {
                            if job.found_urls.iter().any(|existing| existing == &url) {
                                continue;
                            }

                            job.found_urls.push(url.clone());
                            self.log(
                                &job.id,
                                "INFO",
                                "browse",
                                &format!("Discovered URL: {url}"),
                            )
                            .await?;
                            self.persist_job(job).await?;
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

                            if emitted_steps > MAX_BROWSE_STEPS_PER_ATTEMPT {
                                nav_handle.abort();
                                if job.found_urls.is_empty() && !fast_scan_candidate_urls.is_empty() {
                                    self.log(
                                        &job.id,
                                        "WARNING",
                                        "browse",
                                        &format!(
                                            "Step budget exceeded; using {} cached fast-scan URL candidate(s) as fallback",
                                            fast_scan_candidate_urls.len()
                                        ),
                                    )
                                    .await?;
                                    return Ok(NavigationOutcome {
                                        found_urls: fast_scan_candidate_urls.clone(),
                                        downloaded_files: Vec::new(),
                                        raw_output: String::new(),
                                    });
                                }
                                return Err(anyhow::anyhow!(
                                    "Step budget exceeded: attempt produced {emitted_steps} steps (limit {MAX_BROWSE_STEPS_PER_ATTEMPT})"
                                ));
                            }
                            if adjusted_step > MAX_BROWSE_STEPS_PER_JOB {
                                nav_handle.abort();
                                if job.found_urls.is_empty() && !fast_scan_candidate_urls.is_empty() {
                                    self.log(
                                        &job.id,
                                        "WARNING",
                                        "browse",
                                        &format!(
                                            "Job step budget exceeded; using {} cached fast-scan URL candidate(s) as fallback",
                                            fast_scan_candidate_urls.len()
                                        ),
                                    )
                                    .await?;
                                    return Ok(NavigationOutcome {
                                        found_urls: fast_scan_candidate_urls.clone(),
                                        downloaded_files: Vec::new(),
                                        raw_output: String::new(),
                                    });
                                }
                                return Err(anyhow::anyhow!(
                                    "Step budget exceeded: job reached step {adjusted_step} (limit {MAX_BROWSE_STEPS_PER_JOB})"
                                ));
                            }

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

                            if action.eq_ignore_ascii_case("Navigate") && !url.trim().is_empty() {
                                let navigation_key = normalize_navigation_url(&url);
                                if !navigation_key.is_empty() {
                                    recent_navigate_urls.push(navigation_key);
                                    if recent_navigate_urls.len() > 8 {
                                        recent_navigate_urls.remove(0);
                                    }
                                    if navigation_loop_detected(&recent_navigate_urls) {
                                        nav_handle.abort();
                                        if job.found_urls.is_empty()
                                            && !fast_scan_candidate_urls.is_empty()
                                        {
                                            self.log(
                                                &job.id,
                                                "WARNING",
                                                "browse",
                                                &format!(
                                                    "Navigation loop detected; using {} cached fast-scan URL candidate(s) as fallback",
                                                    fast_scan_candidate_urls.len()
                                                ),
                                            )
                                            .await?;
                                            return Ok(NavigationOutcome {
                                                found_urls: fast_scan_candidate_urls.clone(),
                                                downloaded_files: Vec::new(),
                                                raw_output: String::new(),
                                            });
                                        }
                                        return Err(anyhow::anyhow!(
                                            "Navigation loop detected while browsing"
                                        ));
                                    }
                                }

                                if scanned_page_urls.insert(url.clone()) {
                                    match self
                                        .scan_page_for_download_candidates(&job.id, &url, task_prompt)
                                        .await
                                    {
                                        Ok(scan) => {
                                            if scan.total_links >= 250 {
                                                self.log(
                                                    &job.id,
                                                    "INFO",
                                                    "browse",
                                                    &format!(
                                                        "Scanned large link page ({}) with {} links",
                                                        url, scan.total_links
                                                    ),
                                                )
                                                .await?;
                                            }

                                            let mut discovered_count = 0usize;
                                            for found_url in scan.download_urls {
                                                if job
                                                    .found_urls
                                                    .iter()
                                                    .any(|existing| existing == &found_url)
                                                {
                                                    continue;
                                                }
                                                if fast_scan_candidate_urls
                                                    .iter()
                                                    .any(|existing| existing == &found_url)
                                                {
                                                    continue;
                                                }
                                                if fast_scan_candidate_urls.len()
                                                    >= MAX_FAST_SCAN_CANDIDATES
                                                {
                                                    break;
                                                }
                                                fast_scan_candidate_urls.push(found_url.clone());
                                                discovered_count += 1;
                                            }

                                            if discovered_count > 0 {
                                                let total_candidates =
                                                    fast_scan_candidate_urls.len();
                                                let sample = fast_scan_candidate_urls
                                                    .iter()
                                                    .rev()
                                                    .take(3)
                                                    .cloned()
                                                    .collect::<Vec<_>>();
                                                let sample_text = if sample.is_empty() {
                                                    String::new()
                                                } else {
                                                    format!(" (latest: {})", sample.join(", "))
                                                };
                                                self.log(
                                                    &job.id,
                                                    "INFO",
                                                    "browse",
                                                    &format!(
                                                        "Fast link scan captured {discovered_count} new candidate URL(s), {total_candidates} cached total{sample_text}"
                                                    ),
                                                )
                                                .await?;
                                            }
                                        }
                                        Err(err) => {
                                            let _ = self
                                                .log(
                                                    &job.id,
                                                    "DEBUG",
                                                    "browse",
                                                    &format!("Fast link scan skipped for {url}: {err}"),
                                                )
                                                .await;
                                        }
                                    }
                                }
                            }

                            if screenshot_capture_enabled && !is_character_keypress_step(&action) {
                                match capture_chrome_screenshot(
                                    self.config.chrome_debug_port,
                                    &self.http_client,
                                )
                                .await
                                {
                                    Ok(Some((png_bytes, captured_url))) => {
                                        let screenshot_url = if captured_url.trim().is_empty() {
                                            url.clone()
                                        } else {
                                            captured_url
                                        };
                                        let screenshot = self
                                            .db
                                            .append_screenshot(
                                                &job.id,
                                                &png_bytes,
                                                &screenshot_url,
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
                                    }
                                    Ok(None) => {}
                                    Err(err) => {
                                        screenshot_capture_enabled = false;
                                        let _ = self
                                            .log(
                                                &job.id,
                                                "DEBUG",
                                                "screenshot",
                                                &format!(
                                                    "Live screenshot capture disabled: {err}"
                                                ),
                                            )
                                            .await;
                                    }
                                }
                            }

                            let progress = (10.0 + (emitted_steps as f64 * 1.5)).min(40.0);
                            let total_steps = adjusted_step.max(0);
                            let detail = if action.trim().is_empty() {
                                format!("Browsing (step {total_steps})")
                            } else {
                                format!("Browsing: {action} (step {total_steps})")
                            };
                            job.set_progress(progress, detail);
                            self.persist_job(job).await?;
                        }
                    }
                }
                _ = &mut attempt_timeout => {
                    nav_handle.abort();
                    if job.found_urls.is_empty() && !fast_scan_candidate_urls.is_empty() {
                        self.log(
                            &job.id,
                            "WARNING",
                            "browse",
                            &format!(
                                "Browse timeout hit; using {} cached fast-scan URL candidate(s) as fallback",
                                fast_scan_candidate_urls.len()
                            ),
                        )
                        .await?;
                        return Ok(NavigationOutcome {
                            found_urls: fast_scan_candidate_urls.clone(),
                            downloaded_files: Vec::new(),
                            raw_output: String::new(),
                        });
                    }
                    return Err(anyhow::anyhow!(
                        "Browse attempt timed out after {}s",
                        BROWSE_ATTEMPT_TIMEOUT.as_secs()
                    ));
                }
                _ = &mut heartbeat => {
                    let detail = if emitted_steps == 0 {
                        if job.progress_message.trim().is_empty() {
                            "Browsing in progress".to_string()
                        } else {
                            job.progress_message.clone()
                        }
                    } else {
                        let total_steps = step_offset + emitted_steps as i64;
                        format!("Browsing in progress ({total_steps} steps)")
                    };
                    let progress = if emitted_steps == 0 {
                        job.progress_percent.clamp(10.0, 39.0)
                    } else {
                        (10.0 + (emitted_steps as f64)).min(39.0)
                    };
                    job.set_progress(progress, detail);
                    self.persist_job(job).await?;
                    heartbeat
                        .as_mut()
                        .reset(tokio::time::Instant::now() + BROWSE_HEARTBEAT_INTERVAL);
                }
            }
        }

        match nav_handle.await {
            Ok(Ok(mut outcome)) => {
                let has_agent_urls = !job.found_urls.is_empty() || !outcome.found_urls.is_empty();
                if !has_agent_urls && !fast_scan_candidate_urls.is_empty() {
                    self.log(
                        &job.id,
                        "INFO",
                        "browse",
                        &format!(
                            "Using {} fast-scan URL candidate(s) as fallback because agent did not emit any URLs",
                            fast_scan_candidate_urls.len()
                        ),
                    )
                    .await?;
                    outcome.found_urls = fast_scan_candidate_urls;
                }
                Ok(outcome)
            }
            Ok(Err(err)) => Err(err),
            Err(err) => Err(anyhow::anyhow!("Browse task crashed: {err}")),
        }
    }

    async fn apply_navigation_outcome(
        &self,
        job: &mut Job,
        navigation: &NavigationOutcome,
    ) -> Result<()> {
        merge_unique_strings(&mut job.found_urls, &navigation.found_urls);

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
            let suggested_filters = extract_file_filter_entries(&navigation.raw_output);
            if !suggested_filters.is_empty() {
                let before = job.file_filter.len();
                merge_unique_strings(&mut job.file_filter, &suggested_filters);
                let added = job.file_filter.len().saturating_sub(before);
                if added > 0 {
                    self.log(
                        &job.id,
                        "INFO",
                        "browse",
                        &format!(
                            "Applied {added} file filter hint(s) from agent output: {}",
                            suggested_filters.join(", ")
                        ),
                    )
                    .await?;
                }
            }

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

    async fn scan_page_for_download_candidates(
        &self,
        _job_id: &str,
        page_url: &str,
        task_prompt: &str,
    ) -> Result<PageScanResult> {
        let base_url = reqwest::Url::parse(page_url)
            .with_context(|| format!("invalid URL for page scan: {page_url}"))?;

        if !matches!(base_url.scheme(), "http" | "https") {
            return Ok(PageScanResult::default());
        }

        let response = self
            .http_client
            .get(page_url)
            .header("accept", "text/html,application/xhtml+xml")
            .send()
            .await
            .with_context(|| format!("GET failed during page scan for {page_url}"))?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "page scan HTTP status {} for {}",
                response.status(),
                page_url
            ));
        }

        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if !content_type.contains("text/html") && !content_type.contains("application/xhtml+xml") {
            return Ok(PageScanResult::default());
        }

        let html = response
            .text()
            .await
            .with_context(|| format!("reading HTML body for {page_url}"))?;
        if html.len() > 4_000_000 {
            return Ok(PageScanResult::default());
        }

        let anchors = extract_anchor_candidates(&html);
        if anchors.is_empty() {
            return Ok(PageScanResult::default());
        }

        let total_links = anchors.len();
        let keywords = extract_prompt_keywords(task_prompt);
        let mut scored = Vec::new();

        for (href, text) in anchors {
            let href = href.trim();
            if href.is_empty()
                || href.starts_with('#')
                || href.starts_with("javascript:")
                || href.starts_with("mailto:")
            {
                continue;
            }

            let absolute = if href.starts_with("magnet:") {
                href.to_string()
            } else {
                match base_url.join(href) {
                    Ok(joined) => joined.to_string(),
                    Err(_) => continue,
                }
            };

            if !absolute.starts_with("http://")
                && !absolute.starts_with("https://")
                && !absolute.starts_with("magnet:")
            {
                continue;
            }
            if !is_viable_download_url(&absolute) {
                continue;
            }

            let mut score = 30_i32;
            let haystack = format!(
                "{} {}",
                absolute.to_ascii_lowercase(),
                text.to_ascii_lowercase()
            );
            let mut matched = 0_usize;
            for keyword in &keywords {
                if haystack.contains(keyword) {
                    score += 6;
                    matched += 1;
                }
            }
            if !keywords.is_empty() && matched == keywords.len() {
                score += 18;
            }
            if haystack.contains("sample") {
                score -= 8;
            }

            scored.push((score, absolute));
        }

        scored.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));

        let mut seen = HashSet::new();
        let mut download_urls = Vec::new();
        let min_score = if keywords.is_empty() { 30 } else { 36 };
        for (score, url) in scored {
            if score < min_score {
                continue;
            }
            if seen.insert(url.clone()) {
                download_urls.push(url);
            }
            if download_urls.len() >= MAX_FAST_SCAN_CANDIDATES {
                break;
            }
        }

        Ok(PageScanResult {
            total_links,
            download_urls,
        })
    }
}

#[derive(Debug, Default)]
struct PageScanResult {
    total_links: usize,
    download_urls: Vec<String>,
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

fn extract_file_filter_entries(raw_output: &str) -> Vec<String> {
    let mut filters = Vec::new();
    for line in raw_output.lines() {
        let trimmed = line.trim();
        if trimmed.len() < "[FILE_FILTER]".len() {
            continue;
        }
        let Some(prefix) = trimmed.get(0.."[FILE_FILTER]".len()) else {
            continue;
        };
        if !prefix.eq_ignore_ascii_case("[FILE_FILTER]") {
            continue;
        }

        let mut raw = trimmed["[FILE_FILTER]".len()..].trim();
        if raw.len() >= "pattern:".len() {
            let maybe_pattern = &raw[..raw.len().min("pattern:".len())];
            if maybe_pattern.eq_ignore_ascii_case("pattern:") {
                raw = raw["pattern:".len()..].trim();
            }
        }

        for part in raw.split([',', ';']) {
            let candidate = part
                .trim()
                .trim_start_matches("-")
                .trim()
                .trim_matches('`')
                .trim_matches('"')
                .trim_matches('\'')
                .trim();

            if candidate.is_empty() || candidate.len() > 220 {
                continue;
            }
            if !filters.iter().any(|existing| existing == candidate) {
                filters.push(candidate.to_string());
            }
            if filters.len() >= 12 {
                return filters;
            }
        }
    }

    filters
}

fn domain_from_url(input: &str) -> Option<String> {
    if input.trim().is_empty() {
        return None;
    }
    reqwest::Url::parse(input)
        .ok()
        .and_then(|url| url.host_str().map(normalize_domain))
}

fn normalize_domain(input: &str) -> String {
    input.trim().trim_start_matches("www.").to_ascii_lowercase()
}

fn domain_from_input(input: &str) -> Option<String> {
    domain_from_url(input).or_else(|| {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return None;
        }
        let cleaned = trimmed
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or("")
            .trim();
        if cleaned.is_empty() || !cleaned.contains('.') || cleaned.contains(char::is_whitespace) {
            None
        } else {
            Some(normalize_domain(cleaned))
        }
    })
}

fn augment_prompt_with_source_context(
    prompt: &str,
    source_url: &str,
    preferred_domains: &[String],
    failed_urls: &[String],
) -> String {
    if preferred_domains.is_empty() && failed_urls.is_empty() {
        return prompt.to_string();
    }

    let explicit_domain = domain_from_input(source_url);
    let mut failed_domains = HashSet::new();
    for value in failed_urls {
        if let Some(domain) = domain_from_input(value) {
            failed_domains.insert(domain);
        }
    }

    let mut ranked_domains = Vec::new();
    let mut seen_domains = HashSet::new();
    if let Some(domain) = explicit_domain.clone() {
        if seen_domains.insert(domain.clone()) {
            ranked_domains.push(domain);
        }
    }
    for domain in preferred_domains {
        let normalized = normalize_domain(domain);
        if normalized.is_empty() || failed_domains.contains(&normalized) {
            continue;
        }
        if seen_domains.insert(normalized.clone()) {
            ranked_domains.push(normalized);
        }
    }

    let mut sections = Vec::new();
    if !ranked_domains.is_empty() {
        let mut ranked_lines = Vec::new();
        for (idx, domain) in ranked_domains.iter().take(12).enumerate() {
            ranked_lines.push(format!("  {}. {domain}", idx + 1));
        }

        let source_bias = if explicit_domain.is_some() {
            "Use the source URL domain first, then continue down the ranked list."
        } else {
            "Start at the top of this ranked list before trying unranked websites."
        };

        sections.push(format!(
            "SOURCE MEMORY FROM PREVIOUS JOBS (ranked):\n{}\n\
             Rules:\n\
               - {source_bias}\n\
               - If a ranked source fails, move to the next ranked source.\n\
               - Only use broad index/search sites after ranked sources are exhausted.\n",
            ranked_lines.join("\n")
        ));
    }

    if !failed_urls.is_empty() {
        let mut failed_url_lines = Vec::new();
        for url in failed_urls.iter().take(50) {
            failed_url_lines.push(format!("  - {url}"));
        }

        sections.push(format!(
            "IMPORTANT: These URLs were already tried and failed in this job.\n\
             Failed URLs to avoid:\n{}\n",
            failed_url_lines.join("\n")
        ));
    }

    if sections.is_empty() {
        return prompt.to_string();
    }

    format!("{prompt}\n\n{}", sections.join("\n"))
}

fn extract_anchor_candidates(html: &str) -> Vec<(String, String)> {
    let Ok(anchor_re) = Regex::new(r#"(?is)<a\b[^>]*href\s*=\s*["']([^"']+)["'][^>]*>(.*?)</a>"#)
    else {
        return Vec::new();
    };
    let Ok(tag_re) = Regex::new(r"(?is)<[^>]+>") else {
        return Vec::new();
    };

    let mut candidates = Vec::new();
    for capture in anchor_re.captures_iter(html) {
        let Some(href_match) = capture.get(1) else {
            continue;
        };
        let href = href_match.as_str().trim();
        if href.is_empty() {
            continue;
        }

        let text = capture
            .get(2)
            .map(|m| m.as_str())
            .unwrap_or_default()
            .replace('\n', " ");
        let text = tag_re.replace_all(&text, "");
        let text = text.split_whitespace().collect::<Vec<_>>().join(" ");

        candidates.push((href.to_string(), text));
    }

    candidates
}

fn extract_prompt_keywords(prompt: &str) -> Vec<String> {
    let stop_words: HashSet<&str> = HashSet::from([
        "a", "an", "and", "archive", "as", "at", "by", "download", "file", "files", "for", "from",
        "get", "in", "is", "it", "my", "of", "on", "or", "rom", "the", "to", "with",
    ]);

    let mut seen = HashSet::new();
    let mut keywords = Vec::new();
    for token in prompt
        .to_ascii_lowercase()
        .split(|ch: char| !ch.is_ascii_alphanumeric())
    {
        let trimmed = token.trim();
        let is_numeric = trimmed.chars().all(|ch| ch.is_ascii_digit());
        if (trimmed.len() < 2 && !is_numeric) || stop_words.contains(trimmed) {
            continue;
        }
        if seen.insert(trimmed.to_string()) {
            keywords.push(trimmed.to_string());
        }
    }
    keywords
}

fn normalize_navigation_url(url: &str) -> String {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    if let Ok(mut parsed) = reqwest::Url::parse(trimmed) {
        parsed.set_fragment(None);
        let mut normalized = parsed.to_string();
        if normalized.ends_with('/') {
            normalized.pop();
        }
        return normalized.to_ascii_lowercase();
    }

    trimmed.to_ascii_lowercase()
}

fn navigation_loop_detected(recent_urls: &[String]) -> bool {
    if recent_urls.is_empty() {
        return false;
    }

    let Some(last) = recent_urls.last() else {
        return false;
    };
    if recent_urls.iter().filter(|url| *url == last).count() >= 3 {
        return true;
    }

    if recent_urls.len() >= 6 {
        let split = recent_urls.len() - 3;
        if recent_urls[split - 3..split] == recent_urls[split..] {
            return true;
        }
    }

    false
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

#[derive(Debug, Deserialize)]
struct ChromeDebugTarget {
    #[serde(rename = "type")]
    target_type: Option<String>,
    url: Option<String>,
    #[serde(rename = "webSocketDebuggerUrl")]
    websocket_debugger_url: Option<String>,
}

fn is_character_keypress_step(action: &str) -> bool {
    action.to_ascii_lowercase().contains("press_key")
}

fn is_viable_download_url(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    if lower.starts_with("magnet:") || lower.ends_with(".torrent") {
        return true;
    }

    [
        ".zip", ".7z", ".rar", ".iso", ".chd", ".bin", ".cue", ".nes", ".rom",
    ]
    .iter()
    .any(|ext| {
        lower.contains(&format!("{ext}?"))
            || lower.contains(&format!("{ext}&"))
            || lower.ends_with(ext)
    })
}

fn choose_debug_target(targets: &[ChromeDebugTarget]) -> Option<&ChromeDebugTarget> {
    targets
        .iter()
        .filter(|target| target.websocket_debugger_url.is_some())
        .filter(|target| target.target_type.as_deref() == Some("page"))
        .find(|target| {
            target
                .url
                .as_deref()
                .map(|url| {
                    !url.starts_with("chrome://")
                        && !url.starts_with("devtools://")
                        && !url.trim().is_empty()
                })
                .unwrap_or(false)
        })
        .or_else(|| {
            targets.iter().find(|target| {
                target.websocket_debugger_url.is_some()
                    && target.target_type.as_deref() == Some("page")
            })
        })
}

async fn capture_chrome_screenshot(
    debug_port: u16,
    http_client: &reqwest::Client,
) -> Result<Option<(Vec<u8>, String)>> {
    // Capture from a practical source viewport with decent vertical room.
    const CAPTURE_VIEWPORT_WIDTH: i64 = 1280;
    const CAPTURE_VIEWPORT_HEIGHT: i64 = 1024;

    let list_url = format!("http://127.0.0.1:{debug_port}/json/list");
    let targets = http_client
        .get(&list_url)
        .timeout(Duration::from_secs(2))
        .send()
        .await
        .with_context(|| format!("querying chrome targets at {list_url}"))?
        .json::<Vec<ChromeDebugTarget>>()
        .await
        .context("parsing chrome target list")?;

    let Some(target) = choose_debug_target(&targets) else {
        return Ok(None);
    };

    let Some(ws_url) = target.websocket_debugger_url.as_deref() else {
        return Ok(None);
    };
    let target_url = target.url.clone().unwrap_or_default();

    let (mut ws, _) = tokio::time::timeout(Duration::from_secs(2), connect_async(ws_url))
        .await
        .context("timed out connecting to chrome devtools websocket")?
        .context("connecting to chrome devtools websocket failed")?;

    ws.send(WsMessage::Text(
        json!({"id": 1, "method": "Page.enable"}).to_string().into(),
    ))
    .await
    .context("sending Page.enable failed")?;
    ws.send(WsMessage::Text(
        json!({
            "id": 2,
            "method": "Emulation.setDeviceMetricsOverride",
            "params": {
                "width": CAPTURE_VIEWPORT_WIDTH,
                "height": CAPTURE_VIEWPORT_HEIGHT,
                "deviceScaleFactor": 1,
                "mobile": false
            }
        })
        .to_string()
        .into(),
    ))
    .await
    .context("sending Emulation.setDeviceMetricsOverride failed")?;
    ws.send(WsMessage::Text(
        json!({
            "id": 3,
            "method": "Page.captureScreenshot",
            "params": {
                "format": "png",
                "fromSurface": true
            }
        })
        .to_string()
        .into(),
    ))
    .await
    .context("sending Page.captureScreenshot failed")?;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }

        let maybe_msg = tokio::time::timeout(remaining, ws.next())
            .await
            .context("timed out waiting for screenshot response")?;
        let Some(msg) = maybe_msg else {
            break;
        };
        let msg = msg.context("reading screenshot websocket message failed")?;

        if let WsMessage::Text(text) = msg {
            let Ok(value) = serde_json::from_str::<Value>(&text) else {
                continue;
            };

            if value.get("id").and_then(Value::as_i64) != Some(3) {
                continue;
            }

            if let Some(err) = value.get("error") {
                return Err(anyhow::anyhow!("Page.captureScreenshot failed: {err}"));
            }

            let Some(data) = value
                .get("result")
                .and_then(|result| result.get("data"))
                .and_then(Value::as_str)
            else {
                return Ok(None);
            };

            let png_bytes = STANDARD
                .decode(data)
                .context("decoding captured screenshot failed")?;
            let _ = ws.close(None).await;
            return Ok(Some((png_bytes, target_url)));
        }
    }

    Ok(None)
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

#[cfg(test)]
mod tests {
    use super::{
        augment_prompt_with_source_context, domain_from_input, extract_file_filter_entries,
        extract_prompt_keywords, navigation_loop_detected, normalize_navigation_url,
    };

    #[test]
    fn source_context_uses_ranked_domains_and_skips_failed_domains() {
        let prompt = augment_prompt_with_source_context(
            "download the rom",
            "",
            &[
                "myrient.erista.me".to_string(),
                "archive.org".to_string(),
                "www.romhustler.net".to_string(),
            ],
            &["https://archive.org/details/some-pack".to_string()],
        );

        assert!(prompt.contains("SOURCE MEMORY FROM PREVIOUS JOBS (ranked):"));
        assert!(prompt.contains("1. myrient.erista.me"));
        assert!(prompt.contains("2. romhustler.net"));
        assert!(!prompt.contains("2. archive.org"));
        assert!(prompt.contains("Failed URLs to avoid:"));
    }

    #[test]
    fn source_context_prioritizes_explicit_source_domain_first() {
        let prompt = augment_prompt_with_source_context(
            "download file",
            "https://www.example.com/path",
            &["myrient.erista.me".to_string(), "example.com".to_string()],
            &[],
        );

        assert!(prompt.contains("1. example.com"));
        assert!(prompt.contains("2. myrient.erista.me"));
        assert!(prompt.contains("Use the source URL domain first"));
    }

    #[test]
    fn domain_parser_handles_urls_and_bare_domains() {
        assert_eq!(
            domain_from_input("https://www.MYRient.Erista.me/files"),
            Some("myrient.erista.me".to_string())
        );
        assert_eq!(
            domain_from_input("romhustler.net/some/path"),
            Some("romhustler.net".to_string())
        );
        assert_eq!(domain_from_input(""), None);
    }

    #[test]
    fn navigation_loop_detection_catches_repeat_cycles() {
        let history = vec![
            normalize_navigation_url("https://example.com"),
            normalize_navigation_url("https://example.com/files"),
            normalize_navigation_url("https://example.com/files/nes"),
            normalize_navigation_url("https://example.com"),
            normalize_navigation_url("https://example.com/files"),
            normalize_navigation_url("https://example.com/files/nes"),
        ];
        assert!(navigation_loop_detected(&history));
    }

    #[test]
    fn prompt_keywords_remove_noise_words() {
        let keywords = extract_prompt_keywords("download the super mario 3 nes rom from myrient");
        assert!(keywords.contains(&"super".to_string()));
        assert!(keywords.contains(&"mario".to_string()));
        assert!(keywords.contains(&"3".to_string()));
        assert!(!keywords.contains(&"download".to_string()));
        assert!(!keywords.contains(&"rom".to_string()));
    }

    #[test]
    fn file_filter_entries_parse_structured_lines() {
        let output = "\
            [FILE_FILTER] PATTERN: *invoice*\n\
            [FILE_FILTER] PATTERN: *final*, *approved*\n\
            [FILE_FILTER] *invoice*\n";

        let filters = extract_file_filter_entries(output);
        assert_eq!(
            filters,
            vec![
                "*invoice*".to_string(),
                "*final*".to_string(),
                "*approved*".to_string()
            ]
        );
    }

    #[test]
    fn file_filter_entries_ignore_empty_noise() {
        let output = "\
            [FILE_FILTER] PATTERN:\n\
            [FILE_FILTER] PATTERN:   \"  \"\n\
            [FILE_FILTER] PATTERN:    \n";

        let filters = extract_file_filter_entries(output);
        assert!(filters.is_empty());
    }
}
