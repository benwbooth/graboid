use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use regex::Regex;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;
use tokio::time::{Instant, MissedTickBehavior};
use tracing::{debug, info, warn};
use which::which;

use crate::config::AppConfig;

#[derive(Debug, Clone)]
pub enum NavEvent {
    Log {
        level: String,
        source: String,
        message: String,
    },
    Progress {
        percent: f64,
        message: String,
    },
    FoundUrl {
        url: String,
    },
    Step {
        step_number: i64,
        action: String,
        observation: String,
        url: String,
        is_error: bool,
        notes: Vec<String>,
    },
}

#[derive(Debug, Clone)]
pub struct NavigationOutcome {
    pub found_urls: Vec<String>,
    pub downloaded_files: Vec<String>,
    pub raw_output: String,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum BrowserBackend {
    ChromeDevtools,
    BrowserUse,
}

impl BrowserBackend {
    fn from_mode(mode: &str) -> Self {
        if mode.eq_ignore_ascii_case("browser_use") {
            Self::BrowserUse
        } else {
            Self::ChromeDevtools
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            Self::ChromeDevtools => "chrome-devtools",
            Self::BrowserUse => "browser-use",
        }
    }
}

const CHROME_STARTUP_TIMEOUT: Duration = Duration::from_secs(15);
const CLAUDE_STARTUP_SILENCE_TIMEOUT: Duration = Duration::from_secs(45);
const CLAUDE_IDLE_SILENCE_TIMEOUT: Duration = Duration::from_secs(75);
const CLAUDE_POST_DISCOVERY_IDLE_FINISH_TIMEOUT: Duration = Duration::from_secs(20);
const CLAUDE_WAITING_LOG_INTERVAL: Duration = Duration::from_secs(10);
const CLAUDE_IDLE_LOG_INTERVAL: Duration = Duration::from_secs(20);

pub async fn run_navigation(
    job_id: &str,
    source_url: &str,
    prompt: &str,
    file_filter: &[String],
    destination_path: &str,
    file_operation: &str,
    credential: Option<(String, String)>,
    cfg: &AppConfig,
    nav_tx: mpsc::UnboundedSender<NavEvent>,
) -> Result<NavigationOutcome> {
    let preferred_backend = BrowserBackend::from_mode(&cfg.browser_mode);
    let _ = nav_tx.send(NavEvent::Log {
        level: "INFO".to_string(),
        source: "browse".to_string(),
        message: format!(
            "Using browser backend: {}",
            preferred_backend.display_name()
        ),
    });

    if preferred_backend == BrowserBackend::BrowserUse {
        match run_navigation_with_backend(
            job_id,
            source_url,
            prompt,
            file_filter,
            destination_path,
            file_operation,
            credential.clone(),
            cfg,
            nav_tx.clone(),
            preferred_backend,
        )
        .await
        {
            Ok(outcome) => return Ok(outcome),
            Err(err) => {
                let _ = nav_tx.send(NavEvent::Log {
                    level: "WARNING".to_string(),
                    source: "browse".to_string(),
                    message: format!(
                        "browser-use backend failed: {err}. Falling back to chrome-devtools."
                    ),
                });
            }
        }
    }

    run_navigation_with_backend(
        job_id,
        source_url,
        prompt,
        file_filter,
        destination_path,
        file_operation,
        credential,
        cfg,
        nav_tx,
        BrowserBackend::ChromeDevtools,
    )
    .await
}

async fn run_navigation_with_backend(
    job_id: &str,
    source_url: &str,
    prompt: &str,
    file_filter: &[String],
    destination_path: &str,
    file_operation: &str,
    credential: Option<(String, String)>,
    cfg: &AppConfig,
    nav_tx: mpsc::UnboundedSender<NavEvent>,
    backend: BrowserBackend,
) -> Result<NavigationOutcome> {
    let _ = nav_tx.send(NavEvent::Progress {
        percent: 11.0,
        message: "Preparing browser session".to_string(),
    });

    let download_dir = cfg.download_dir();
    tokio::fs::create_dir_all(&download_dir)
        .await
        .with_context(|| format!("failed creating download dir {download_dir:?}"))?;

    let files_before = list_files(&download_dir);

    let mut chrome_child = if backend == BrowserBackend::ChromeDevtools {
        let _ = nav_tx.send(NavEvent::Progress {
            percent: 12.0,
            message: "Launching Chrome debug session".to_string(),
        });
        Some(
            start_chrome(job_id, cfg, &download_dir)
                .await
                .context("failed to start managed chrome")?,
        )
    } else {
        None
    };

    if backend == BrowserBackend::ChromeDevtools {
        let _ = nav_tx.send(NavEvent::Progress {
            percent: 14.0,
            message: format!("Chrome debug endpoint ready on :{}", cfg.chrome_debug_port),
        });
    }

    let mcp_config = build_mcp_config(cfg, backend);

    let full_prompt = build_prompt(
        source_url,
        prompt,
        file_filter,
        destination_path,
        file_operation,
        &download_dir,
        cfg,
        backend,
        credential
            .as_ref()
            .map(|(username, password)| (username.as_str(), password.as_str())),
    );
    let _ = nav_tx.send(NavEvent::Progress {
        percent: 15.0,
        message: format!("Starting Claude with {} MCP", backend.display_name()),
    });
    let raw_output = match run_claude_session(job_id, &full_prompt, cfg, &mcp_config, &nav_tx).await
    {
        Ok(output) => output,
        Err(err) => {
            if let Some(child) = chrome_child.as_mut() {
                stop_chrome(child).await;
            }
            return Err(err);
        }
    };
    if let Some(child) = chrome_child.as_mut() {
        stop_chrome(child).await;
    }

    let files_after = list_files(&download_dir);
    let new_downloads = files_after
        .difference(&files_before)
        .map(|name| download_dir.join(name).display().to_string())
        .collect::<Vec<_>>();

    let found_urls = parse_download_links(&raw_output);

    Ok(NavigationOutcome {
        found_urls,
        downloaded_files: new_downloads,
        raw_output,
    })
}

fn build_mcp_config(cfg: &AppConfig, backend: BrowserBackend) -> Value {
    match backend {
        BrowserBackend::ChromeDevtools => {
            let (command, args) = chrome_devtools_mcp_command(cfg.chrome_debug_port);
            json!({
                "mcpServers": {
                    "chrome-devtools": {
                        "command": command,
                        "args": args,
                    }
                }
            })
        }
        BrowserBackend::BrowserUse => {
            let command = cfg.browser_use_mcp_command.trim();
            let command = if command.is_empty() { "uvx" } else { command };
            let mut args = parse_browser_use_args(&cfg.browser_use_mcp_args);
            if args.is_empty() {
                args.push("browser-use[mcp]".to_string());
            }
            json!({
                "mcpServers": {
                    "browser-use": {
                        "command": command,
                        "args": args,
                    }
                }
            })
        }
    }
}

fn chrome_devtools_mcp_command(port: u16) -> (String, Vec<String>) {
    let browser_url = format!("http://127.0.0.1:{port}");
    if let Ok(path) = which("chrome-devtools-mcp") {
        return (
            path.display().to_string(),
            vec!["--browserUrl".to_string(), browser_url],
        );
    }

    (
        "npx".to_string(),
        vec![
            "--yes".to_string(),
            "chrome-devtools-mcp@latest".to_string(),
            "--browserUrl".to_string(),
            browser_url,
        ],
    )
}

fn parse_browser_use_args(input: &str) -> Vec<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    shlex::split(trimmed).unwrap_or_else(|| {
        trimmed
            .split_whitespace()
            .map(str::trim)
            .filter(|arg| !arg.is_empty())
            .map(str::to_string)
            .collect()
    })
}

async fn run_claude_session(
    job_id: &str,
    prompt: &str,
    cfg: &AppConfig,
    mcp_config: &Value,
    nav_tx: &mpsc::UnboundedSender<NavEvent>,
) -> Result<String> {
    let _ = nav_tx.send(NavEvent::Progress {
        percent: 15.5,
        message: "Spawning Claude process".to_string(),
    });

    let mut cmd = Command::new(&cfg.claude_cmd);
    cmd.arg("-p")
        .arg(prompt)
        .arg("--model")
        .arg(&cfg.claude_model)
        .arg("--mcp-config")
        .arg(mcp_config.to_string())
        .arg("--strict-mcp-config")
        .arg("--dangerously-skip-permissions")
        .arg("--output-format")
        .arg("stream-json")
        .arg("--include-partial-messages")
        .arg("--verbose")
        .arg("--no-session-persistence")
        .arg("--disallowed-tools")
        .arg("Bash,Read,Write,Edit,Task,Grep")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut proc = cmd
        .spawn()
        .with_context(|| format!("failed to spawn {}", cfg.claude_cmd))?;

    let _ = nav_tx.send(NavEvent::Progress {
        percent: 17.0,
        message: "Waiting for Claude MCP startup".to_string(),
    });

    let (line_tx, mut line_rx) = mpsc::unbounded_channel::<String>();

    if let Some(stdout) = proc.stdout.take() {
        spawn_output_reader(stdout, line_tx.clone(), "claude-stdout");
    }

    if let Some(stderr) = proc.stderr.take() {
        spawn_output_reader(stderr, line_tx.clone(), "claude-stderr");
    }

    drop(line_tx);

    let mut step_counter = 0_i64;
    let mut raw_output = String::new();
    let mut stream_connected = false;
    let mut startup_waited = 0_u64;
    let mut last_output_at = Instant::now();
    let mut discovered_url_count = 0usize;

    let timeout = tokio::time::sleep(Duration::from_secs(cfg.claude_timeout_seconds));
    tokio::pin!(timeout);
    let startup_deadline = Instant::now() + CLAUDE_STARTUP_SILENCE_TIMEOUT;
    let silence_timeout = tokio::time::sleep_until(startup_deadline);
    tokio::pin!(silence_timeout);

    let mut startup_tick = tokio::time::interval(CLAUDE_WAITING_LOG_INTERVAL);
    startup_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    startup_tick.tick().await;
    let mut idle_tick = tokio::time::interval(CLAUDE_IDLE_LOG_INTERVAL);
    idle_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    idle_tick.tick().await;

    loop {
        tokio::select! {
            _ = &mut timeout => {
                warn!(job_id, "claude timed out after {}s", cfg.claude_timeout_seconds);
                let _ = nav_tx.send(NavEvent::Log {
                    level: "ERROR".to_string(),
                    source: "claude".to_string(),
                    message: format!("Claude timed out after {} seconds", cfg.claude_timeout_seconds),
                });
                let _ = proc.kill().await;
                break;
            }
            _ = startup_tick.tick(), if !stream_connected => {
                startup_waited += CLAUDE_WAITING_LOG_INTERVAL.as_secs();
                let _ = nav_tx.send(NavEvent::Log {
                    level: "INFO".to_string(),
                    source: "claude".to_string(),
                    message: format!(
                        "Still waiting for Claude MCP startup ({}s elapsed)",
                        startup_waited
                    ),
                });
                let _ = nav_tx.send(NavEvent::Progress {
                    percent: (17.0 + (startup_waited as f64 / 20.0)).min(19.5),
                    message: format!(
                        "Waiting for Claude MCP startup ({}s)",
                        startup_waited
                    ),
                });
            }
            _ = idle_tick.tick(), if stream_connected => {
                let idle_secs = Instant::now()
                    .saturating_duration_since(last_output_at)
                    .as_secs();
                if discovered_url_count > 0
                    && idle_secs >= CLAUDE_POST_DISCOVERY_IDLE_FINISH_TIMEOUT.as_secs()
                {
                    let _ = nav_tx.send(NavEvent::Log {
                        level: "INFO".to_string(),
                        source: "claude".to_string(),
                        message: format!(
                            "No new Claude output for {idle_secs}s after finding {discovered_url_count} URL(s); ending browse attempt"
                        ),
                    });
                    let _ = proc.kill().await;
                    let _ = tokio::time::timeout(Duration::from_secs(5), proc.wait()).await;
                    return Ok(raw_output);
                }

                let _ = nav_tx.send(NavEvent::Log {
                    level: "INFO".to_string(),
                    source: "claude".to_string(),
                    message: format!("Waiting for Claude output ({idle_secs}s idle)"),
                });
            }
            _ = &mut silence_timeout => {
                let (seconds, context) = if stream_connected {
                    (
                        CLAUDE_IDLE_SILENCE_TIMEOUT.as_secs(),
                        "while running browser automation",
                    )
                } else {
                    (
                        CLAUDE_STARTUP_SILENCE_TIMEOUT.as_secs(),
                        "while waiting for Claude stream startup",
                    )
                };
                let message = format!("Claude produced no output for {seconds}s {context}");
                warn!(job_id, "{message}");
                let _ = nav_tx.send(NavEvent::Log {
                    level: "ERROR".to_string(),
                    source: "claude".to_string(),
                    message: message.clone(),
                });
                let _ = nav_tx.send(NavEvent::Progress {
                    percent: 19.5,
                    message: "Claude stalled; aborting attempt".to_string(),
                });
                let _ = proc.kill().await;
                return Err(anyhow!(message));
            }
            maybe_line = line_rx.recv() => {
                match maybe_line {
                    Some(line) => {
                        let line_result = handle_claude_line(
                            &line,
                            &mut raw_output,
                            &mut step_counter,
                            nav_tx,
                        );
                        discovered_url_count += line_result.found_urls;

                        if line_result.stream_connected && !stream_connected {
                            stream_connected = true;
                            last_output_at = Instant::now();
                            let _ = nav_tx.send(NavEvent::Progress {
                                percent: 20.0,
                                message: "Claude stream connected".to_string(),
                            });
                            silence_timeout.as_mut().reset(Instant::now() + CLAUDE_IDLE_SILENCE_TIMEOUT);
                        } else if stream_connected {
                            last_output_at = Instant::now();
                            silence_timeout
                                .as_mut()
                                .reset(Instant::now() + CLAUDE_IDLE_SILENCE_TIMEOUT);
                        }
                    }
                    None => break,
                }
            }
        }
    }

    let status = tokio::time::timeout(Duration::from_secs(5), proc.wait()).await;
    match status {
        Ok(Ok(exit)) if exit.success() => {
            info!(job_id, "claude exited successfully");
        }
        Ok(Ok(exit)) => {
            let _ = nav_tx.send(NavEvent::Log {
                level: "ERROR".to_string(),
                source: "claude".to_string(),
                message: format!("Claude exited with status {}", exit),
            });
            return Err(anyhow!("claude exited unsuccessfully: {exit}"));
        }
        Ok(Err(err)) => {
            return Err(err).context("waiting for claude failed");
        }
        Err(_) => {
            let _ = proc.kill().await;
            return Err(anyhow!("timed out waiting for claude process to exit"));
        }
    }

    Ok(raw_output)
}

fn handle_claude_line(
    line: &str,
    raw_output: &mut String,
    step_counter: &mut i64,
    nav_tx: &mpsc::UnboundedSender<NavEvent>,
) -> ClaudeLineResult {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return ClaudeLineResult::default();
    }

    if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
        let mut result = ClaudeLineResult::default();
        match value
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default()
        {
            "system" => {
                result.stream_connected = true;
                let _ = nav_tx.send(NavEvent::Log {
                    level: "INFO".to_string(),
                    source: "claude".to_string(),
                    message: "Claude stream connected".to_string(),
                });
            }
            "assistant" => {
                result.stream_connected = true;
                if let Some(content) = value
                    .get("message")
                    .and_then(|v| v.get("content"))
                    .and_then(Value::as_array)
                {
                    for block in content {
                        match block
                            .get("type")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                        {
                            "tool_use" => {
                                *step_counter += 1;
                                let tool_name =
                                    block.get("name").and_then(Value::as_str).unwrap_or("tool");
                                let input = block.get("input").cloned().unwrap_or(Value::Null);
                                let (action, observation, url) =
                                    map_tool_to_step(tool_name, &input);
                                let _ = nav_tx.send(NavEvent::Step {
                                    step_number: *step_counter,
                                    action,
                                    observation,
                                    url,
                                    is_error: false,
                                    notes: Vec::new(),
                                });
                            }
                            "text" => {
                                if let Some(text) = block.get("text").and_then(Value::as_str) {
                                    let links = parse_download_links(text);
                                    result.found_urls += links.len();
                                    for url in links {
                                        let _ = nav_tx.send(NavEvent::FoundUrl { url });
                                    }
                                    raw_output.push_str(text);
                                    raw_output.push('\n');
                                    for line in text.lines() {
                                        let line = line.trim();
                                        if line.is_empty() {
                                            continue;
                                        }
                                        let excerpt = truncate(line, 220);
                                        let _ = nav_tx.send(NavEvent::Log {
                                            level: "INFO".to_string(),
                                            source: "claude_output".to_string(),
                                            message: excerpt,
                                        });
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            "result" => {
                result.stream_connected = true;
                if let Some(result_text) = value.get("result").and_then(Value::as_str) {
                    let links = parse_download_links(result_text);
                    result.found_urls += links.len();
                    for url in links {
                        let _ = nav_tx.send(NavEvent::FoundUrl { url });
                    }
                    raw_output.push_str(result_text);
                    raw_output.push('\n');
                }
            }
            _ => {}
        }
        return result;
    }

    debug!("non-json claude line: {trimmed}");
    raw_output.push_str(trimmed);
    raw_output.push('\n');
    let _ = nav_tx.send(NavEvent::Log {
        level: "DEBUG".to_string(),
        source: "claude_raw".to_string(),
        message: truncate(trimmed, 220),
    });
    ClaudeLineResult::default()
}

#[derive(Default)]
struct ClaudeLineResult {
    stream_connected: bool,
    found_urls: usize,
}

fn spawn_output_reader<R>(stream: R, tx: mpsc::UnboundedSender<String>, stream_name: &'static str)
where
    R: AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut reader = BufReader::new(stream);
        let mut buf = Vec::with_capacity(4096);

        loop {
            buf.clear();
            match reader.read_until(b'\n', &mut buf).await {
                Ok(0) => break,
                Ok(_) => {
                    while matches!(buf.last(), Some(b'\n' | b'\r')) {
                        buf.pop();
                    }
                    if buf.is_empty() {
                        continue;
                    }
                    let line = String::from_utf8_lossy(&buf).into_owned();
                    let _ = tx.send(line);
                }
                Err(err) => {
                    let _ = tx.send(format!("[{stream_name} read error] {err}"));
                    break;
                }
            }
        }
    });
}

fn map_tool_to_step(tool_name: &str, input: &Value) -> (String, String, String) {
    let name = tool_name.to_ascii_lowercase();
    let input_text = truncate(&input.to_string(), 200);

    if name.contains("navigate") {
        let url = input
            .get("url")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        return (
            "Navigate".to_string(),
            if url.is_empty() {
                "Navigate page".to_string()
            } else {
                format!("Navigate to {url}")
            },
            url,
        );
    }

    if name.contains("click") {
        return (
            "Click".to_string(),
            format!("Click element ({input_text})"),
            String::new(),
        );
    }

    if name.contains("type") || name.contains("fill") {
        return (
            "Type".to_string(),
            format!("Type input ({input_text})"),
            String::new(),
        );
    }

    if name.contains("scroll") {
        return (
            "Scroll".to_string(),
            format!("Scroll page ({input_text})"),
            String::new(),
        );
    }

    if name.contains("screenshot") {
        return (
            "Screenshot".to_string(),
            "Capture screenshot".to_string(),
            String::new(),
        );
    }

    (
        tool_name.to_string(),
        format!("Tool call {tool_name} ({input_text})"),
        String::new(),
    )
}

fn parse_download_links(text: &str) -> Vec<String> {
    let mut links = Vec::new();

    let explicit = Regex::new(r#"(?i)\[DOWNLOAD\]\s*URL:\s*(https?://[^\s<>"]+)"#).unwrap();
    for capture in explicit.captures_iter(text) {
        if let Some(url) = capture.get(1) {
            links.push(clean_url(url.as_str()));
        }
    }

    let files = Regex::new(
        r#"(?i)https?://[^\s<>"']+\.(zip|7z|rar|torrent|iso|chd|bin|cue|nes|rom)(\?[^\s<>"']*)?"#,
    )
    .unwrap();
    for capture in files.captures_iter(text) {
        if let Some(m) = capture.get(0) {
            links.push(clean_url(m.as_str()));
        }
    }

    let magnets = Regex::new(r#"(?i)magnet:\?[^\s<>"]+"#).unwrap();
    for capture in magnets.captures_iter(text) {
        if let Some(m) = capture.get(0) {
            links.push(clean_url(m.as_str()));
        }
    }

    links.retain(|u| !u.contains('{') && !u.contains('}'));
    links.sort();
    links.dedup();
    links
}

fn clean_url(url: &str) -> String {
    url.trim_end_matches(&['.', ',', ';', ')', ']', '"', '\''][..])
        .to_string()
}

fn truncate(input: &str, max: usize) -> String {
    if input.len() <= max {
        return input.to_string();
    }
    format!("{}...", &input[..max])
}

fn build_prompt(
    source_url: &str,
    prompt: &str,
    file_filter: &[String],
    destination_path: &str,
    file_operation: &str,
    download_dir: &Path,
    cfg: &AppConfig,
    backend: BrowserBackend,
    credential: Option<(&str, &str)>,
) -> String {
    let target = if source_url.trim().is_empty() {
        "about:blank"
    } else {
        source_url
    };

    let credential_block = credential
        .map(|(username, password)| {
            format!(
                "LOGIN CREDENTIALS (use only when the site requests authentication):\n\
                 - Username: {username}\n\
                 - Password: {password}\n\n"
            )
        })
        .unwrap_or_default();

    let backend_intro = match backend {
        BrowserBackend::ChromeDevtools => {
            "You have access to chrome-devtools MCP tools to control a browser.\n\
             The browser is already running and downloads automatically save to:"
        }
        BrowserBackend::BrowserUse => {
            "You have access to browser-use MCP tools to control a browser.\n\
             Use browser-use tools for navigation and emit discovered links. Download directory:"
        }
    };
    let backend_requirement = match backend {
        BrowserBackend::ChromeDevtools => "Use chrome-devtools MCP tools for navigation.",
        BrowserBackend::BrowserUse => "Use browser-use MCP tools for navigation.",
    };
    let file_filter_summary = if file_filter.is_empty() {
        "none".to_string()
    } else {
        file_filter
            .iter()
            .take(8)
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };
    let selective_torrent_status = if matches!(cfg.torrent_client.as_str(), "embedded" | "auto") {
        if cfg!(feature = "librqbit-embedded") {
            if file_filter.is_empty() {
                "available (emit [FILE_FILTER] PATTERN lines to activate selective matching)"
            } else {
                "enabled (active file filters will be used)"
            }
        } else {
            "configured but unavailable in this build (missing feature `librqbit-embedded`)"
        }
    } else {
        "disabled by torrent_client setting (non-embedded backend)"
    };
    let file_filter_requirement = if file_filter.is_empty() {
        "If you can infer target filenames, emit one or more `[FILE_FILTER] PATTERN: <glob>` lines before finishing (example: `[FILE_FILTER] PATTERN: *invoice*.*`)."
    } else {
        "Respect active file filters and prioritize links likely to match them."
    };

    format!(
        "{} {}\n\n\
         {}\
         Navigate to {} and complete this task:\n{}\n\n\
         JOB CONTEXT:\n\
         - destination_path: {}\n\
         - file_operation: {}\n\
         - file_filter: {}\n\
         - torrent_client: {}\n\
         - selective_torrent: {}\n\
         - archive_extractors: zip, 7z, rar, tar, tar.gz, tar.bz2, tar.xz, tar.zst/tzst, gz, bz2, xz, zst\n\n\
         BACKEND TOOLCHAIN (triggered by your outputs):\n\
         - Emit `[DOWNLOAD] URL: <url>` for direct files, magnet links, or `.torrent` links.\n\
         - Backend will download, extract archives, filter files, and place final outputs automatically.\n\
         - Use strong judgment: prefer the most relevant, authoritative, complete, and user-intent-aligned result(s).\n\
         - After surveying relevant options on the current page, emit a curated set of best candidates (usually 1-5).\n\n\
         REQUIREMENTS:\n\
         - {} \n\
         - Use targeted page search with evaluate_script (querySelectorAll on links/buttons) before broad snapshots.\n\
         - On long directory pages, do one evaluate_script pass that extracts all anchor href/text pairs and filter in-script by task keywords.\n\
         - Do not loop between homepage and the same directory. Stay in the deepest relevant page until links are extracted.\n\
         - Never navigate to about:blank again after the first real page load unless recovery is required.\n\
         - Avoid repeated identical tool calls; if one approach fails, switch strategy immediately.\n\
         - When you find a downloadable link, emit: [DOWNLOAD] URL: <url>\n\
         - {}\n\
         - When multiple plausible options exist, choose a small curated set using common-sense quality checks and user intent.\n\
         - Avoid low-value or ambiguous variants unless no better candidate exists.\n\
         - Do not stop at the first plausible link; quickly compare nearby alternatives on the same page before deciding.\n\
         - Emit learning notes when useful: [LEARNING: type=navigation_tip] <tip> or [LEARNING: type=download_method] <tip>\n\
         - Emit clear progress while navigating.\n\
         - End with [RESULT] SUCCESS: true/false\n\
         - If blocked, emit: [ERROR] PROBLEM: <description>\n\n\
         Start by navigating to {}",
        backend_intro,
        download_dir.display(),
        credential_block,
        target,
        prompt,
        destination_path,
        file_operation,
        file_filter_summary,
        cfg.torrent_client,
        selective_torrent_status,
        backend_requirement,
        file_filter_requirement,
        target
    )
}

async fn start_chrome(job_id: &str, cfg: &AppConfig, download_dir: &Path) -> Result<Child> {
    let chrome_path = find_chrome_binary().context("chrome/chromium not found in PATH")?;

    let profile_dir = download_dir.join(format!(".chrome-profile-{job_id}"));
    tokio::fs::create_dir_all(&profile_dir)
        .await
        .with_context(|| format!("failed to create chrome profile {profile_dir:?}"))?;

    let mut cmd = Command::new(chrome_path);
    cmd.arg(format!("--remote-debugging-port={}", cfg.chrome_debug_port))
        .arg(format!("--user-data-dir={}", profile_dir.display()))
        .arg(format!(
            "--download-default-directory={}",
            download_dir.display()
        ))
        // Keep source snapshots readable without excessive memory cost.
        .arg("--window-size=1280,1024")
        .arg("--no-first-run")
        .arg("--no-default-browser-check")
        .arg("--disable-extensions")
        .arg("--disable-background-networking")
        .arg("--disable-popup-blocking")
        .arg("--disable-sync")
        .arg("about:blank")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .kill_on_drop(true);

    if cfg.chrome_headless {
        cmd.arg("--headless=new");
    }

    let mut child = cmd.spawn().context("failed spawning chrome")?;

    if let Some(status) = child.try_wait().context("failed checking chrome startup")? {
        return Err(anyhow!("chrome exited immediately with status {status}"));
    }

    if let Err(err) =
        wait_for_chrome_debug_endpoint(cfg.chrome_debug_port, CHROME_STARTUP_TIMEOUT).await
    {
        stop_chrome(&mut child).await;
        return Err(err);
    }

    info!(
        job_id,
        "managed chrome is ready on port {}", cfg.chrome_debug_port
    );
    Ok(child)
}

async fn stop_chrome(child: &mut Child) {
    if let Err(err) = child.kill().await {
        debug!("failed to kill chrome process: {err}");
    }
    let _ = child.wait().await;
}

fn find_chrome_binary() -> Option<PathBuf> {
    [
        "google-chrome-stable",
        "google-chrome",
        "chromium-browser",
        "chromium",
        "chrome",
    ]
    .iter()
    .find_map(|name| which(name).ok())
}

async fn wait_for_chrome_debug_endpoint(port: u16, timeout: Duration) -> Result<()> {
    let url = format!("http://127.0.0.1:{port}/json/version");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .context("failed to build HTTP client for chrome readiness probe")?;
    let deadline = Instant::now() + timeout;

    loop {
        if let Ok(response) = client.get(&url).send().await {
            if response.status().is_success() {
                return Ok(());
            }
        }

        if Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    Err(anyhow!(
        "chrome debug endpoint did not become ready at {url} within {}s",
        timeout.as_secs()
    ))
}

fn list_files(path: &Path) -> HashSet<String> {
    let Ok(read_dir) = std::fs::read_dir(path) else {
        return HashSet::new();
    };

    read_dir
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let is_file = entry.file_type().ok()?.is_file();
            if !is_file {
                return None;
            }
            Some(entry.file_name().to_string_lossy().to_string())
        })
        .collect()
}
