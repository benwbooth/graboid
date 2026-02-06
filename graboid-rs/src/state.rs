use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, Local, TimeZone, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, RwLock, broadcast};
use walkdir::WalkDir;

use crate::config::AppConfig;
use crate::db::JobDb;
use crate::events::ServerEvent;
use crate::runner::JobRunner;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub db: Arc<JobDb>,
    pub runner: Arc<JobRunner>,
    pub events: broadcast::Sender<ServerEvent>,
    pub runtime: Arc<RuntimeState>,
    pub git_info: GitInfo,
    pub auth: AuthConfig,
    pub config_path: PathBuf,
    pub api_key: Arc<RwLock<String>>,
}

#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub username: String,
    pub password: String,
    pub session_secret: String,
    pub session_max_age_seconds: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct GitInfo {
    pub backend: BuildStamp,
    pub frontend: BuildStamp,
}

#[derive(Debug, Clone, Serialize)]
pub struct BuildStamp {
    pub hash: String,
    pub timestamp: String,
    pub tz: String,
    pub epoch: i64,
}

impl GitInfo {
    pub fn capture(template_root: &Path) -> Self {
        Self {
            backend: capture_backend_stamp(),
            frontend: capture_frontend_stamp(template_root),
        }
    }
}

fn capture_backend_stamp() -> BuildStamp {
    let now = Local::now();
    let epoch = option_env!("BUILD_EPOCH")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or_else(|| now.timestamp());
    let built_at = Local.timestamp_opt(epoch, 0).single().unwrap_or(now);
    let hash = option_env!("BUILD_HASH")
        .filter(|v| !v.trim().is_empty())
        .unwrap_or("unknown")
        .to_string();

    BuildStamp {
        hash,
        timestamp: built_at.format("%Y-%m-%d %H:%M:%S").to_string(),
        tz: built_at.format("%Z").to_string(),
        epoch: built_at.timestamp(),
    }
}

fn capture_frontend_stamp(template_root: &Path) -> BuildStamp {
    let mut files = WalkDir::new(template_root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.path().to_path_buf())
        .collect::<Vec<_>>();
    files.sort();

    if files.is_empty() {
        let now = Local::now();
        return BuildStamp {
            hash: "unknown".to_string(),
            timestamp: now.format("%Y-%m-%d %H:%M:%S").to_string(),
            tz: now.format("%Z").to_string(),
            epoch: now.timestamp(),
        };
    }

    let mut hasher = Sha256::new();
    let mut latest_mtime: Option<DateTime<Local>> = None;

    for path in &files {
        let rel = path.strip_prefix(template_root).unwrap_or(path.as_path());
        hasher.update(rel.to_string_lossy().as_bytes());
        hasher.update([0_u8]);

        if let Ok(bytes) = std::fs::read(path) {
            hasher.update(&bytes);
            hasher.update([0_u8]);
        }

        if let Ok(meta) = std::fs::metadata(path) {
            if let Ok(modified) = meta.modified() {
                let modified_local: DateTime<Local> = DateTime::from(modified);
                if latest_mtime
                    .as_ref()
                    .map(|current| modified_local > *current)
                    .unwrap_or(true)
                {
                    latest_mtime = Some(modified_local);
                }
            }
        }
    }

    let digest_hex = format!("{:x}", hasher.finalize());
    let short_hash = digest_hex.chars().take(8).collect::<String>();
    let built_at = latest_mtime.unwrap_or_else(Local::now);

    BuildStamp {
        hash: short_hash,
        timestamp: built_at.format("%Y-%m-%d %H:%M:%S").to_string(),
        tz: built_at.format("%Z").to_string(),
        epoch: built_at.timestamp(),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct GlobalLogRecord {
    pub time: f64,
    pub level: String,
    pub name: String,
    pub message: String,
}

#[derive(Debug, Clone)]
struct RuntimeSnapshot {
    is_running: bool,
    current_task: String,
    browser_screenshot_base64: Option<String>,
    browser_url: String,
    downloads: Vec<serde_json::Value>,
    messages: VecDeque<AgentMessage>,
}

impl Default for RuntimeSnapshot {
    fn default() -> Self {
        Self {
            is_running: false,
            current_task: String::new(),
            browser_screenshot_base64: None,
            browser_url: String::new(),
            downloads: Vec::new(),
            messages: VecDeque::new(),
        }
    }
}

#[derive(Clone)]
pub struct RuntimeState {
    snapshot: Arc<RwLock<RuntimeSnapshot>>,
    logs: Arc<Mutex<VecDeque<GlobalLogRecord>>>,
    log_capacity: usize,
    message_capacity: usize,
}

impl RuntimeState {
    pub fn new(log_capacity: usize, message_capacity: usize) -> Self {
        Self {
            snapshot: Arc::new(RwLock::new(RuntimeSnapshot::default())),
            logs: Arc::new(Mutex::new(VecDeque::with_capacity(log_capacity))),
            log_capacity,
            message_capacity,
        }
    }

    pub async fn set_status(&self, is_running: bool, task: impl Into<String>) {
        let mut snap = self.snapshot.write().await;
        snap.is_running = is_running;
        snap.current_task = task.into();
    }

    pub async fn is_running(&self) -> bool {
        self.snapshot.read().await.is_running
    }

    pub async fn current_task(&self) -> String {
        self.snapshot.read().await.current_task.clone()
    }

    pub async fn add_message(&self, role: impl Into<String>, content: impl Into<String>) {
        let mut snap = self.snapshot.write().await;
        snap.messages.push_back(AgentMessage {
            role: role.into(),
            content: content.into(),
        });
        while snap.messages.len() > self.message_capacity {
            let _ = snap.messages.pop_front();
        }
    }

    pub async fn messages_tail(&self, count: usize) -> Vec<AgentMessage> {
        let snap = self.snapshot.read().await;
        let len = snap.messages.len();
        let skip = len.saturating_sub(count);
        snap.messages.iter().skip(skip).cloned().collect()
    }

    pub async fn set_screenshot(&self, base64_png: String, url: impl Into<String>) {
        let mut snap = self.snapshot.write().await;
        snap.browser_screenshot_base64 = Some(base64_png);
        snap.browser_url = url.into();
    }

    pub async fn screenshot(&self) -> Option<(String, String)> {
        let snap = self.snapshot.read().await;
        snap.browser_screenshot_base64
            .as_ref()
            .map(|data| (data.clone(), snap.browser_url.clone()))
    }

    pub async fn push_log(&self, level: &str, name: &str, message: &str) {
        let mut logs = self.logs.lock().await;
        logs.push_back(GlobalLogRecord {
            time: Utc::now().timestamp_millis() as f64 / 1000.0,
            level: level.to_string(),
            name: name.to_string(),
            message: message.to_string(),
        });
        while logs.len() > self.log_capacity {
            let _ = logs.pop_front();
        }
    }

    pub async fn global_logs(
        &self,
        limit: usize,
        level: Option<&str>,
        search: Option<&str>,
    ) -> Vec<GlobalLogRecord> {
        let logs = self.logs.lock().await;
        let level = level.map(|v| v.to_ascii_uppercase());
        let search = search.map(|v| v.to_ascii_lowercase());

        let mut filtered = logs
            .iter()
            .filter(|entry| {
                let level_ok = level
                    .as_ref()
                    .map(|needle| entry.level.eq_ignore_ascii_case(needle))
                    .unwrap_or(true);
                let search_ok = search
                    .as_ref()
                    .map(|needle| entry.message.to_ascii_lowercase().contains(needle))
                    .unwrap_or(true);
                level_ok && search_ok
            })
            .cloned()
            .collect::<Vec<_>>();

        if filtered.len() > limit {
            filtered = filtered.split_off(filtered.len() - limit);
        }
        filtered
    }

    pub async fn snapshot_status(&self) -> (bool, String, Vec<serde_json::Value>, usize) {
        let snap = self.snapshot.read().await;
        (
            snap.is_running,
            snap.current_task.clone(),
            snap.downloads.clone(),
            snap.messages.len(),
        )
    }
}
