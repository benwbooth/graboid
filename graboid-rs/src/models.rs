use std::collections::BTreeMap;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Pending,
    Running,
    Browsing,
    Downloading,
    Extracting,
    Copying,
    Complete,
    Failed,
    Cancelled,
}

impl JobStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Browsing => "browsing",
            Self::Downloading => "downloading",
            Self::Extracting => "extracting",
            Self::Copying => "copying",
            Self::Complete => "complete",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Complete | Self::Failed | Self::Cancelled)
    }
}

impl FromStr for JobStatus {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "pending" => Self::Pending,
            "running" => Self::Running,
            "browsing" => Self::Browsing,
            "downloading" => Self::Downloading,
            "extracting" => Self::Extracting,
            "copying" => Self::Copying,
            "complete" => Self::Complete,
            "failed" => Self::Failed,
            "cancelled" => Self::Cancelled,
            _ => return Err(()),
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobPhase {
    Init,
    Browse,
    Download,
    Extract,
    Copy,
    Done,
}

impl JobPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Init => "init",
            Self::Browse => "browse",
            Self::Download => "download",
            Self::Extract => "extract",
            Self::Copy => "copy",
            Self::Done => "done",
        }
    }
}

impl FromStr for JobPhase {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "init" => Self::Init,
            "browse" => Self::Browse,
            "download" => Self::Download,
            "extract" => Self::Extract,
            "copy" => Self::Copy,
            "done" => Self::Done,
            _ => return Err(()),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub prompt: String,
    pub source_url: String,
    pub credential_name: Option<String>,
    pub file_filter: Vec<String>,
    pub destination_path: String,
    pub file_operation: String,
    pub priority: i32,
    pub status: JobStatus,
    pub current_phase: JobPhase,
    pub progress_percent: f64,
    pub progress_message: String,
    pub found_urls: Vec<String>,
    pub downloaded_files: Vec<String>,
    pub final_paths: Vec<String>,
    pub error_message: String,
    pub metadata: Value,
}

impl Job {
    pub fn new(req: CreateJobRequest, default_destination: &str) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            created_at: now,
            updated_at: now,
            prompt: req.prompt,
            source_url: req.source_url,
            credential_name: req.credential_name,
            file_filter: req.file_filter,
            destination_path: if req.destination_path.trim().is_empty() {
                default_destination.to_string()
            } else {
                req.destination_path
            },
            file_operation: if req.file_operation.trim().is_empty() {
                "copy".to_string()
            } else {
                req.file_operation
            },
            priority: req.priority,
            status: JobStatus::Pending,
            current_phase: JobPhase::Init,
            progress_percent: 0.0,
            progress_message: "Queued".to_string(),
            found_urls: Vec::new(),
            downloaded_files: Vec::new(),
            final_paths: Vec::new(),
            error_message: String::new(),
            metadata: req.metadata,
        }
    }

    pub fn touch(&mut self) {
        self.updated_at = Utc::now();
    }

    pub fn set_status(&mut self, status: JobStatus) {
        self.status = status;
        self.touch();
    }

    pub fn set_phase(&mut self, phase: JobPhase) {
        self.current_phase = phase;
        self.touch();
    }

    pub fn set_progress(&mut self, progress_percent: f64, message: impl Into<String>) {
        self.progress_percent = progress_percent.clamp(0.0, 100.0);
        self.progress_message = message.into();
        self.touch();
    }

    pub fn fail(&mut self, message: impl Into<String>) {
        self.set_status(JobStatus::Failed);
        self.set_phase(JobPhase::Done);
        self.set_progress(self.progress_percent.max(1.0), "Failed");
        self.error_message = message.into();
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateJobRequest {
    pub prompt: String,
    #[serde(default)]
    pub source_url: String,
    #[serde(default)]
    pub credential_name: Option<String>,
    #[serde(default)]
    pub file_filter: Vec<String>,
    #[serde(default)]
    pub destination_path: String,
    #[serde(default = "default_file_operation")]
    pub file_operation: String,
    #[serde(default)]
    pub priority: i32,
    #[serde(default = "default_metadata")]
    pub metadata: Value,
}

fn default_file_operation() -> String {
    "copy".to_string()
}

fn default_metadata() -> Value {
    Value::Object(Default::default())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobLogEntry {
    pub id: i64,
    pub job_id: String,
    pub timestamp: DateTime<Utc>,
    pub level: String,
    pub source: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobStepEntry {
    pub id: i64,
    pub job_id: String,
    pub step_number: i64,
    pub action: String,
    pub observation: String,
    pub url: String,
    pub is_error: bool,
    pub notes: Vec<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct JobScreenshotEntry {
    pub id: i64,
    pub job_id: String,
    pub timestamp: DateTime<Utc>,
    pub screenshot_data: Vec<u8>,
    pub url: String,
    pub phase: String,
    pub step_number: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobStepDetail {
    pub step_number: i64,
    pub action: String,
    pub observation: String,
    pub url: String,
    pub timestamp: DateTime<Utc>,
    pub is_error: bool,
    pub screenshot_base64: Option<String>,
    pub notes: Vec<String>,
    pub claude_messages: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoteEntry {
    pub id: i64,
    pub domain: String,
    pub note_type: String,
    pub content: String,
    pub label: Option<String>,
    pub url_pattern: Option<String>,
    pub success: Option<bool>,
    pub use_count: i64,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoteStats {
    pub total_notes: i64,
    pub domains: i64,
    pub successful: i64,
    pub by_type: BTreeMap<String, i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialEntry {
    pub name: String,
    pub username: String,
    pub password: String,
    pub metadata: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct JobListResponse {
    pub jobs: Vec<Job>,
    pub total: i64,
    pub offset: i64,
    pub limit: i64,
}
