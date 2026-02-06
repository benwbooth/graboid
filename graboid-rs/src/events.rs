use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};

use crate::models::{Job, JobLogEntry, JobScreenshotEntry, JobStepEntry};

#[derive(Debug, Clone)]
pub enum ServerEvent {
    JobUpdate(Job),
    JobLog(JobLogEntry),
    JobStep(JobStepEntry),
    JobScreenshot(JobScreenshotEntry),
    Status { is_running: bool, task: String },
    Message { role: String, content: String },
    Screenshot { data_base64: String, url: String },
}

impl ServerEvent {
    pub fn as_json_value(&self) -> Value {
        match self {
            Self::JobUpdate(job) => json!({
                "type": "job_update",
                "job_id": job.id,
                "status": job.status,
                "phase": job.current_phase,
                "progress": job.progress_percent,
                "message": job.progress_message,
                "updated_at": job.updated_at,
            }),
            Self::JobLog(log) => json!({
                "type": "job_log",
                "job_id": log.job_id,
                "id": log.id,
                "level": log.level,
                "source": log.source,
                "message": log.message,
                "timestamp": log.timestamp,
            }),
            Self::JobStep(step) => json!({
                "type": "job_step",
                "job_id": step.job_id,
                "id": step.id,
                "step_number": step.step_number,
                "action": step.action,
                "observation": step.observation,
                "url": step.url,
                "is_error": step.is_error,
                "notes": step.notes,
                "timestamp": step.timestamp,
                "screenshot_base64": Value::Null,
            }),
            Self::JobScreenshot(shot) => json!({
                "type": "job_screenshot",
                "job_id": shot.job_id,
                "id": shot.id,
                "timestamp": shot.timestamp,
                "url": shot.url,
                "phase": shot.phase,
                "step_number": shot.step_number,
                "data_base64": STANDARD.encode(&shot.screenshot_data),
            }),
            Self::Status { is_running, task } => json!({
                "type": "status",
                "is_running": is_running,
                "task": task,
            }),
            Self::Message { role, content } => json!({
                "type": "message",
                "role": role,
                "content": content,
            }),
            Self::Screenshot { data_base64, url } => json!({
                "type": "screenshot",
                "data": data_base64,
                "url": url,
            }),
        }
    }
}
