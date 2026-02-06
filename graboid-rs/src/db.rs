use std::collections::BTreeMap;
use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};

use crate::models::{
    CredentialEntry, Job, JobLogEntry, JobPhase, JobScreenshotEntry, JobStatus, JobStepEntry,
    NoteEntry, NoteStats,
};

#[derive(Clone)]
pub struct JobDb {
    pool: SqlitePool,
}

impl JobDb {
    pub async fn new(db_path: &Path) -> Result<Self> {
        if let Some(parent) = db_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("failed creating database directory {parent:?}"))?;
        }

        let opts = SqliteConnectOptions::new()
            .filename(db_path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .foreign_keys(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(10)
            .connect_with(opts)
            .await
            .context("failed to connect to sqlite")?;

        let db = Self { pool };
        db.init().await?;
        Ok(db)
    }

    async fn init(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                prompt TEXT NOT NULL,
                source_url TEXT NOT NULL,
                credential_name TEXT,
                file_filter_json TEXT NOT NULL DEFAULT '[]',
                destination_path TEXT NOT NULL,
                file_operation TEXT NOT NULL,
                status TEXT NOT NULL,
                priority INTEGER NOT NULL,
                progress_percent REAL NOT NULL,
                progress_message TEXT NOT NULL,
                current_phase TEXT NOT NULL,
                found_urls_json TEXT NOT NULL,
                downloaded_files_json TEXT NOT NULL,
                final_paths_json TEXT NOT NULL,
                error_message TEXT NOT NULL,
                metadata_json TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("failed creating jobs table")?;

        // Compatibility migrations for older schema revisions.
        let _ = sqlx::query("ALTER TABLE jobs ADD COLUMN credential_name TEXT")
            .execute(&self.pool)
            .await;
        let _ =
            sqlx::query("ALTER TABLE jobs ADD COLUMN file_filter_json TEXT NOT NULL DEFAULT '[]'")
                .execute(&self.pool)
                .await;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS job_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                level TEXT NOT NULL,
                source TEXT NOT NULL,
                message TEXT NOT NULL,
                FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("failed creating job_logs table")?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS job_steps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT NOT NULL,
                step_number INTEGER NOT NULL,
                action TEXT NOT NULL,
                observation TEXT NOT NULL,
                url TEXT NOT NULL,
                is_error INTEGER NOT NULL,
                notes_json TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("failed creating job_steps table")?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS job_screenshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                screenshot_data BLOB NOT NULL,
                url TEXT NOT NULL,
                phase TEXT NOT NULL,
                step_number INTEGER,
                FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("failed creating job_screenshots table")?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                note_type TEXT NOT NULL,
                content TEXT NOT NULL,
                label TEXT,
                url_pattern TEXT,
                success INTEGER,
                use_count INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("failed creating notes table")?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS credentials (
                name TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("failed creating credentials table")?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status)")
            .execute(&self.pool)
            .await
            .context("failed creating idx_jobs_status")?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_jobs_priority_created ON jobs(priority DESC, created_at ASC)",
        )
        .execute(&self.pool)
        .await
        .context("failed creating idx_jobs_priority_created")?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_logs_job_time ON job_logs(job_id, timestamp)")
            .execute(&self.pool)
            .await
            .context("failed creating idx_logs_job_time")?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_steps_job_num ON job_steps(job_id, step_number)",
        )
        .execute(&self.pool)
        .await
        .context("failed creating idx_steps_job_num")?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_screenshots_job_time ON job_screenshots(job_id, timestamp)",
        )
        .execute(&self.pool)
        .await
        .context("failed creating idx_screenshots_job_time")?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_notes_domain ON notes(domain)")
            .execute(&self.pool)
            .await
            .context("failed creating idx_notes_domain")?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_credentials_updated ON credentials(updated_at DESC)",
        )
        .execute(&self.pool)
        .await
        .context("failed creating idx_credentials_updated")?;

        Ok(())
    }

    pub async fn requeue_inflight_jobs(&self) -> Result<u64> {
        let now = Utc::now().to_rfc3339();
        let result = sqlx::query(
            r#"
            UPDATE jobs
            SET status = 'pending',
                current_phase = 'init',
                progress_message = 'Requeued after restart',
                updated_at = ?
            WHERE status IN ('running', 'browsing', 'downloading', 'extracting', 'copying')
            "#,
        )
        .bind(now)
        .execute(&self.pool)
        .await
        .context("failed requeueing inflight jobs")?;

        Ok(result.rows_affected())
    }

    pub async fn create_job(&self, job: &Job) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO jobs (
                id, created_at, updated_at, prompt, source_url, credential_name,
                file_filter_json, destination_path, file_operation, status, priority,
                progress_percent, progress_message, current_phase, found_urls_json,
                downloaded_files_json, final_paths_json, error_message, metadata_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&job.id)
        .bind(job.created_at.to_rfc3339())
        .bind(job.updated_at.to_rfc3339())
        .bind(&job.prompt)
        .bind(&job.source_url)
        .bind(job.credential_name.clone())
        .bind(vec_to_json(&job.file_filter))
        .bind(&job.destination_path)
        .bind(&job.file_operation)
        .bind(job.status.as_str())
        .bind(job.priority)
        .bind(job.progress_percent)
        .bind(&job.progress_message)
        .bind(job.current_phase.as_str())
        .bind(vec_to_json(&job.found_urls))
        .bind(vec_to_json(&job.downloaded_files))
        .bind(vec_to_json(&job.final_paths))
        .bind(&job.error_message)
        .bind(value_to_json(&job.metadata))
        .execute(&self.pool)
        .await
        .context("failed inserting job")?;

        Ok(())
    }

    pub async fn update_job(&self, job: &Job) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE jobs
            SET updated_at = ?,
                prompt = ?,
                source_url = ?,
                credential_name = ?,
                file_filter_json = ?,
                destination_path = ?,
                file_operation = ?,
                status = ?,
                priority = ?,
                progress_percent = ?,
                progress_message = ?,
                current_phase = ?,
                found_urls_json = ?,
                downloaded_files_json = ?,
                final_paths_json = ?,
                error_message = ?,
                metadata_json = ?
            WHERE id = ?
            "#,
        )
        .bind(job.updated_at.to_rfc3339())
        .bind(&job.prompt)
        .bind(&job.source_url)
        .bind(job.credential_name.clone())
        .bind(vec_to_json(&job.file_filter))
        .bind(&job.destination_path)
        .bind(&job.file_operation)
        .bind(job.status.as_str())
        .bind(job.priority)
        .bind(job.progress_percent)
        .bind(&job.progress_message)
        .bind(job.current_phase.as_str())
        .bind(vec_to_json(&job.found_urls))
        .bind(vec_to_json(&job.downloaded_files))
        .bind(vec_to_json(&job.final_paths))
        .bind(&job.error_message)
        .bind(value_to_json(&job.metadata))
        .bind(&job.id)
        .execute(&self.pool)
        .await
        .context("failed updating job")?;

        Ok(())
    }

    pub async fn get_job(&self, job_id: &str) -> Result<Option<Job>> {
        let row = sqlx::query("SELECT * FROM jobs WHERE id = ?")
            .bind(job_id)
            .fetch_optional(&self.pool)
            .await
            .context("failed loading job")?;

        row.map(row_to_job).transpose()
    }

    pub async fn list_jobs(
        &self,
        status: Option<JobStatus>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Job>> {
        let rows = if let Some(status) = status {
            sqlx::query(
                "SELECT * FROM jobs WHERE status = ? ORDER BY priority DESC, created_at ASC LIMIT ? OFFSET ?",
            )
            .bind(status.as_str())
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await
            .context("failed listing jobs by status")?
        } else {
            sqlx::query(
                "SELECT * FROM jobs ORDER BY priority DESC, created_at ASC LIMIT ? OFFSET ?",
            )
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await
            .context("failed listing jobs")?
        };

        rows.into_iter().map(row_to_job).collect()
    }

    pub async fn count_jobs(&self, status: Option<JobStatus>) -> Result<i64> {
        let row = if let Some(status) = status {
            sqlx::query("SELECT COUNT(*) AS count FROM jobs WHERE status = ?")
                .bind(status.as_str())
                .fetch_one(&self.pool)
                .await
                .context("failed counting jobs by status")?
        } else {
            sqlx::query("SELECT COUNT(*) AS count FROM jobs")
                .fetch_one(&self.pool)
                .await
                .context("failed counting jobs")?
        };

        row.try_get::<i64, _>("count")
            .context("missing count column")
    }

    pub async fn list_pending_job_ids(&self, limit: i64) -> Result<Vec<String>> {
        let rows = sqlx::query(
            "SELECT id FROM jobs WHERE status = 'pending' ORDER BY priority DESC, created_at ASC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .context("failed listing pending jobs")?;

        rows.into_iter()
            .map(|row| row.try_get::<String, _>("id").context("missing job id"))
            .collect()
    }

    pub async fn append_log(
        &self,
        job_id: &str,
        level: &str,
        source: &str,
        message: &str,
    ) -> Result<JobLogEntry> {
        let timestamp = Utc::now();
        let result = sqlx::query(
            "INSERT INTO job_logs (job_id, timestamp, level, source, message) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(job_id)
        .bind(timestamp.to_rfc3339())
        .bind(level)
        .bind(source)
        .bind(message)
        .execute(&self.pool)
        .await
        .context("failed inserting log")?;

        let id = result.last_insert_rowid();
        Ok(JobLogEntry {
            id,
            job_id: job_id.to_string(),
            timestamp,
            level: level.to_string(),
            source: source.to_string(),
            message: message.to_string(),
        })
    }

    pub async fn list_logs(&self, job_id: &str, limit: i64) -> Result<Vec<JobLogEntry>> {
        let rows = sqlx::query(
            "SELECT id, job_id, timestamp, level, source, message FROM job_logs WHERE job_id = ? ORDER BY timestamp ASC LIMIT ?",
        )
        .bind(job_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .context("failed listing logs")?;

        rows.into_iter().map(row_to_log).collect()
    }

    pub async fn list_recent_logs(
        &self,
        limit: i64,
        level: Option<&str>,
        search: Option<&str>,
    ) -> Result<Vec<JobLogEntry>> {
        let mut query = String::from(
            "SELECT id, job_id, timestamp, level, source, message FROM job_logs WHERE 1=1",
        );
        let mut binds: Vec<String> = Vec::new();

        if let Some(level) = level {
            query.push_str(" AND level = ?");
            binds.push(level.to_ascii_uppercase());
        }
        if let Some(search) = search {
            query.push_str(" AND lower(message) LIKE ?");
            binds.push(format!("%{}%", search.to_ascii_lowercase()));
        }

        query.push_str(" ORDER BY timestamp DESC LIMIT ?");

        let mut q = sqlx::query(&query);
        for bind in binds {
            q = q.bind(bind);
        }
        q = q.bind(limit.max(1));

        let rows = q
            .fetch_all(&self.pool)
            .await
            .context("failed listing recent logs")?;

        let mut logs = rows
            .into_iter()
            .map(row_to_log)
            .collect::<Result<Vec<_>>>()?;
        logs.reverse();
        Ok(logs)
    }

    pub async fn append_step(
        &self,
        job_id: &str,
        step_number: i64,
        action: &str,
        observation: &str,
        url: &str,
        is_error: bool,
        notes: &[String],
    ) -> Result<JobStepEntry> {
        let timestamp = Utc::now();
        let result = sqlx::query(
            "INSERT INTO job_steps (job_id, step_number, action, observation, url, is_error, notes_json, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(job_id)
        .bind(step_number)
        .bind(action)
        .bind(observation)
        .bind(url)
        .bind(if is_error { 1 } else { 0 })
        .bind(vec_to_json(notes))
        .bind(timestamp.to_rfc3339())
        .execute(&self.pool)
        .await
        .context("failed inserting step")?;

        let id = result.last_insert_rowid();
        Ok(JobStepEntry {
            id,
            job_id: job_id.to_string(),
            step_number,
            action: action.to_string(),
            observation: observation.to_string(),
            url: url.to_string(),
            is_error,
            notes: notes.to_vec(),
            timestamp,
        })
    }

    pub async fn list_steps(&self, job_id: &str) -> Result<Vec<JobStepEntry>> {
        let rows = sqlx::query(
            "SELECT id, job_id, step_number, action, observation, url, is_error, notes_json, timestamp FROM job_steps WHERE job_id = ? ORDER BY step_number ASC, id ASC",
        )
        .bind(job_id)
        .fetch_all(&self.pool)
        .await
        .context("failed listing steps")?;

        rows.into_iter().map(row_to_step).collect()
    }

    pub async fn append_screenshot(
        &self,
        job_id: &str,
        screenshot_data: &[u8],
        url: &str,
        phase: &str,
        step_number: Option<i64>,
    ) -> Result<JobScreenshotEntry> {
        let timestamp = Utc::now();
        let result = sqlx::query(
            "INSERT INTO job_screenshots (job_id, timestamp, screenshot_data, url, phase, step_number) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(job_id)
        .bind(timestamp.to_rfc3339())
        .bind(screenshot_data)
        .bind(url)
        .bind(phase)
        .bind(step_number)
        .execute(&self.pool)
        .await
        .context("failed inserting screenshot")?;

        Ok(JobScreenshotEntry {
            id: result.last_insert_rowid(),
            job_id: job_id.to_string(),
            timestamp,
            screenshot_data: screenshot_data.to_vec(),
            url: url.to_string(),
            phase: phase.to_string(),
            step_number,
        })
    }

    pub async fn list_screenshots(&self, job_id: &str) -> Result<Vec<JobScreenshotEntry>> {
        let rows = sqlx::query(
            "SELECT id, job_id, timestamp, screenshot_data, url, phase, step_number FROM job_screenshots WHERE job_id = ? ORDER BY timestamp ASC",
        )
        .bind(job_id)
        .fetch_all(&self.pool)
        .await
        .context("failed listing screenshots")?;

        rows.into_iter().map(row_to_screenshot).collect()
    }

    pub async fn latest_screenshot(&self, job_id: &str) -> Result<Option<JobScreenshotEntry>> {
        let row = sqlx::query(
            "SELECT id, job_id, timestamp, screenshot_data, url, phase, step_number FROM job_screenshots WHERE job_id = ? ORDER BY timestamp DESC LIMIT 1",
        )
        .bind(job_id)
        .fetch_optional(&self.pool)
        .await
        .context("failed loading latest screenshot")?;

        row.map(row_to_screenshot).transpose()
    }

    pub async fn add_note(
        &self,
        domain: &str,
        note_type: &str,
        content: &str,
        label: Option<&str>,
        url_pattern: Option<&str>,
        success: Option<bool>,
    ) -> Result<NoteEntry> {
        let timestamp = Utc::now();
        let result = sqlx::query(
            "INSERT INTO notes (domain, note_type, content, label, url_pattern, success, use_count, created_at) VALUES (?, ?, ?, ?, ?, ?, 0, ?)",
        )
        .bind(domain)
        .bind(note_type)
        .bind(content)
        .bind(label)
        .bind(url_pattern)
        .bind(success.map(|v| if v { 1 } else { 0 }))
        .bind(timestamp.to_rfc3339())
        .execute(&self.pool)
        .await
        .context("failed inserting note")?;

        Ok(NoteEntry {
            id: result.last_insert_rowid(),
            domain: domain.to_string(),
            note_type: note_type.to_string(),
            content: content.to_string(),
            label: label.map(str::to_string),
            url_pattern: url_pattern.map(str::to_string),
            success,
            use_count: 0,
            created_at: timestamp,
        })
    }

    pub async fn list_notes(&self) -> Result<Vec<NoteEntry>> {
        let rows = sqlx::query(
            "SELECT id, domain, note_type, content, label, url_pattern, success, use_count, created_at FROM notes ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await
        .context("failed listing notes")?;

        rows.into_iter().map(row_to_note).collect()
    }

    pub async fn list_notes_for_domain(&self, domain: &str) -> Result<Vec<NoteEntry>> {
        let rows = sqlx::query(
            "SELECT id, domain, note_type, content, label, url_pattern, success, use_count, created_at FROM notes WHERE domain = ? ORDER BY created_at DESC",
        )
        .bind(domain)
        .fetch_all(&self.pool)
        .await
        .context("failed listing notes for domain")?;

        rows.into_iter().map(row_to_note).collect()
    }

    pub async fn list_note_domains(&self) -> Result<Vec<String>> {
        let rows = sqlx::query("SELECT DISTINCT domain FROM notes ORDER BY domain ASC")
            .fetch_all(&self.pool)
            .await
            .context("failed listing note domains")?;

        rows.into_iter()
            .map(|r| r.try_get::<String, _>("domain").context("missing domain"))
            .collect()
    }

    pub async fn note_stats(&self) -> Result<NoteStats> {
        let total = sqlx::query("SELECT COUNT(*) AS count FROM notes")
            .fetch_one(&self.pool)
            .await
            .context("failed counting notes")?
            .try_get::<i64, _>("count")
            .context("missing note count")?;

        let domains = sqlx::query("SELECT COUNT(DISTINCT domain) AS count FROM notes")
            .fetch_one(&self.pool)
            .await
            .context("failed counting note domains")?
            .try_get::<i64, _>("count")
            .context("missing domain count")?;

        let successful = sqlx::query("SELECT COUNT(*) AS count FROM notes WHERE success = 1")
            .fetch_one(&self.pool)
            .await
            .context("failed counting successful notes")?
            .try_get::<i64, _>("count")
            .context("missing successful count")?;

        let rows = sqlx::query("SELECT note_type, COUNT(*) AS count FROM notes GROUP BY note_type")
            .fetch_all(&self.pool)
            .await
            .context("failed grouping note types")?;

        let mut by_type = BTreeMap::new();
        for row in rows {
            by_type.insert(
                row.try_get::<String, _>("note_type")?,
                row.try_get::<i64, _>("count")?,
            );
        }

        Ok(NoteStats {
            total_notes: total,
            domains,
            successful,
            by_type,
        })
    }

    pub async fn list_credential_names(&self) -> Result<Vec<String>> {
        let rows = sqlx::query("SELECT name FROM credentials ORDER BY name ASC")
            .fetch_all(&self.pool)
            .await
            .context("failed listing credentials")?;

        rows.into_iter()
            .map(|row| {
                row.try_get::<String, _>("name")
                    .context("missing credential name")
            })
            .collect()
    }

    pub async fn get_credential(&self, name: &str) -> Result<Option<CredentialEntry>> {
        let row = sqlx::query(
            "SELECT name, username, password, metadata_json, created_at, updated_at FROM credentials WHERE name = ?",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .context("failed loading credential")?;

        row.map(row_to_credential).transpose()
    }

    pub async fn upsert_credential(
        &self,
        name: &str,
        username: &str,
        password: &str,
        metadata: &Value,
    ) -> Result<CredentialEntry> {
        let now = Utc::now().to_rfc3339();
        let metadata_json = value_to_json(metadata);

        sqlx::query(
            r#"
            INSERT INTO credentials (name, username, password, metadata_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
                username = excluded.username,
                password = excluded.password,
                metadata_json = excluded.metadata_json,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(name)
        .bind(username)
        .bind(password)
        .bind(metadata_json)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await
        .context("failed upserting credential")?;

        let row = sqlx::query(
            "SELECT name, username, password, metadata_json, created_at, updated_at FROM credentials WHERE name = ?",
        )
        .bind(name)
        .fetch_one(&self.pool)
        .await
        .context("failed loading upserted credential")?;

        row_to_credential(row)
    }

    pub async fn delete_credential(&self, name: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM credentials WHERE name = ?")
            .bind(name)
            .execute(&self.pool)
            .await
            .context("failed deleting credential")?;
        Ok(result.rows_affected() > 0)
    }
}

fn row_to_job(row: sqlx::sqlite::SqliteRow) -> Result<Job> {
    let created_at = parse_timestamp(row.try_get::<String, _>("created_at")?)?;
    let updated_at = parse_timestamp(row.try_get::<String, _>("updated_at")?)?;
    let status =
        JobStatus::from_str(&row.try_get::<String, _>("status")?).unwrap_or(JobStatus::Pending);
    let phase =
        JobPhase::from_str(&row.try_get::<String, _>("current_phase")?).unwrap_or(JobPhase::Init);

    Ok(Job {
        id: row.try_get("id")?,
        created_at,
        updated_at,
        prompt: row.try_get("prompt")?,
        source_url: row.try_get("source_url")?,
        credential_name: row.try_get::<Option<String>, _>("credential_name")?,
        file_filter: json_to_vec(&row.try_get::<String, _>("file_filter_json")?),
        destination_path: row.try_get("destination_path")?,
        file_operation: row.try_get("file_operation")?,
        priority: row.try_get("priority")?,
        status,
        current_phase: phase,
        progress_percent: row.try_get("progress_percent")?,
        progress_message: row.try_get("progress_message")?,
        found_urls: json_to_vec(&row.try_get::<String, _>("found_urls_json")?),
        downloaded_files: json_to_vec(&row.try_get::<String, _>("downloaded_files_json")?),
        final_paths: json_to_vec(&row.try_get::<String, _>("final_paths_json")?),
        error_message: row.try_get("error_message")?,
        metadata: json_to_value(&row.try_get::<String, _>("metadata_json")?),
    })
}

fn row_to_log(row: sqlx::sqlite::SqliteRow) -> Result<JobLogEntry> {
    Ok(JobLogEntry {
        id: row.try_get("id")?,
        job_id: row.try_get("job_id")?,
        timestamp: parse_timestamp(row.try_get::<String, _>("timestamp")?)?,
        level: row.try_get("level")?,
        source: row.try_get("source")?,
        message: row.try_get("message")?,
    })
}

fn row_to_step(row: sqlx::sqlite::SqliteRow) -> Result<JobStepEntry> {
    Ok(JobStepEntry {
        id: row.try_get("id")?,
        job_id: row.try_get("job_id")?,
        step_number: row.try_get("step_number")?,
        action: row.try_get("action")?,
        observation: row.try_get("observation")?,
        url: row.try_get("url")?,
        is_error: row.try_get::<i64, _>("is_error")? != 0,
        notes: json_to_vec(&row.try_get::<String, _>("notes_json")?),
        timestamp: parse_timestamp(row.try_get::<String, _>("timestamp")?)?,
    })
}

fn row_to_screenshot(row: sqlx::sqlite::SqliteRow) -> Result<JobScreenshotEntry> {
    Ok(JobScreenshotEntry {
        id: row.try_get("id")?,
        job_id: row.try_get("job_id")?,
        timestamp: parse_timestamp(row.try_get::<String, _>("timestamp")?)?,
        screenshot_data: row.try_get("screenshot_data")?,
        url: row.try_get("url")?,
        phase: row.try_get("phase")?,
        step_number: row.try_get::<Option<i64>, _>("step_number")?,
    })
}

fn row_to_note(row: sqlx::sqlite::SqliteRow) -> Result<NoteEntry> {
    Ok(NoteEntry {
        id: row.try_get("id")?,
        domain: row.try_get("domain")?,
        note_type: row.try_get("note_type")?,
        content: row.try_get("content")?,
        label: row.try_get::<Option<String>, _>("label")?,
        url_pattern: row.try_get::<Option<String>, _>("url_pattern")?,
        success: row.try_get::<Option<i64>, _>("success")?.map(|v| v != 0),
        use_count: row.try_get("use_count")?,
        created_at: parse_timestamp(row.try_get::<String, _>("created_at")?)?,
    })
}

fn row_to_credential(row: sqlx::sqlite::SqliteRow) -> Result<CredentialEntry> {
    Ok(CredentialEntry {
        name: row.try_get("name")?,
        username: row.try_get("username")?,
        password: row.try_get("password")?,
        metadata: json_to_value(&row.try_get::<String, _>("metadata_json")?),
        created_at: parse_timestamp(row.try_get::<String, _>("created_at")?)?,
        updated_at: parse_timestamp(row.try_get::<String, _>("updated_at")?)?,
    })
}

fn parse_timestamp(s: String) -> Result<DateTime<Utc>> {
    let dt = DateTime::parse_from_rfc3339(&s)
        .with_context(|| format!("invalid timestamp {s}"))?
        .with_timezone(&Utc);
    Ok(dt)
}

fn vec_to_json(values: &[String]) -> String {
    serde_json::to_string(values).unwrap_or_else(|_| "[]".to_string())
}

fn json_to_vec(raw: &str) -> Vec<String> {
    serde_json::from_str(raw).unwrap_or_default()
}

fn value_to_json(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "{}".to_string())
}

fn json_to_value(raw: &str) -> Value {
    serde_json::from_str(raw).unwrap_or_else(|_| Value::Object(Default::default()))
}
