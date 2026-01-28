"""SQLite database layer for job storage."""

import aiosqlite
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .models import Job, JobLog, JobScreenshot, JobStatus, JobStep


class JobDatabase:
    """SQLite database for job persistence."""

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS jobs (
        id TEXT PRIMARY KEY,
        created_at TIMESTAMP NOT NULL,
        updated_at TIMESTAMP NOT NULL,
        prompt TEXT NOT NULL,
        source_url TEXT,
        credential_name TEXT,
        file_filter TEXT,
        destination_path TEXT,
        file_operation TEXT DEFAULT 'copy',
        status TEXT DEFAULT 'pending',
        priority INTEGER DEFAULT 0,
        progress_percent REAL DEFAULT 0.0,
        progress_message TEXT,
        current_phase TEXT DEFAULT 'init',
        found_urls TEXT,
        downloaded_files TEXT,
        final_paths TEXT,
        error_message TEXT,
        metadata TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
    CREATE INDEX IF NOT EXISTS idx_jobs_priority ON jobs(priority DESC, created_at ASC);
    CREATE INDEX IF NOT EXISTS idx_jobs_created_at ON jobs(created_at);

    CREATE TABLE IF NOT EXISTS job_screenshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id TEXT NOT NULL,
        timestamp TIMESTAMP NOT NULL,
        screenshot_data BLOB NOT NULL,
        url TEXT,
        phase TEXT,
        FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_screenshots_job_id ON job_screenshots(job_id);
    CREATE INDEX IF NOT EXISTS idx_screenshots_timestamp ON job_screenshots(timestamp);

    CREATE TABLE IF NOT EXISTS job_steps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id TEXT NOT NULL,
        step_number INTEGER NOT NULL,
        action TEXT NOT NULL,
        observation TEXT,
        url TEXT,
        is_error BOOLEAN DEFAULT 0,
        timestamp TIMESTAMP NOT NULL,
        FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_steps_job_id ON job_steps(job_id);
    CREATE INDEX IF NOT EXISTS idx_steps_step_number ON job_steps(job_id, step_number);

    CREATE TABLE IF NOT EXISTS job_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id TEXT NOT NULL,
        timestamp TIMESTAMP NOT NULL,
        level TEXT NOT NULL,
        source TEXT,
        message TEXT NOT NULL,
        FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_logs_job_id ON job_logs(job_id);
    CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON job_logs(job_id, timestamp);
    """

    def __init__(self, db_path: str | Path):
        """Initialize database with path."""
        self.db_path = Path(db_path)
        self._connection: aiosqlite.Connection | None = None

    async def connect(self) -> None:
        """Connect to database and initialize schema."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = await aiosqlite.connect(self.db_path)
        self._connection.row_factory = aiosqlite.Row
        await self._connection.executescript(self.SCHEMA)
        await self._connection.commit()

    async def close(self) -> None:
        """Close database connection."""
        if self._connection:
            await self._connection.close()
            self._connection = None

    async def _get_conn(self) -> aiosqlite.Connection:
        """Get connection, connecting if needed."""
        if not self._connection:
            await self.connect()
        return self._connection  # type: ignore

    async def create_job(self, job: Job) -> Job:
        """Insert a new job into the database."""
        conn = await self._get_conn()
        data = job.to_dict()
        columns = ", ".join(data.keys())
        placeholders = ", ".join("?" for _ in data)
        await conn.execute(
            f"INSERT INTO jobs ({columns}) VALUES ({placeholders})",
            list(data.values()),
        )
        await conn.commit()
        return job

    async def get_job(self, job_id: str) -> Job | None:
        """Get a job by ID."""
        conn = await self._get_conn()
        async with conn.execute(
            "SELECT * FROM jobs WHERE id = ?", (job_id,)
        ) as cursor:
            row = await cursor.fetchone()
            if row:
                return Job.from_dict(dict(row))
        return None

    async def update_job(self, job: Job) -> None:
        """Update an existing job."""
        conn = await self._get_conn()
        job.updated_at = datetime.utcnow()
        data = job.to_dict()
        del data["id"]
        set_clause = ", ".join(f"{k} = ?" for k in data.keys())
        await conn.execute(
            f"UPDATE jobs SET {set_clause} WHERE id = ?",
            [*data.values(), job.id],
        )
        await conn.commit()

    async def delete_job(self, job_id: str) -> bool:
        """Delete a job and its screenshots."""
        conn = await self._get_conn()
        cursor = await conn.execute("DELETE FROM jobs WHERE id = ?", (job_id,))
        await conn.commit()
        return cursor.rowcount > 0

    async def list_jobs(
        self,
        status: JobStatus | None = None,
        limit: int = 100,
        offset: int = 0,
        order_by: str = "created_at",
        descending: bool = True,
    ) -> list[Job]:
        """List jobs with optional filtering."""
        conn = await self._get_conn()
        query = "SELECT * FROM jobs"
        params: list[Any] = []

        if status:
            query += " WHERE status = ?"
            params.append(status.value)

        direction = "DESC" if descending else "ASC"
        query += f" ORDER BY {order_by} {direction} LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        async with conn.execute(query, params) as cursor:
            rows = await cursor.fetchall()
            return [Job.from_dict(dict(row)) for row in rows]

    async def get_pending_jobs(self) -> list[Job]:
        """Get all pending jobs ordered by priority and creation time."""
        conn = await self._get_conn()
        async with conn.execute(
            "SELECT * FROM jobs WHERE status = ? ORDER BY priority DESC, created_at ASC",
            (JobStatus.PENDING.value,),
        ) as cursor:
            rows = await cursor.fetchall()
            return [Job.from_dict(dict(row)) for row in rows]

    async def count_jobs(self, status: JobStatus | None = None) -> int:
        """Count jobs, optionally filtered by status."""
        conn = await self._get_conn()
        if status:
            query = "SELECT COUNT(*) FROM jobs WHERE status = ?"
            params = (status.value,)
        else:
            query = "SELECT COUNT(*) FROM jobs"
            params = ()
        async with conn.execute(query, params) as cursor:
            row = await cursor.fetchone()
            return row[0] if row else 0

    async def get_running_jobs(self) -> list[Job]:
        """Get all currently running jobs."""
        conn = await self._get_conn()
        running_statuses = [
            JobStatus.RUNNING.value,
            JobStatus.BROWSING.value,
            JobStatus.DOWNLOADING.value,
            JobStatus.EXTRACTING.value,
            JobStatus.COPYING.value,
        ]
        placeholders = ",".join("?" for _ in running_statuses)
        async with conn.execute(
            f"SELECT * FROM jobs WHERE status IN ({placeholders})",
            running_statuses,
        ) as cursor:
            rows = await cursor.fetchall()
            return [Job.from_dict(dict(row)) for row in rows]

    # Screenshot operations

    async def add_screenshot(self, screenshot: JobScreenshot) -> int:
        """Add a screenshot for a job."""
        conn = await self._get_conn()
        data = screenshot.to_dict()
        cursor = await conn.execute(
            """INSERT INTO job_screenshots (job_id, timestamp, screenshot_data, url, phase)
               VALUES (?, ?, ?, ?, ?)""",
            (data["job_id"], data["timestamp"], data["screenshot_data"], data["url"], data["phase"]),
        )
        await conn.commit()
        return cursor.lastrowid or 0

    async def get_screenshots(self, job_id: str) -> list[JobScreenshot]:
        """Get all screenshots for a job."""
        conn = await self._get_conn()
        async with conn.execute(
            "SELECT * FROM job_screenshots WHERE job_id = ? ORDER BY timestamp ASC",
            (job_id,),
        ) as cursor:
            rows = await cursor.fetchall()
            return [JobScreenshot.from_dict(dict(row)) for row in rows]

    async def get_latest_screenshot(self, job_id: str) -> JobScreenshot | None:
        """Get the most recent screenshot for a job."""
        conn = await self._get_conn()
        async with conn.execute(
            "SELECT * FROM job_screenshots WHERE job_id = ? ORDER BY timestamp DESC LIMIT 1",
            (job_id,),
        ) as cursor:
            row = await cursor.fetchone()
            if row:
                return JobScreenshot.from_dict(dict(row))
        return None

    async def cleanup_old_screenshots(self, max_age_hours: int = 24) -> int:
        """Delete screenshots older than the specified age."""
        conn = await self._get_conn()
        cutoff = datetime.utcnow() - timedelta(hours=max_age_hours)
        cursor = await conn.execute(
            "DELETE FROM job_screenshots WHERE timestamp < ?",
            (cutoff.isoformat(),),
        )
        await conn.commit()
        return cursor.rowcount

    async def cleanup_completed_jobs(self, max_age_hours: int = 168) -> int:
        """Delete completed/failed/cancelled jobs older than specified age."""
        conn = await self._get_conn()
        cutoff = datetime.utcnow() - timedelta(hours=max_age_hours)
        terminal_statuses = [
            JobStatus.COMPLETE.value,
            JobStatus.FAILED.value,
            JobStatus.CANCELLED.value,
        ]
        placeholders = ",".join("?" for _ in terminal_statuses)
        cursor = await conn.execute(
            f"DELETE FROM jobs WHERE status IN ({placeholders}) AND updated_at < ?",
            [*terminal_statuses, cutoff.isoformat()],
        )
        await conn.commit()
        return cursor.rowcount

    # Step operations

    async def add_step(self, step: JobStep) -> int:
        """Add a navigation step for a job."""
        conn = await self._get_conn()
        data = step.to_dict()
        cursor = await conn.execute(
            """INSERT INTO job_steps (job_id, step_number, action, observation, url, is_error, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (data["job_id"], data["step_number"], data["action"], data["observation"],
             data["url"], data["is_error"], data["timestamp"]),
        )
        await conn.commit()
        return cursor.lastrowid or 0

    async def add_steps(self, steps: list[JobStep]) -> None:
        """Add multiple navigation steps for a job."""
        if not steps:
            return
        conn = await self._get_conn()
        for step in steps:
            data = step.to_dict()
            await conn.execute(
                """INSERT INTO job_steps (job_id, step_number, action, observation, url, is_error, timestamp)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (data["job_id"], data["step_number"], data["action"], data["observation"],
                 data["url"], data["is_error"], data["timestamp"]),
            )
        await conn.commit()

    async def get_steps(self, job_id: str) -> list[JobStep]:
        """Get all navigation steps for a job."""
        conn = await self._get_conn()
        async with conn.execute(
            "SELECT * FROM job_steps WHERE job_id = ? ORDER BY step_number ASC",
            (job_id,),
        ) as cursor:
            rows = await cursor.fetchall()
            return [JobStep.from_dict(dict(row)) for row in rows]

    async def clear_steps(self, job_id: str) -> None:
        """Clear all steps for a job (useful when re-running)."""
        conn = await self._get_conn()
        await conn.execute("DELETE FROM job_steps WHERE job_id = ?", (job_id,))
        await conn.commit()

    # Log operations

    async def add_log(self, log: JobLog) -> int:
        """Add a log entry for a job."""
        conn = await self._get_conn()
        data = log.to_dict()
        cursor = await conn.execute(
            """INSERT INTO job_logs (job_id, timestamp, level, source, message)
               VALUES (?, ?, ?, ?, ?)""",
            (data["job_id"], data["timestamp"], data["level"], data["source"], data["message"]),
        )
        await conn.commit()
        return cursor.lastrowid or 0

    async def get_logs(self, job_id: str, limit: int = 500) -> list[JobLog]:
        """Get logs for a job."""
        conn = await self._get_conn()
        async with conn.execute(
            "SELECT * FROM job_logs WHERE job_id = ? ORDER BY timestamp ASC LIMIT ?",
            (job_id, limit),
        ) as cursor:
            rows = await cursor.fetchall()
            return [JobLog.from_dict(dict(row)) for row in rows]

    async def clear_logs(self, job_id: str) -> None:
        """Clear all logs for a job."""
        conn = await self._get_conn()
        await conn.execute("DELETE FROM job_logs WHERE job_id = ?", (job_id,))
        await conn.commit()
