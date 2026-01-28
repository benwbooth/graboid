"""Job models and status enums for the job queue system."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
import json
import uuid


class JobStatus(str, Enum):
    """Job status values."""

    PENDING = "pending"
    RUNNING = "running"
    BROWSING = "browsing"
    DOWNLOADING = "downloading"
    EXTRACTING = "extracting"
    COPYING = "copying"
    COMPLETE = "complete"
    FAILED = "failed"
    CANCELLED = "cancelled"


class JobPhase(str, Enum):
    """Job execution phases."""

    INIT = "init"
    BROWSE = "browse"
    DOWNLOAD = "download"
    EXTRACT = "extract"
    COPY = "copy"
    DONE = "done"


class FileOperation(str, Enum):
    """File operation types."""

    COPY = "copy"
    HARDLINK = "hardlink"
    SYMLINK = "symlink"
    REFLINK = "reflink"
    PATH_ONLY = "path_only"


@dataclass
class Job:
    """Represents a download job in the queue."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    # Input parameters
    prompt: str = ""
    source_url: str = ""
    credential_name: str | None = None
    file_filter: list[str] = field(default_factory=list)
    destination_path: str = ""
    file_operation: FileOperation = FileOperation.COPY

    # Queue management
    status: JobStatus = JobStatus.PENDING
    priority: int = 0

    # Progress tracking
    progress_percent: float = 0.0
    progress_message: str = ""
    current_phase: JobPhase = JobPhase.INIT

    # Results
    found_urls: list[str] = field(default_factory=list)
    downloaded_files: list[str] = field(default_factory=list)
    final_paths: list[str] = field(default_factory=list)
    error_message: str = ""

    # Arbitrary metadata
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert job to dictionary for storage."""
        return {
            "id": self.id,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "prompt": self.prompt,
            "source_url": self.source_url,
            "credential_name": self.credential_name,
            "file_filter": json.dumps(self.file_filter),
            "destination_path": self.destination_path,
            "file_operation": self.file_operation.value,
            "status": self.status.value,
            "priority": self.priority,
            "progress_percent": self.progress_percent,
            "progress_message": self.progress_message,
            "current_phase": self.current_phase.value,
            "found_urls": json.dumps(self.found_urls),
            "downloaded_files": json.dumps(self.downloaded_files),
            "final_paths": json.dumps(self.final_paths),
            "error_message": self.error_message,
            "metadata": json.dumps(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Job":
        """Create job from dictionary."""
        return cls(
            id=data["id"],
            created_at=datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"]),
            prompt=data["prompt"],
            source_url=data["source_url"],
            credential_name=data.get("credential_name"),
            file_filter=json.loads(data.get("file_filter", "[]")),
            destination_path=data["destination_path"],
            file_operation=FileOperation(data.get("file_operation", "copy")),
            status=JobStatus(data["status"]),
            priority=data.get("priority", 0),
            progress_percent=data.get("progress_percent", 0.0),
            progress_message=data.get("progress_message", ""),
            current_phase=JobPhase(data.get("current_phase", "init")),
            found_urls=json.loads(data.get("found_urls", "[]")),
            downloaded_files=json.loads(data.get("downloaded_files", "[]")),
            final_paths=json.loads(data.get("final_paths", "[]")),
            error_message=data.get("error_message", ""),
            metadata=json.loads(data.get("metadata", "{}")),
        )

    def update_progress(self, percent: float, message: str = "") -> None:
        """Update job progress."""
        self.progress_percent = percent
        if message:
            self.progress_message = message
        self.updated_at = datetime.utcnow()

    def set_phase(self, phase: JobPhase) -> None:
        """Set the current phase."""
        self.current_phase = phase
        self.updated_at = datetime.utcnow()

    def set_status(self, status: JobStatus) -> None:
        """Set the job status."""
        self.status = status
        self.updated_at = datetime.utcnow()

    def fail(self, error: str) -> None:
        """Mark job as failed with error message."""
        self.status = JobStatus.FAILED
        self.error_message = error
        self.updated_at = datetime.utcnow()


@dataclass
class JobScreenshot:
    """Represents a screenshot taken during job execution."""

    id: int | None = None
    job_id: str = ""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    screenshot_data: bytes = b""
    url: str = ""
    phase: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "job_id": self.job_id,
            "timestamp": self.timestamp.isoformat(),
            "screenshot_data": self.screenshot_data,
            "url": self.url,
            "phase": self.phase,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "JobScreenshot":
        """Create from dictionary."""
        return cls(
            id=data.get("id"),
            job_id=data["job_id"],
            timestamp=datetime.fromisoformat(data["timestamp"])
            if isinstance(data["timestamp"], str)
            else data["timestamp"],
            screenshot_data=data["screenshot_data"],
            url=data.get("url", ""),
            phase=data.get("phase", ""),
        )


@dataclass
class JobStep:
    """Represents a navigation step during job execution."""

    id: int | None = None
    job_id: str = ""
    step_number: int = 0
    action: str = ""
    observation: str = ""
    url: str = ""
    is_error: bool = False
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "job_id": self.job_id,
            "step_number": self.step_number,
            "action": self.action,
            "observation": self.observation,
            "url": self.url,
            "is_error": self.is_error,
            "timestamp": self.timestamp.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "JobStep":
        """Create from dictionary."""
        return cls(
            id=data.get("id"),
            job_id=data["job_id"],
            step_number=data.get("step_number", 0),
            action=data.get("action", ""),
            observation=data.get("observation", ""),
            url=data.get("url", ""),
            is_error=data.get("is_error", False),
            timestamp=datetime.fromisoformat(data["timestamp"])
            if isinstance(data.get("timestamp"), str)
            else data.get("timestamp", datetime.utcnow()),
        )


@dataclass
class JobLog:
    """Represents a log entry for a job."""

    id: int | None = None
    job_id: str = ""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    level: str = "INFO"
    source: str = ""
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "job_id": self.job_id,
            "timestamp": self.timestamp.isoformat(),
            "level": self.level,
            "source": self.source,
            "message": self.message,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "JobLog":
        """Create from dictionary."""
        return cls(
            id=data.get("id"),
            job_id=data["job_id"],
            timestamp=datetime.fromisoformat(data["timestamp"])
            if isinstance(data.get("timestamp"), str)
            else data.get("timestamp", datetime.utcnow()),
            level=data.get("level", "INFO"),
            source=data.get("source", ""),
            message=data.get("message", ""),
        )


@dataclass
class JobCreateRequest:
    """Request to create a new job."""

    prompt: str
    source_url: str = ""
    credential_name: str | None = None
    file_filter: list[str] = field(default_factory=list)
    destination_path: str = ""
    file_operation: str = "copy"
    priority: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class JobListResponse:
    """Response containing a list of jobs."""

    jobs: list[Job]
    total: int
    offset: int
    limit: int
