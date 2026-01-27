"""Job queue manager for coordinating job execution."""

import asyncio
from datetime import datetime
from typing import Any, Callable

from .database import JobDatabase
from .models import Job, JobCreateRequest, JobPhase, JobScreenshot, JobStatus


class JobQueue:
    """Manages the job queue and coordinates execution."""

    def __init__(
        self,
        db: JobDatabase,
        max_concurrent: int = 1,
        on_job_update: Callable[[Job], Any] | None = None,
        on_screenshot: Callable[[JobScreenshot], Any] | None = None,
    ):
        """Initialize queue manager.

        Args:
            db: Job database instance
            max_concurrent: Maximum concurrent jobs (default 1 for predictability)
            on_job_update: Callback when job state changes
            on_screenshot: Callback when screenshot is added
        """
        self.db = db
        self.max_concurrent = max_concurrent
        self._on_job_update = on_job_update
        self._on_screenshot = on_screenshot
        self._running_jobs: dict[str, asyncio.Task[None]] = {}
        self._job_events: dict[str, asyncio.Event] = {}
        self._shutdown = False
        self._lock = asyncio.Lock()

    async def submit(
        self,
        prompt: str,
        source_url: str = "",
        credential_name: str | None = None,
        file_filter: list[str] | None = None,
        destination_path: str = "",
        file_operation: str = "copy",
        priority: int = 0,
        metadata: dict[str, Any] | None = None,
    ) -> Job:
        """Submit a new job to the queue.

        Returns:
            The created job
        """
        from .models import FileOperation

        job = Job(
            prompt=prompt,
            source_url=source_url,
            credential_name=credential_name,
            file_filter=file_filter or [],
            destination_path=destination_path,
            file_operation=FileOperation(file_operation),
            priority=priority,
            metadata=metadata or {},
        )

        await self.db.create_job(job)
        await self._notify_update(job)
        return job

    async def submit_request(self, request: JobCreateRequest) -> Job:
        """Submit a job from a request object."""
        return await self.submit(
            prompt=request.prompt,
            source_url=request.source_url,
            credential_name=request.credential_name,
            file_filter=request.file_filter,
            destination_path=request.destination_path,
            file_operation=request.file_operation,
            priority=request.priority,
            metadata=request.metadata,
        )

    async def get_job(self, job_id: str) -> Job | None:
        """Get a job by ID."""
        return await self.db.get_job(job_id)

    async def list_jobs(
        self,
        status: JobStatus | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Job]:
        """List jobs with optional status filter."""
        return await self.db.list_jobs(status=status, limit=limit, offset=offset)

    async def cancel_job(self, job_id: str) -> bool:
        """Cancel a pending or running job.

        Returns:
            True if job was cancelled, False if not found or already terminal
        """
        job = await self.db.get_job(job_id)
        if not job:
            return False

        # Can only cancel non-terminal jobs
        if job.status in (JobStatus.COMPLETE, JobStatus.FAILED, JobStatus.CANCELLED):
            return False

        # If running, signal cancellation
        if job_id in self._running_jobs:
            task = self._running_jobs[job_id]
            task.cancel()

        job.set_status(JobStatus.CANCELLED)
        await self.db.update_job(job)
        await self._notify_update(job)
        return True

    async def update_progress(
        self,
        job_id: str,
        percent: float,
        message: str = "",
        phase: JobPhase | None = None,
        status: JobStatus | None = None,
    ) -> None:
        """Update job progress."""
        job = await self.db.get_job(job_id)
        if not job:
            return

        job.update_progress(percent, message)
        if phase:
            job.set_phase(phase)
        if status:
            job.set_status(status)

        await self.db.update_job(job)
        await self._notify_update(job)

    async def add_screenshot(
        self,
        job_id: str,
        screenshot_data: bytes,
        url: str = "",
        phase: str = "",
    ) -> None:
        """Add a screenshot for a job."""
        screenshot = JobScreenshot(
            job_id=job_id,
            screenshot_data=screenshot_data,
            url=url,
            phase=phase,
        )
        await self.db.add_screenshot(screenshot)
        if self._on_screenshot:
            await self._maybe_await(self._on_screenshot(screenshot))

    async def get_screenshots(self, job_id: str) -> list[JobScreenshot]:
        """Get all screenshots for a job."""
        return await self.db.get_screenshots(job_id)

    async def get_next_job(self) -> Job | None:
        """Get the next pending job to execute."""
        async with self._lock:
            if len(self._running_jobs) >= self.max_concurrent:
                return None

            pending = await self.db.get_pending_jobs()
            for job in pending:
                if job.id not in self._running_jobs:
                    return job
        return None

    def is_running(self, job_id: str) -> bool:
        """Check if a job is currently running."""
        return job_id in self._running_jobs

    def running_count(self) -> int:
        """Get count of currently running jobs."""
        return len(self._running_jobs)

    async def mark_running(self, job_id: str, task: asyncio.Task[None]) -> None:
        """Mark a job as running with its task."""
        async with self._lock:
            self._running_jobs[job_id] = task
            self._job_events[job_id] = asyncio.Event()

    async def mark_complete(self, job_id: str) -> None:
        """Mark a job as no longer running."""
        async with self._lock:
            self._running_jobs.pop(job_id, None)
            event = self._job_events.pop(job_id, None)
            if event:
                event.set()

    async def wait_for_job(self, job_id: str, timeout: float | None = None) -> Job | None:
        """Wait for a job to complete.

        Args:
            job_id: Job ID to wait for
            timeout: Optional timeout in seconds

        Returns:
            The completed job, or None if timeout/not found
        """
        event = self._job_events.get(job_id)
        if event:
            try:
                await asyncio.wait_for(event.wait(), timeout)
            except asyncio.TimeoutError:
                pass
        return await self.db.get_job(job_id)

    async def cleanup(self, screenshot_max_age_hours: int = 24, job_max_age_hours: int = 168) -> None:
        """Clean up old screenshots and completed jobs."""
        await self.db.cleanup_old_screenshots(screenshot_max_age_hours)
        await self.db.cleanup_completed_jobs(job_max_age_hours)

    async def shutdown(self) -> None:
        """Shutdown the queue and cancel running jobs."""
        self._shutdown = True
        async with self._lock:
            for job_id, task in list(self._running_jobs.items()):
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
            self._running_jobs.clear()

    async def _notify_update(self, job: Job) -> None:
        """Notify listeners of job update."""
        if self._on_job_update:
            await self._maybe_await(self._on_job_update(job))

    @staticmethod
    async def _maybe_await(result: Any) -> Any:
        """Await result if it's a coroutine."""
        if asyncio.iscoroutine(result):
            return await result
        return result
