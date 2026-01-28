"""Job execution runner for processing jobs from the queue."""

import asyncio
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable
from urllib.parse import urlparse

from .models import Job, JobPhase, JobStatus
from .queue import JobQueue

if TYPE_CHECKING:
    from ..orchestrator import Config, Graboid

logger = logging.getLogger(__name__)


class JobLogger:
    """Logger that writes to both standard logging and job-specific storage."""

    def __init__(self, job_id: str, queue: JobQueue):
        self.job_id = job_id
        self.queue = queue
        self._logger = logging.getLogger(f"job.{job_id[:8]}")

    async def log(self, level: str, message: str, source: str = ""):
        """Log a message to both standard logger and job storage."""
        # Log to standard logger
        log_level = getattr(logging, level.upper(), logging.INFO)
        self._logger.log(log_level, message)

        # Log to job storage
        try:
            await self.queue.add_log(self.job_id, message, level, source)
        except Exception as e:
            self._logger.warning(f"Failed to store job log: {e}")

    async def info(self, message: str, source: str = ""):
        await self.log("INFO", message, source)

    async def warning(self, message: str, source: str = ""):
        await self.log("WARNING", message, source)

    async def error(self, message: str, source: str = ""):
        await self.log("ERROR", message, source)

    async def debug(self, message: str, source: str = ""):
        await self.log("DEBUG", message, source)


class JobRunner:
    """Executes jobs from the queue using the Graboid orchestrator."""

    def __init__(
        self,
        queue: JobQueue,
        graboid: "Graboid",
        config: "Config",
        on_screenshot: Callable[[str, bytes, str], Any] | None = None,
    ):
        """Initialize job runner.

        Args:
            queue: Job queue instance
            graboid: Graboid orchestrator instance
            config: Application config
            on_screenshot: Callback for screenshots (job_id, data, url)
        """
        self.queue = queue
        self.graboid = graboid
        self.config = config
        self._on_screenshot = on_screenshot
        self._running = False
        self._worker_task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        """Start the job runner worker."""
        if self._running:
            return
        self._running = True
        self._worker_task = asyncio.create_task(self._worker_loop())
        logger.info("Job runner started")

    async def stop(self) -> None:
        """Stop the job runner."""
        self._running = False
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
        logger.info("Job runner stopped")

    async def _worker_loop(self) -> None:
        """Main worker loop that picks up and executes jobs."""
        while self._running:
            try:
                job = await self.queue.get_next_job()
                if job:
                    task = asyncio.create_task(self._execute_job(job))
                    await self.queue.mark_running(job.id, task)
                    try:
                        await task
                    except asyncio.CancelledError:
                        logger.info(f"Job {job.id} was cancelled")
                    finally:
                        await self.queue.mark_complete(job.id)
                else:
                    await asyncio.sleep(1)
            except Exception as e:
                logger.error(f"Worker loop error: {e}")
                await asyncio.sleep(5)

    async def _execute_job(self, job: Job) -> None:
        """Execute a single job through its phases."""
        # Create job-specific logger
        job_log = JobLogger(job.id, self.queue)

        try:
            await job_log.info(f"Starting job: {job.prompt[:100]}...", "runner")
            await self._update_job(job, JobStatus.RUNNING, JobPhase.INIT, 0, "Initializing job")

            # Phase 1: Browse (if we have a source URL or need to find one)
            if job.source_url or job.prompt:
                await self._phase_browse(job, job_log)

            if job.status == JobStatus.FAILED:
                await job_log.error(f"Job failed in browse phase: {job.error_message}", "runner")
                return

            # Phase 2: Download found URLs
            if job.found_urls:
                await self._phase_download(job, job_log)

            if job.status == JobStatus.FAILED:
                await job_log.error(f"Job failed in download phase: {job.error_message}", "runner")
                return

            # Phase 3: Extract archives if needed
            if job.downloaded_files:
                await self._phase_extract(job, job_log)

            if job.status == JobStatus.FAILED:
                await job_log.error(f"Job failed in extract phase: {job.error_message}", "runner")
                return

            # Phase 4: Copy files to destination
            if job.downloaded_files and job.destination_path:
                await self._phase_copy(job, job_log)

            if job.status == JobStatus.FAILED:
                await job_log.error(f"Job failed in copy phase: {job.error_message}", "runner")
                return

            # Complete
            await job_log.info(f"Job completed successfully", "runner")
            await self._update_job(job, JobStatus.COMPLETE, JobPhase.DONE, 100, "Job complete")

        except asyncio.CancelledError:
            await job_log.warning("Job cancelled", "runner")
            job.set_status(JobStatus.CANCELLED)
            await self.queue.db.update_job(job)
            raise
        except Exception as e:
            await job_log.error(f"Job failed with exception: {e}", "runner")
            logger.error(f"Job {job.id} failed: {e}")
            job.fail(str(e))
            await self.queue.db.update_job(job)

    async def _phase_browse(self, job: Job, job_log: JobLogger) -> None:
        """Browse phase: Use LLM to find download URLs."""
        await job_log.info(f"Starting browse phase for URL: {job.source_url}", "browse")
        await self._update_job(job, JobStatus.BROWSING, JobPhase.BROWSE, 10, "Browsing for download links")

        # If we have a direct source URL and no prompt, treat it as a direct download
        if job.source_url and not job.prompt:
            await job_log.info("Direct URL provided, skipping browser navigation", "browse")
            job.found_urls = [job.source_url]
            await self.queue.db.update_job(job)
            return

        # Build the browse task
        url = job.source_url or "about:blank"
        task = job.prompt or "Find download links for the requested content"

        try:
            # Create screenshot callback that saves to job queue
            async def screenshot_callback(data: bytes, url: str, description: str):
                """Save screenshot to job queue and notify via callback."""
                try:
                    await self.queue.add_screenshot(job.id, data, url, description)
                    if self._on_screenshot:
                        self._on_screenshot(job.id, data, url)
                except Exception as e:
                    logger.warning(f"Failed to save screenshot: {e}")

            # Create log callback to capture Claude's output
            async def log_callback(message: str, level: str = "INFO"):
                await job_log.log(level, message, "claude")

            await job_log.info(f"Starting browser automation with task: {task[:100]}...", "browse")
            result = await self.graboid.browse(url, task, screenshot_callback=screenshot_callback, log_callback=log_callback)

            # Save navigation steps if available
            if hasattr(result, 'steps') and result.steps:
                step_dicts = [
                    {
                        "step_number": step.step_number,
                        "action": step.action,
                        "observation": step.observation,
                        "url": step.url or "",
                        "is_error": step.is_error,
                    }
                    for step in result.steps
                ]
                await self.queue.add_steps(job.id, step_dicts)
                await job_log.info(f"Saved {len(step_dicts)} navigation steps", "browse")

            # Log raw output if available
            if hasattr(result, 'raw_output') and result.raw_output:
                # Split into lines and log each
                for line in result.raw_output.split('\n')[:50]:  # Limit to first 50 lines
                    if line.strip():
                        await job_log.debug(line, "claude_output")

            if result.success and result.found_links:
                job.found_urls = result.found_links
                await job_log.info(f"Found {len(result.found_links)} download links: {result.found_links}", "browse")
                await self._update_job(
                    job, JobStatus.BROWSING, JobPhase.BROWSE, 30,
                    f"Found {len(result.found_links)} download links"
                )
            elif result.error:
                await job_log.error(f"Browse failed: {result.error}", "browse")
                job.fail(f"Browse failed: {result.error}")
            else:
                await job_log.error("No download links found", "browse")
                job.fail("No download links found")

            await self.queue.db.update_job(job)

        except Exception as e:
            await job_log.error(f"Browse exception: {e}", "browse")
            job.fail(f"Browse error: {e}")
            await self.queue.db.update_job(job)

    async def _phase_download(self, job: Job, job_log: JobLogger) -> None:
        """Download phase: Download files from found URLs."""
        await job_log.info(f"Starting download phase for {len(job.found_urls)} URLs", "download")
        await self._update_job(job, JobStatus.DOWNLOADING, JobPhase.DOWNLOAD, 40, "Starting downloads")

        downloaded = []
        total = len(job.found_urls)

        for i, url in enumerate(job.found_urls):
            try:
                progress = 40 + (i / total) * 30
                await job_log.info(f"Downloading {i+1}/{total}: {url}", "download")
                await self._update_job(
                    job, JobStatus.DOWNLOADING, JobPhase.DOWNLOAD, progress,
                    f"Downloading {i+1}/{total}: {url[:50]}..."
                )

                # Check if this is a torrent/magnet
                if url.startswith("magnet:") or url.endswith(".torrent"):
                    await job_log.info(f"Adding torrent: {url}", "download")
                    result = await self.graboid.add_torrent(url)
                    if result.success:
                        # Record a marker so the job shows a download entry
                        downloaded.append(f"torrent:{url}")
                        await job_log.info(f"Torrent queued for download", "download")
                    else:
                        await job_log.warning(
                            f"Torrent add failed for {url}: {result.error}", "download"
                        )
                else:
                    # Regular HTTP download
                    result = await self.graboid.download(url)
                    if result.success:
                        downloaded.extend([str(p) for p in result.downloaded_files])
                        await job_log.info(f"Downloaded: {result.downloaded_files}", "download")
                    elif result.error:
                        await job_log.warning(f"Download failed for {url}: {result.error}", "download")

            except Exception as e:
                await job_log.error(f"Download exception for {url}: {e}", "download")

        job.downloaded_files = downloaded
        await self.queue.db.update_job(job)

        if not downloaded:
            await job_log.error("All downloads failed", "download")
            job.fail("All downloads failed")
            await self.queue.db.update_job(job)
        else:
            await job_log.info(f"Downloaded {len(downloaded)} files", "download")

    async def _phase_extract(self, job: Job, job_log: JobLogger) -> None:
        """Extract phase: Extract archives if needed."""
        await job_log.info(f"Starting extract phase for {len(job.downloaded_files)} files", "extract")
        await self._update_job(job, JobStatus.EXTRACTING, JobPhase.EXTRACT, 75, "Checking for archives")

        # Import archive handler
        try:
            from ..archives import ArchiveHandler
        except ImportError:
            await job_log.debug("Archive handler not available, skipping extraction", "extract")
            return

        extracted = []
        handler = ArchiveHandler()

        for file_path in job.downloaded_files:
            path = Path(file_path)
            if handler.is_archive(path):
                await job_log.info(f"Extracting archive: {path.name}", "extract")
                await self._update_job(
                    job, JobStatus.EXTRACTING, JobPhase.EXTRACT, 80,
                    f"Extracting {path.name}"
                )
                try:
                    extract_dir = path.parent / path.stem
                    result = await handler.extract(path, extract_dir, patterns=job.file_filter or None)
                    extracted.extend([str(p) for p in result])
                    await job_log.info(f"Extracted {len(result)} files from {path.name}", "extract")
                except Exception as e:
                    await job_log.warning(f"Failed to extract {path}: {e}", "extract")
                    extracted.append(file_path)
            else:
                extracted.append(file_path)

        job.downloaded_files = extracted
        await self.queue.db.update_job(job)
        await job_log.info(f"Extract phase complete, {len(extracted)} files ready", "extract")

    async def _phase_copy(self, job: Job, job_log: JobLogger) -> None:
        """Copy phase: Copy files to destination using configured operation."""
        await job_log.info(f"Starting copy phase to {job.destination_path}", "copy")
        await self._update_job(job, JobStatus.COPYING, JobPhase.COPY, 90, "Copying files to destination")

        try:
            from ..files import FileOperations
        except ImportError:
            await job_log.debug("File operations not available, skipping copy", "copy")
            job.final_paths = job.downloaded_files
            await self.queue.db.update_job(job)
            return

        ops = FileOperations()
        destination = Path(job.destination_path)
        destination.mkdir(parents=True, exist_ok=True)

        final_paths = []
        operation = job.file_operation.value

        for file_path in job.downloaded_files:
            source = Path(file_path)
            if not source.exists():
                await job_log.warning(f"Source file not found: {source}", "copy")
                continue

            dest = destination / source.name
            try:
                await job_log.info(f"Performing {operation}: {source.name} -> {dest}", "copy")
                result = await ops.perform(operation, source, dest)
                if result:
                    final_paths.append(str(result))
                    await job_log.info(f"Successfully copied {source.name}", "copy")
            except Exception as e:
                await job_log.warning(f"Failed to {operation} {source} to {dest}: {e}", "copy")
                final_paths.append(file_path)

        job.final_paths = final_paths
        await self.queue.db.update_job(job)
        await job_log.info(f"Copy phase complete, {len(final_paths)} files at destination", "copy")

    async def _update_job(
        self,
        job: Job,
        status: JobStatus,
        phase: JobPhase,
        progress: float,
        message: str,
    ) -> None:
        """Update job state and notify queue."""
        job.set_status(status)
        job.set_phase(phase)
        job.update_progress(progress, message)
        await self.queue.db.update_job(job)
        await self.queue._notify_update(job)

    async def run_job(self, job_id: str) -> Job | None:
        """Run a specific job immediately (for manual triggering)."""
        job = await self.queue.get_job(job_id)
        if not job:
            return None

        if job.status != JobStatus.PENDING:
            return job

        task = asyncio.create_task(self._execute_job(job))
        await self.queue.mark_running(job.id, task)
        try:
            await task
        except asyncio.CancelledError:
            pass
        finally:
            await self.queue.mark_complete(job.id)

        return await self.queue.get_job(job_id)
