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
        try:
            await self._update_job(job, JobStatus.RUNNING, JobPhase.INIT, 0, "Initializing job")

            # Phase 1: Browse (if we have a source URL or need to find one)
            if job.source_url or job.prompt:
                await self._phase_browse(job)

            if job.status == JobStatus.FAILED:
                return

            # Phase 2: Download found URLs
            if job.found_urls:
                await self._phase_download(job)

            if job.status == JobStatus.FAILED:
                return

            # Phase 3: Extract archives if needed
            if job.downloaded_files:
                await self._phase_extract(job)

            if job.status == JobStatus.FAILED:
                return

            # Phase 4: Copy files to destination
            if job.downloaded_files and job.destination_path:
                await self._phase_copy(job)

            if job.status == JobStatus.FAILED:
                return

            # Complete
            await self._update_job(job, JobStatus.COMPLETE, JobPhase.DONE, 100, "Job complete")

        except asyncio.CancelledError:
            job.set_status(JobStatus.CANCELLED)
            await self.queue.db.update_job(job)
            raise
        except Exception as e:
            logger.error(f"Job {job.id} failed: {e}")
            job.fail(str(e))
            await self.queue.db.update_job(job)

    async def _phase_browse(self, job: Job) -> None:
        """Browse phase: Use LLM to find download URLs."""
        await self._update_job(job, JobStatus.BROWSING, JobPhase.BROWSE, 10, "Browsing for download links")

        # If we have a direct source URL and no prompt, treat it as a direct download
        if job.source_url and not job.prompt:
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

            result = await self.graboid.browse(url, task, screenshot_callback=screenshot_callback)

            if result.success and result.found_links:
                job.found_urls = result.found_links
                await self._update_job(
                    job, JobStatus.BROWSING, JobPhase.BROWSE, 30,
                    f"Found {len(result.found_links)} download links"
                )
            elif result.error:
                job.fail(f"Browse failed: {result.error}")
            else:
                job.fail("No download links found")

            await self.queue.db.update_job(job)

        except Exception as e:
            job.fail(f"Browse error: {e}")
            await self.queue.db.update_job(job)

    async def _phase_download(self, job: Job) -> None:
        """Download phase: Download files from found URLs."""
        await self._update_job(job, JobStatus.DOWNLOADING, JobPhase.DOWNLOAD, 40, "Starting downloads")

        downloaded = []
        total = len(job.found_urls)

        for i, url in enumerate(job.found_urls):
            try:
                progress = 40 + (i / total) * 30
                await self._update_job(
                    job, JobStatus.DOWNLOADING, JobPhase.DOWNLOAD, progress,
                    f"Downloading {i+1}/{total}: {url[:50]}..."
                )

                # Check if this is a torrent/magnet
                if url.startswith("magnet:") or url.endswith(".torrent"):
                    result = await self.graboid.add_torrent(url)
                    if result.success:
                        # For torrents, we'd need to track the files differently
                        downloaded.extend([str(p) for p in result.downloaded_files])
                else:
                    # Regular HTTP download
                    result = await self.graboid.download(url)
                    if result.success:
                        downloaded.extend([str(p) for p in result.downloaded_files])
                    elif result.error:
                        logger.warning(f"Download failed for {url}: {result.error}")

            except Exception as e:
                logger.warning(f"Download failed for {url}: {e}")

        job.downloaded_files = downloaded
        await self.queue.db.update_job(job)

        if not downloaded:
            job.fail("All downloads failed")
            await self.queue.db.update_job(job)

    async def _phase_extract(self, job: Job) -> None:
        """Extract phase: Extract archives if needed."""
        await self._update_job(job, JobStatus.EXTRACTING, JobPhase.EXTRACT, 75, "Checking for archives")

        # Import archive handler
        try:
            from ..archives import ArchiveHandler
        except ImportError:
            logger.debug("Archive handler not available, skipping extraction")
            return

        extracted = []
        handler = ArchiveHandler()

        for file_path in job.downloaded_files:
            path = Path(file_path)
            if handler.is_archive(path):
                await self._update_job(
                    job, JobStatus.EXTRACTING, JobPhase.EXTRACT, 80,
                    f"Extracting {path.name}"
                )
                try:
                    extract_dir = path.parent / path.stem
                    result = await handler.extract(path, extract_dir, patterns=job.file_filter or None)
                    extracted.extend([str(p) for p in result])
                except Exception as e:
                    logger.warning(f"Failed to extract {path}: {e}")
                    extracted.append(file_path)
            else:
                extracted.append(file_path)

        job.downloaded_files = extracted
        await self.queue.db.update_job(job)

    async def _phase_copy(self, job: Job) -> None:
        """Copy phase: Copy files to destination using configured operation."""
        await self._update_job(job, JobStatus.COPYING, JobPhase.COPY, 90, "Copying files to destination")

        try:
            from ..files import FileOperations
        except ImportError:
            logger.debug("File operations not available, skipping copy")
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
                continue

            dest = destination / source.name
            try:
                result = await ops.perform(operation, source, dest)
                if result:
                    final_paths.append(str(result))
            except Exception as e:
                logger.warning(f"Failed to {operation} {source} to {dest}: {e}")
                final_paths.append(file_path)

        job.final_paths = final_paths
        await self.queue.db.update_job(job)

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
