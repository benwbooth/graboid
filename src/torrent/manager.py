"""Torrent download queue manager."""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable

from rich.console import Console
from rich.live import Live
from rich.table import Table

from .client import TorrentClient, TorrentState, TorrentStatus, get_available_client

logger = logging.getLogger(__name__)


@dataclass
class QueuedDownload:
    """A queued torrent download."""

    id: str
    source: str  # magnet link, torrent URL, or file path
    label: str
    torrent_hash: str | None = None
    added_at: datetime = field(default_factory=datetime.now)
    completed_at: datetime | None = None
    error: str | None = None


class TorrentManager:
    """
    Manages a queue of torrent downloads with progress tracking.

    Features:
    - Automatic client detection (qBittorrent or embedded)
    - Download queue with concurrent limit
    - Progress monitoring and callbacks
    - Category-based organization
    - Path translation for containerized clients
    """

    def __init__(
        self,
        client: TorrentClient | None = None,
        download_dir: Path | None = None,
        max_concurrent: int = 3,
        category_prefix: str = "graboid",
        path_translator: Callable[[Path], Path] | None = None,
    ):
        self.client = client
        self.download_dir = download_dir or Path.cwd() / "downloads"
        self.max_concurrent = max_concurrent
        self.category_prefix = category_prefix
        self.path_translator = path_translator or (lambda p: p)

        self._queue: list[QueuedDownload] = []
        self._active: dict[str, QueuedDownload] = {}  # torrent_hash -> download
        self._completed: list[QueuedDownload] = []
        self._progress_callbacks: list[Callable[[QueuedDownload, TorrentStatus], None]] = []
        self._monitor_task: asyncio.Task | None = None
        self._running = False

    async def initialize(self) -> None:
        """Initialize the torrent client if not provided."""
        if self.client is None:
            self.client = await get_available_client(download_dir=self.download_dir)

    def add_progress_callback(
        self, callback: Callable[[QueuedDownload, TorrentStatus], None]
    ) -> None:
        """Add a callback for progress updates."""
        self._progress_callbacks.append(callback)

    def _notify_progress(self, download: QueuedDownload, status: TorrentStatus) -> None:
        """Notify all progress callbacks."""
        for callback in self._progress_callbacks:
            try:
                callback(download, status)
            except Exception as e:
                logger.warning(f"Progress callback error: {e}")

    def _make_category(self, label: str) -> str:
        """Create category name for a label."""
        safe_label = label.lower().replace(" ", "-").replace("/", "-")
        return f"{self.category_prefix}/{safe_label}"

    async def add_download(
        self,
        source: str,
        label: str,
    ) -> QueuedDownload:
        """
        Add a torrent to the download queue.

        Args:
            source: Magnet link, torrent URL, or file path
            label: Label name for organization

        Returns:
            QueuedDownload object
        """
        import hashlib

        download_id = hashlib.md5(f"{source}{datetime.now().isoformat()}".encode()).hexdigest()[:12]

        download = QueuedDownload(
            id=download_id,
            source=source,
            label=label,
        )

        self._queue.append(download)
        logger.info(f"Queued download: {download_id} for {label}")

        return download

    async def start(self) -> None:
        """Start processing the download queue."""
        if self._running:
            return

        await self.initialize()
        self._running = True

        # Start monitor task
        self._monitor_task = asyncio.create_task(self._monitor_loop())

        # Process queue
        asyncio.create_task(self._process_queue())

    async def stop(self) -> None:
        """Stop the download manager."""
        self._running = False
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass

    async def _process_queue(self) -> None:
        """Process queued downloads."""
        while self._running:
            # Start downloads up to concurrent limit
            while len(self._active) < self.max_concurrent and self._queue:
                download = self._queue.pop(0)
                await self._start_download(download)

            await asyncio.sleep(1)

    async def _start_download(self, download: QueuedDownload) -> None:
        """Start a single download."""
        if self.client is None:
            download.error = "No torrent client available"
            return

        try:
            category = self._make_category(download.label)
            save_path = self.download_dir / download.label.replace(" ", "_")
            save_path.mkdir(parents=True, exist_ok=True)

            # Translate path for containerized clients
            client_save_path = self.path_translator(save_path)

            torrent_hash = await self.client.add_torrent(
                download.source,
                save_path=client_save_path,
                category=category,
            )

            download.torrent_hash = torrent_hash
            self._active[torrent_hash] = download
            logger.info(f"Started download: {download.id} (hash: {torrent_hash})")

        except Exception as e:
            logger.error(f"Failed to start download {download.id}: {e}")
            download.error = str(e)
            self._completed.append(download)

    async def _monitor_loop(self) -> None:
        """Monitor active downloads for completion."""
        while self._running:
            if self.client is None:
                await asyncio.sleep(5)
                continue

            completed_hashes = []

            for torrent_hash, download in list(self._active.items()):
                try:
                    status = await self.client.get_status(torrent_hash)

                    if status is None:
                        continue

                    # Notify callbacks
                    self._notify_progress(download, status)

                    # Check for completion
                    if status.state == TorrentState.COMPLETED:
                        download.completed_at = datetime.now()
                        completed_hashes.append(torrent_hash)
                        logger.info(f"Download completed: {download.id}")

                    elif status.state == TorrentState.ERROR:
                        download.error = "Torrent error"
                        completed_hashes.append(torrent_hash)
                        logger.error(f"Download failed: {download.id}")

                except Exception as e:
                    logger.warning(f"Error monitoring {torrent_hash}: {e}")

            # Move completed to completed list
            for torrent_hash in completed_hashes:
                download = self._active.pop(torrent_hash)
                self._completed.append(download)

            await asyncio.sleep(5)

    async def get_status(self) -> dict:
        """Get current status of all downloads."""
        return {
            "queued": len(self._queue),
            "active": len(self._active),
            "completed": len(self._completed),
            "failed": len([d for d in self._completed if d.error]),
        }

    async def get_all_statuses(self) -> list[tuple[QueuedDownload, TorrentStatus | None]]:
        """Get detailed status for all active downloads."""
        if self.client is None:
            return []

        results = []
        for torrent_hash, download in self._active.items():
            status = await self.client.get_status(torrent_hash)
            results.append((download, status))
        return results

    async def wait_for_completion(
        self,
        show_progress: bool = True,
        console: Console | None = None,
    ) -> list[QueuedDownload]:
        """
        Wait for all downloads to complete.

        Args:
            show_progress: Whether to show a live progress display
            console: Rich console for output

        Returns:
            List of completed downloads
        """
        console = console or Console()

        if show_progress:
            with Live(self._make_progress_table(), refresh_per_second=1, console=console) as live:
                while self._queue or self._active:
                    live.update(self._make_progress_table())
                    await asyncio.sleep(1)
        else:
            while self._queue or self._active:
                await asyncio.sleep(5)

        return self._completed

    def _make_progress_table(self) -> Table:
        """Create a rich table showing download progress."""
        table = Table(title="Torrent Downloads")

        table.add_column("Label", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Progress", style="yellow")
        table.add_column("Speed", style="blue")
        table.add_column("ETA", style="magenta")

        # Queued
        for download in self._queue[:5]:
            table.add_row(download.label, "Queued", "-", "-", "-")

        if len(self._queue) > 5:
            table.add_row(f"... +{len(self._queue) - 5} more", "", "", "", "")

        # Active - need to get status synchronously for table
        # This is a limitation - in real use, cache the statuses
        for download in self._active.values():
            table.add_row(
                download.label,
                "Downloading",
                "...",
                "...",
                "...",
            )

        # Recent completed
        for download in self._completed[-3:]:
            status = "Completed" if not download.error else f"Failed: {download.error[:20]}"
            table.add_row(download.label, status, "100%", "-", "-")

        return table


async def download_torrents(
    sources: list[tuple[str, str]],  # (source, label) tuples
    download_dir: Path | None = None,
    max_concurrent: int = 3,
    show_progress: bool = True,
) -> list[QueuedDownload]:
    """
    Convenience function to download multiple torrents.

    Args:
        sources: List of (source, label) tuples
        download_dir: Download directory
        max_concurrent: Maximum concurrent downloads
        show_progress: Whether to show progress

    Returns:
        List of completed downloads
    """
    manager = TorrentManager(
        download_dir=download_dir,
        max_concurrent=max_concurrent,
    )

    await manager.start()

    for source, label in sources:
        await manager.add_download(source, label)

    completed = await manager.wait_for_completion(show_progress=show_progress)

    await manager.stop()

    return completed
