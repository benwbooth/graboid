"""Custom download controller for reliable file downloads."""

import asyncio
import hashlib
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable
from urllib.parse import unquote, urlparse

import httpx
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    TaskID,
    TextColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
)

logger = logging.getLogger(__name__)


@dataclass
class DownloadResult:
    """Result of a download operation."""

    success: bool
    path: Path | None = None
    size: int = 0
    error: str | None = None
    is_torrent: bool = False
    magnet_link: str | None = None


@dataclass
class DownloadProgress:
    """Progress information for a download."""

    filename: str
    total_bytes: int
    downloaded_bytes: int
    speed_bps: float = 0.0


class DownloadController:
    """Handles file downloads with progress tracking and resume support."""

    def __init__(
        self,
        download_dir: Path | None = None,
        chunk_size: int = 1024 * 1024,  # 1MB chunks
        timeout: float = 30.0,
        max_retries: int = 3,
    ):
        self.download_dir = download_dir or Path.cwd() / "downloads"
        self.download_dir.mkdir(parents=True, exist_ok=True)
        self.chunk_size = chunk_size
        self.timeout = timeout
        self.max_retries = max_retries
        self._progress_callbacks: list[Callable[[DownloadProgress], None]] = []

    def add_progress_callback(self, callback: Callable[[DownloadProgress], None]) -> None:
        """Add a callback for progress updates."""
        self._progress_callbacks.append(callback)

    def _notify_progress(self, progress: DownloadProgress) -> None:
        """Notify all progress callbacks."""
        for callback in self._progress_callbacks:
            try:
                callback(progress)
            except Exception as e:
                logger.warning(f"Progress callback error: {e}")

    def _extract_filename(self, url: str, response: httpx.Response) -> str:
        """Extract filename from URL or Content-Disposition header."""
        # Try Content-Disposition header first
        content_disp = response.headers.get("content-disposition", "")
        if content_disp:
            # Try filename*= (RFC 5987)
            match = re.search(r"filename\*=(?:UTF-8'')?([^;]+)", content_disp, re.IGNORECASE)
            if match:
                return unquote(match.group(1).strip('"'))

            # Try filename=
            match = re.search(r'filename="?([^";\n]+)"?', content_disp, re.IGNORECASE)
            if match:
                return unquote(match.group(1).strip())

        # Fall back to URL path
        parsed = urlparse(url)
        path = unquote(parsed.path)
        if path and "/" in path:
            return path.rsplit("/", 1)[-1]

        return "download"

    def _is_torrent_or_magnet(self, url: str, response: httpx.Response | None = None) -> tuple[bool, str | None]:
        """Check if URL is a torrent file or magnet link."""
        if url.startswith("magnet:"):
            return True, url

        if response:
            content_type = response.headers.get("content-type", "").lower()
            if "application/x-bittorrent" in content_type:
                return True, None

        if url.lower().endswith(".torrent"):
            return True, None

        return False, None

    async def download_file(
        self,
        url: str,
        filename: str | None = None,
        expected_hash: str | None = None,
        hash_algorithm: str = "md5",
        show_progress: bool = True,
    ) -> DownloadResult:
        """
        Download a file from URL with progress tracking.

        Args:
            url: URL to download from
            filename: Override filename (extracted from URL/headers if None)
            expected_hash: Expected hash for verification
            hash_algorithm: Hash algorithm to use (md5, sha1, sha256)
            show_progress: Whether to show rich progress bar

        Returns:
            DownloadResult with success status and file path
        """
        # Handle magnet links
        if url.startswith("magnet:"):
            return DownloadResult(
                success=True,
                is_torrent=True,
                magnet_link=url,
            )

        for attempt in range(self.max_retries):
            try:
                return await self._do_download(
                    url, filename, expected_hash, hash_algorithm, show_progress
                )
            except httpx.HTTPStatusError as e:
                if e.response.status_code in (429, 503):
                    # Rate limited or service unavailable, wait and retry
                    wait_time = 2 ** attempt
                    logger.warning(f"Rate limited, waiting {wait_time}s before retry")
                    await asyncio.sleep(wait_time)
                    continue
                return DownloadResult(success=False, error=f"HTTP {e.response.status_code}: {e}")
            except httpx.TimeoutException:
                logger.warning(f"Timeout on attempt {attempt + 1}")
                continue
            except Exception as e:
                logger.error(f"Download error: {e}")
                return DownloadResult(success=False, error=str(e))

        return DownloadResult(success=False, error="Max retries exceeded")

    async def _do_download(
        self,
        url: str,
        filename: str | None,
        expected_hash: str | None,
        hash_algorithm: str,
        show_progress: bool,
    ) -> DownloadResult:
        """Perform the actual download."""
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=httpx.Timeout(self.timeout, read=300.0),
        ) as client:
            # Start streaming request
            async with client.stream("GET", url) as response:
                response.raise_for_status()

                # Check if it's a torrent
                is_torrent, magnet = self._is_torrent_or_magnet(url, response)

                # Determine filename
                actual_filename = filename or self._extract_filename(url, response)
                file_path = self.download_dir / actual_filename

                # Get total size
                total_size = int(response.headers.get("content-length", 0))

                # Set up hash if needed
                hasher = None
                if expected_hash:
                    hasher = hashlib.new(hash_algorithm)

                # Download with progress
                downloaded = 0

                if show_progress:
                    with Progress(
                        TextColumn("[bold blue]{task.fields[filename]}", justify="right"),
                        BarColumn(bar_width=40),
                        "[progress.percentage]{task.percentage:>3.1f}%",
                        DownloadColumn(),
                        TransferSpeedColumn(),
                        TimeRemainingColumn(),
                    ) as progress:
                        task = progress.add_task(
                            "download",
                            filename=actual_filename[:30],
                            total=total_size or None,
                        )

                        with open(file_path, "wb") as f:
                            async for chunk in response.aiter_bytes(self.chunk_size):
                                f.write(chunk)
                                downloaded += len(chunk)

                                if hasher:
                                    hasher.update(chunk)

                                progress.update(task, completed=downloaded)

                                self._notify_progress(
                                    DownloadProgress(
                                        filename=actual_filename,
                                        total_bytes=total_size,
                                        downloaded_bytes=downloaded,
                                    )
                                )
                else:
                    with open(file_path, "wb") as f:
                        async for chunk in response.aiter_bytes(self.chunk_size):
                            f.write(chunk)
                            downloaded += len(chunk)

                            if hasher:
                                hasher.update(chunk)

                # Verify hash if provided
                if expected_hash and hasher:
                    actual_hash = hasher.hexdigest()
                    if actual_hash.lower() != expected_hash.lower():
                        file_path.unlink()  # Remove corrupt file
                        return DownloadResult(
                            success=False,
                            error=f"Hash mismatch: expected {expected_hash}, got {actual_hash}",
                        )

                return DownloadResult(
                    success=True,
                    path=file_path,
                    size=downloaded,
                    is_torrent=is_torrent,
                )

    async def download_with_resume(
        self,
        url: str,
        filename: str | None = None,
    ) -> DownloadResult:
        """Download a file with resume support for interrupted downloads."""
        async with httpx.AsyncClient(follow_redirects=True) as client:
            # First, get file info with HEAD request
            head_response = await client.head(url)
            head_response.raise_for_status()

            actual_filename = filename or self._extract_filename(url, head_response)
            file_path = self.download_dir / actual_filename
            partial_path = file_path.with_suffix(file_path.suffix + ".partial")

            total_size = int(head_response.headers.get("content-length", 0))
            accept_ranges = head_response.headers.get("accept-ranges", "").lower() == "bytes"

            # Check for existing partial download
            start_byte = 0
            if partial_path.exists() and accept_ranges:
                start_byte = partial_path.stat().st_size
                if start_byte >= total_size:
                    # Already complete
                    partial_path.rename(file_path)
                    return DownloadResult(success=True, path=file_path, size=total_size)

            # Set up headers for range request
            headers = {}
            if start_byte > 0:
                headers["Range"] = f"bytes={start_byte}-"
                logger.info(f"Resuming download from byte {start_byte}")

            # Download
            async with client.stream("GET", url, headers=headers) as response:
                response.raise_for_status()

                mode = "ab" if start_byte > 0 else "wb"
                downloaded = start_byte

                with Progress(
                    TextColumn("[bold blue]{task.fields[filename]}", justify="right"),
                    BarColumn(bar_width=40),
                    "[progress.percentage]{task.percentage:>3.1f}%",
                    DownloadColumn(),
                    TransferSpeedColumn(),
                    TimeRemainingColumn(),
                ) as progress:
                    task = progress.add_task(
                        "download",
                        filename=actual_filename[:30],
                        total=total_size,
                        completed=start_byte,
                    )

                    with open(partial_path, mode) as f:
                        async for chunk in response.aiter_bytes(self.chunk_size):
                            f.write(chunk)
                            downloaded += len(chunk)
                            progress.update(task, completed=downloaded)

            # Rename partial to final
            partial_path.rename(file_path)

            return DownloadResult(success=True, path=file_path, size=downloaded)
