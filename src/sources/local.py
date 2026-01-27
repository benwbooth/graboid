"""Local filesystem source with path whitelisting for security."""

import asyncio
import logging
import os
import shutil
from datetime import datetime
from pathlib import Path

from .base import ProgressCallback, SourceFile, SourceProtocol

logger = logging.getLogger(__name__)


class LocalSource(SourceProtocol):
    """Local filesystem source with security whitelisting.

    For security, this source only allows access to explicitly whitelisted paths.
    Attempting to access paths outside the whitelist will raise PermissionError.
    """

    def __init__(self, allowed_paths: list[str | Path] | None = None):
        """Initialize local source.

        Args:
            allowed_paths: List of paths that are allowed to be accessed.
                          If None or empty, all local access is denied.
                          Supports ~ expansion for home directory.
        """
        self._allowed_paths: list[Path] = []
        if allowed_paths:
            for p in allowed_paths:
                expanded = Path(p).expanduser().resolve()
                self._allowed_paths.append(expanded)

        self._connected = False

    async def connect(self) -> None:
        """Connect (validates configuration)."""
        if not self._allowed_paths:
            logger.warning("LocalSource initialized with no allowed paths - all access will be denied")
        self._connected = True
        logger.info(f"LocalSource ready with {len(self._allowed_paths)} allowed paths")

    async def disconnect(self) -> None:
        """Disconnect."""
        self._connected = False

    def _check_path_allowed(self, path: Path) -> bool:
        """Check if a path is within the allowed whitelist.

        Args:
            path: Path to check

        Returns:
            True if path is allowed
        """
        resolved = path.resolve()

        for allowed in self._allowed_paths:
            try:
                resolved.relative_to(allowed)
                return True
            except ValueError:
                continue

        return False

    def _validate_path(self, path: str | Path) -> Path:
        """Validate and resolve a path.

        Args:
            path: Path to validate

        Returns:
            Resolved Path

        Raises:
            PermissionError: If path is not in whitelist
        """
        resolved = Path(path).expanduser().resolve()

        if not self._check_path_allowed(resolved):
            raise PermissionError(
                f"Access denied: '{path}' is not within allowed paths. "
                f"Allowed paths: {[str(p) for p in self._allowed_paths]}"
            )

        return resolved

    async def list_files(self, path: str = "/") -> list[SourceFile]:
        """List files in a directory."""
        resolved = self._validate_path(path)

        if not resolved.is_dir():
            raise FileNotFoundError(f"Directory not found: {path}")

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._list_files_sync, resolved)

    def _list_files_sync(self, path: Path) -> list[SourceFile]:
        """Synchronous file listing."""
        files = []

        for entry in path.iterdir():
            try:
                stat_info = entry.stat()
                is_dir = entry.is_dir()

                files.append(
                    SourceFile(
                        name=entry.name,
                        path=str(entry),
                        size=stat_info.st_size if not is_dir else 0,
                        is_directory=is_dir,
                        modified_time=datetime.fromtimestamp(stat_info.st_mtime),
                        permissions=oct(stat_info.st_mode)[-3:],
                    )
                )
            except (PermissionError, OSError) as e:
                logger.debug(f"Cannot stat {entry}: {e}")

        return files

    async def download(
        self,
        remote_path: str,
        local_path: Path,
        progress_callback: ProgressCallback | None = None,
    ) -> Path:
        """Copy a file to the destination.

        Note: For local sources, 'download' is actually a copy operation.
        """
        source = self._validate_path(remote_path)

        if not source.is_file():
            raise FileNotFoundError(f"File not found: {remote_path}")

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._copy_file_sync, source, local_path, progress_callback
        )

    def _copy_file_sync(
        self,
        source: Path,
        dest: Path,
        progress_callback: ProgressCallback | None,
    ) -> Path:
        """Synchronous file copy with progress."""
        dest.parent.mkdir(parents=True, exist_ok=True)

        total_size = source.stat().st_size
        chunk_size = 1024 * 1024  # 1MB chunks
        transferred = 0

        with open(source, "rb") as src, open(dest, "wb") as dst:
            while True:
                chunk = src.read(chunk_size)
                if not chunk:
                    break

                dst.write(chunk)
                transferred += len(chunk)

                if progress_callback:
                    progress_callback(transferred, total_size)

        # Preserve metadata
        shutil.copystat(source, dest)

        logger.info(f"Copied {source} to {dest}")
        return dest

    async def get_file_info(self, path: str) -> SourceFile | None:
        """Get information about a specific file."""
        try:
            resolved = self._validate_path(path)
        except PermissionError:
            return None

        if not resolved.exists():
            return None

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._get_file_info_sync, resolved)

    def _get_file_info_sync(self, path: Path) -> SourceFile | None:
        """Synchronous file info retrieval."""
        try:
            stat_info = path.stat()
            is_dir = path.is_dir()

            return SourceFile(
                name=path.name,
                path=str(path),
                size=stat_info.st_size if not is_dir else 0,
                is_directory=is_dir,
                modified_time=datetime.fromtimestamp(stat_info.st_mtime),
                permissions=oct(stat_info.st_mode)[-3:],
            )
        except (PermissionError, OSError):
            return None

    async def create_link(
        self,
        source_path: str,
        link_path: Path,
        symbolic: bool = False,
    ) -> Path:
        """Create a hard link or symbolic link.

        Args:
            source_path: Source file path
            link_path: Path for the link
            symbolic: Create symbolic link instead of hard link

        Returns:
            Path to created link
        """
        source = self._validate_path(source_path)

        if not source.is_file():
            raise FileNotFoundError(f"File not found: {source_path}")

        link_path.parent.mkdir(parents=True, exist_ok=True)

        if symbolic:
            link_path.symlink_to(source)
        else:
            link_path.hardlink_to(source)

        logger.info(f"Created {'symlink' if symbolic else 'hardlink'}: {link_path} -> {source}")
        return link_path
