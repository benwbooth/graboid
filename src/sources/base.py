"""Base classes for source protocol implementations."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable


@dataclass
class SourceFile:
    """Represents a file on a remote source."""

    name: str
    path: str
    size: int
    is_directory: bool
    modified_time: datetime | None = None
    permissions: str | None = None
    metadata: dict[str, Any] | None = None

    @property
    def extension(self) -> str:
        """Get file extension (lowercase, without dot)."""
        if "." in self.name:
            return self.name.rsplit(".", 1)[-1].lower()
        return ""

    def matches_patterns(self, patterns: list[str]) -> bool:
        """Check if file matches any of the given glob patterns.

        Args:
            patterns: List of glob patterns (e.g., ["*.txt", "*.pdf"])

        Returns:
            True if file matches any pattern
        """
        import fnmatch

        for pattern in patterns:
            if fnmatch.fnmatch(self.name, pattern):
                return True
            if fnmatch.fnmatch(self.path, pattern):
                return True
        return False


# Type alias for progress callbacks
ProgressCallback = Callable[[int, int], None]  # (bytes_transferred, total_bytes)


class SourceProtocol(ABC):
    """Abstract base class for source protocol implementations.

    All source protocols (FTP, SFTP, SMB, local) implement this interface
    for consistent file operations.
    """

    @abstractmethod
    async def connect(self) -> None:
        """Establish connection to the source.

        Raises:
            ConnectionError: If connection fails
        """
        ...

    @abstractmethod
    async def disconnect(self) -> None:
        """Close connection to the source."""
        ...

    @abstractmethod
    async def list_files(self, path: str = "/") -> list[SourceFile]:
        """List files in a directory.

        Args:
            path: Directory path to list

        Returns:
            List of SourceFile objects

        Raises:
            FileNotFoundError: If path doesn't exist
            PermissionError: If access denied
        """
        ...

    @abstractmethod
    async def download(
        self,
        remote_path: str,
        local_path: Path,
        progress_callback: ProgressCallback | None = None,
    ) -> Path:
        """Download a file from the source.

        Args:
            remote_path: Path on the source
            local_path: Local destination path
            progress_callback: Optional callback for progress updates

        Returns:
            Path to downloaded file

        Raises:
            FileNotFoundError: If remote file doesn't exist
            PermissionError: If access denied
            IOError: If download fails
        """
        ...

    @abstractmethod
    async def get_file_info(self, path: str) -> SourceFile | None:
        """Get information about a specific file.

        Args:
            path: File path

        Returns:
            SourceFile if exists, None otherwise
        """
        ...

    async def download_directory(
        self,
        remote_path: str,
        local_path: Path,
        patterns: list[str] | None = None,
        progress_callback: ProgressCallback | None = None,
    ) -> list[Path]:
        """Download all files from a directory.

        Args:
            remote_path: Directory path on source
            local_path: Local destination directory
            patterns: Optional glob patterns to filter files
            progress_callback: Optional callback for progress updates

        Returns:
            List of downloaded file paths
        """
        downloaded = []
        files = await self.list_files(remote_path)

        for f in files:
            if f.is_directory:
                # Recursively download subdirectories
                sub_local = local_path / f.name
                sub_local.mkdir(parents=True, exist_ok=True)
                sub_files = await self.download_directory(
                    f.path, sub_local, patterns, progress_callback
                )
                downloaded.extend(sub_files)
            else:
                # Check pattern match
                if patterns and not f.matches_patterns(patterns):
                    continue

                dest = local_path / f.name
                try:
                    result = await self.download(f.path, dest, progress_callback)
                    downloaded.append(result)
                except Exception as e:
                    # Log but continue with other files
                    import logging

                    logging.warning(f"Failed to download {f.path}: {e}")

        return downloaded

    async def exists(self, path: str) -> bool:
        """Check if a file or directory exists.

        Args:
            path: Path to check

        Returns:
            True if exists
        """
        info = await self.get_file_info(path)
        return info is not None

    async def __aenter__(self) -> "SourceProtocol":
        """Async context manager entry."""
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.disconnect()
