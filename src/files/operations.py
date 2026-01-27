"""File operations: copy, hardlink, symlink, reflink."""

import asyncio
import logging
import os
import shutil
from enum import Enum
from pathlib import Path
from typing import Callable

logger = logging.getLogger(__name__)


class FileOperation(str, Enum):
    """File operation types."""

    COPY = "copy"
    HARDLINK = "hardlink"
    SYMLINK = "symlink"
    REFLINK = "reflink"
    PATH_ONLY = "path_only"


# Progress callback type
ProgressCallback = Callable[[int, int], None]  # (bytes_copied, total_bytes)


class FileOperations:
    """Handles various file operations with async support."""

    def __init__(self):
        """Initialize file operations handler."""
        self._reflink_available: bool | None = None

    @property
    def reflink_available(self) -> bool:
        """Check if reflink (copy-on-write) is available."""
        if self._reflink_available is None:
            try:
                import reflink

                self._reflink_available = reflink.supported_at(".")
            except ImportError:
                self._reflink_available = False
            except Exception:
                self._reflink_available = False

        return self._reflink_available

    async def perform(
        self,
        operation: str | FileOperation,
        source: Path,
        destination: Path,
        progress_callback: ProgressCallback | None = None,
    ) -> Path | None:
        """Perform a file operation.

        Args:
            operation: Operation type (copy, hardlink, symlink, reflink, path_only)
            source: Source file path
            destination: Destination path
            progress_callback: Optional progress callback for copy operations

        Returns:
            Destination path on success, None on failure

        Raises:
            ValueError: If operation is unknown
            FileNotFoundError: If source doesn't exist
        """
        if isinstance(operation, str):
            operation = FileOperation(operation)

        if not source.exists():
            raise FileNotFoundError(f"Source file not found: {source}")

        destination.parent.mkdir(parents=True, exist_ok=True)

        loop = asyncio.get_event_loop()

        if operation == FileOperation.COPY:
            return await loop.run_in_executor(
                None, self._copy, source, destination, progress_callback
            )
        elif operation == FileOperation.HARDLINK:
            return await loop.run_in_executor(None, self._hardlink, source, destination)
        elif operation == FileOperation.SYMLINK:
            return await loop.run_in_executor(None, self._symlink, source, destination)
        elif operation == FileOperation.REFLINK:
            return await loop.run_in_executor(
                None, self._reflink, source, destination, progress_callback
            )
        elif operation == FileOperation.PATH_ONLY:
            return source
        else:
            raise ValueError(f"Unknown operation: {operation}")

    def _copy(
        self,
        source: Path,
        destination: Path,
        progress_callback: ProgressCallback | None,
    ) -> Path:
        """Copy file with progress support."""
        total_size = source.stat().st_size

        if progress_callback:
            chunk_size = 1024 * 1024  # 1MB chunks
            copied = 0

            with open(source, "rb") as src, open(destination, "wb") as dst:
                while True:
                    chunk = src.read(chunk_size)
                    if not chunk:
                        break
                    dst.write(chunk)
                    copied += len(chunk)
                    progress_callback(copied, total_size)

            # Copy metadata
            shutil.copystat(source, destination)
        else:
            shutil.copy2(source, destination)

        logger.debug(f"Copied {source} to {destination}")
        return destination

    def _hardlink(self, source: Path, destination: Path) -> Path:
        """Create a hard link."""
        if destination.exists():
            destination.unlink()

        destination.hardlink_to(source)
        logger.debug(f"Hard linked {destination} -> {source}")
        return destination

    def _symlink(self, source: Path, destination: Path) -> Path:
        """Create a symbolic link."""
        if destination.exists() or destination.is_symlink():
            destination.unlink()

        # Use absolute path for symlink target
        destination.symlink_to(source.resolve())
        logger.debug(f"Sym linked {destination} -> {source}")
        return destination

    def _reflink(
        self,
        source: Path,
        destination: Path,
        progress_callback: ProgressCallback | None,
    ) -> Path:
        """Create a copy-on-write reflink, falling back to copy if unavailable."""
        try:
            import reflink

            if destination.exists():
                destination.unlink()

            reflink.reflink(str(source), str(destination))
            logger.debug(f"Reflinked {source} to {destination}")
            return destination

        except ImportError:
            logger.debug("reflink module not available, falling back to copy")
            return self._copy(source, destination, progress_callback)

        except (OSError, NotImplementedError) as e:
            # Reflink not supported on this filesystem
            logger.debug(f"reflink failed ({e}), falling back to copy")
            return self._copy(source, destination, progress_callback)

    async def copy(
        self,
        source: Path,
        destination: Path,
        progress_callback: ProgressCallback | None = None,
    ) -> Path:
        """Copy a file."""
        return await self.perform(FileOperation.COPY, source, destination, progress_callback)

    async def hardlink(self, source: Path, destination: Path) -> Path:
        """Create a hard link."""
        return await self.perform(FileOperation.HARDLINK, source, destination)

    async def symlink(self, source: Path, destination: Path) -> Path:
        """Create a symbolic link."""
        return await self.perform(FileOperation.SYMLINK, source, destination)

    async def reflink(
        self,
        source: Path,
        destination: Path,
        progress_callback: ProgressCallback | None = None,
    ) -> Path:
        """Create a copy-on-write reflink (falls back to copy)."""
        return await self.perform(FileOperation.REFLINK, source, destination, progress_callback)

    async def move(self, source: Path, destination: Path) -> Path:
        """Move a file."""
        destination.parent.mkdir(parents=True, exist_ok=True)

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, shutil.move, str(source), str(destination))

        logger.debug(f"Moved {source} to {destination}")
        return destination

    async def copy_directory(
        self,
        source: Path,
        destination: Path,
        operation: FileOperation = FileOperation.COPY,
        patterns: list[str] | None = None,
        progress_callback: ProgressCallback | None = None,
    ) -> list[Path]:
        """Copy all files from a directory.

        Args:
            source: Source directory
            destination: Destination directory
            operation: File operation to use
            patterns: Optional glob patterns to filter files
            progress_callback: Optional progress callback

        Returns:
            List of destination paths
        """
        import fnmatch

        if not source.is_dir():
            raise ValueError(f"Source is not a directory: {source}")

        destination.mkdir(parents=True, exist_ok=True)
        results = []

        for item in source.rglob("*"):
            if item.is_dir():
                continue

            # Check pattern match
            if patterns:
                if not any(fnmatch.fnmatch(item.name, p) for p in patterns):
                    continue

            # Calculate relative path
            rel_path = item.relative_to(source)
            dest_path = destination / rel_path

            try:
                result = await self.perform(operation, item, dest_path, progress_callback)
                if result:
                    results.append(result)
            except Exception as e:
                logger.warning(f"Failed to {operation.value} {item}: {e}")

        return results

    @staticmethod
    def get_operation_description(operation: FileOperation) -> str:
        """Get human-readable description of an operation."""
        descriptions = {
            FileOperation.COPY: "Copy file (full duplicate)",
            FileOperation.HARDLINK: "Hard link (same inode, saves space)",
            FileOperation.SYMLINK: "Symbolic link (pointer to original)",
            FileOperation.REFLINK: "Copy-on-write (space-efficient until modified)",
            FileOperation.PATH_ONLY: "Return path only (no file operation)",
        }
        return descriptions.get(operation, "Unknown operation")
