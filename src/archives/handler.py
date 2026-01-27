"""Archive handling for zip, tar, 7z, and rar formats."""

import asyncio
import fnmatch
import logging
import shutil
import tarfile
import zipfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import BinaryIO

logger = logging.getLogger(__name__)


@dataclass
class ArchiveEntry:
    """Represents an entry in an archive."""

    name: str
    size: int
    compressed_size: int
    is_directory: bool
    modified_time: datetime | None = None

    @property
    def compression_ratio(self) -> float:
        """Get compression ratio (0.0 = fully compressed, 1.0 = no compression)."""
        if self.size == 0:
            return 1.0
        return self.compressed_size / self.size


@dataclass
class ArchiveInfo:
    """Information about an archive."""

    path: Path
    format: str
    total_size: int
    compressed_size: int
    file_count: int
    entries: list[ArchiveEntry]

    @property
    def compression_ratio(self) -> float:
        """Get overall compression ratio."""
        if self.total_size == 0:
            return 1.0
        return self.compressed_size / self.total_size


class ArchiveHandler:
    """Handles listing and extraction of various archive formats.

    Supported formats:
    - ZIP (.zip)
    - TAR (.tar, .tar.gz, .tgz, .tar.bz2, .tbz2, .tar.xz, .txz)
    - 7-Zip (.7z)
    - RAR (.rar)
    """

    # Archive extensions by type
    EXTENSIONS = {
        "zip": [".zip"],
        "tar": [".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz"],
        "7z": [".7z"],
        "rar": [".rar"],
    }

    def __init__(self, cache_dir: Path | None = None):
        """Initialize archive handler.

        Args:
            cache_dir: Directory for caching extracted archives
        """
        self.cache_dir = cache_dir

    def is_archive(self, path: Path) -> bool:
        """Check if a file is a supported archive.

        Args:
            path: Path to check

        Returns:
            True if file is a supported archive
        """
        suffix = path.suffix.lower()
        name_lower = path.name.lower()

        for extensions in self.EXTENSIONS.values():
            for ext in extensions:
                if name_lower.endswith(ext):
                    return True

        return False

    def get_format(self, path: Path) -> str | None:
        """Get the archive format.

        Args:
            path: Path to archive

        Returns:
            Format string or None if not an archive
        """
        name_lower = path.name.lower()

        for format_name, extensions in self.EXTENSIONS.items():
            for ext in extensions:
                if name_lower.endswith(ext):
                    return format_name

        return None

    async def list_contents(self, path: Path) -> ArchiveInfo:
        """List contents of an archive without extracting.

        Args:
            path: Path to archive

        Returns:
            ArchiveInfo with entry listing

        Raises:
            ValueError: If unsupported archive format
            FileNotFoundError: If archive doesn't exist
        """
        if not path.exists():
            raise FileNotFoundError(f"Archive not found: {path}")

        format_type = self.get_format(path)
        if not format_type:
            raise ValueError(f"Unsupported archive format: {path}")

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._list_contents_sync, path, format_type)

    def _list_contents_sync(self, path: Path, format_type: str) -> ArchiveInfo:
        """Synchronous archive listing."""
        if format_type == "zip":
            return self._list_zip(path)
        elif format_type == "tar":
            return self._list_tar(path)
        elif format_type == "7z":
            return self._list_7z(path)
        elif format_type == "rar":
            return self._list_rar(path)
        else:
            raise ValueError(f"Unsupported format: {format_type}")

    def _list_zip(self, path: Path) -> ArchiveInfo:
        """List ZIP archive contents."""
        entries = []
        total_size = 0
        compressed_size = 0

        with zipfile.ZipFile(path, "r") as zf:
            for info in zf.infolist():
                is_dir = info.is_dir()
                size = info.file_size
                comp_size = info.compress_size

                modified = None
                if info.date_time:
                    try:
                        modified = datetime(*info.date_time)
                    except Exception:
                        pass

                entries.append(
                    ArchiveEntry(
                        name=info.filename,
                        size=size,
                        compressed_size=comp_size,
                        is_directory=is_dir,
                        modified_time=modified,
                    )
                )

                if not is_dir:
                    total_size += size
                    compressed_size += comp_size

        return ArchiveInfo(
            path=path,
            format="zip",
            total_size=total_size,
            compressed_size=compressed_size,
            file_count=len([e for e in entries if not e.is_directory]),
            entries=entries,
        )

    def _list_tar(self, path: Path) -> ArchiveInfo:
        """List TAR archive contents."""
        entries = []
        total_size = 0

        mode = "r:*"  # Auto-detect compression

        with tarfile.open(path, mode) as tf:
            for member in tf.getmembers():
                is_dir = member.isdir()
                size = member.size

                modified = None
                if member.mtime:
                    modified = datetime.fromtimestamp(member.mtime)

                entries.append(
                    ArchiveEntry(
                        name=member.name,
                        size=size,
                        compressed_size=size,  # TAR doesn't track per-file compression
                        is_directory=is_dir,
                        modified_time=modified,
                    )
                )

                if not is_dir:
                    total_size += size

        compressed_size = path.stat().st_size

        return ArchiveInfo(
            path=path,
            format="tar",
            total_size=total_size,
            compressed_size=compressed_size,
            file_count=len([e for e in entries if not e.is_directory]),
            entries=entries,
        )

    def _list_7z(self, path: Path) -> ArchiveInfo:
        """List 7-Zip archive contents."""
        try:
            import py7zr
        except ImportError:
            raise ImportError("py7zr required for 7z support: pip install py7zr")

        entries = []
        total_size = 0
        compressed_size = 0

        with py7zr.SevenZipFile(path, "r") as szf:
            for name, info in szf.archiveinfo().files.items():
                is_dir = info.get("is_directory", False)
                size = info.get("uncompressed", 0)
                comp_size = info.get("compressed", 0)

                modified = info.get("modified")

                entries.append(
                    ArchiveEntry(
                        name=name,
                        size=size,
                        compressed_size=comp_size,
                        is_directory=is_dir,
                        modified_time=modified,
                    )
                )

                if not is_dir:
                    total_size += size
                    compressed_size += comp_size

        return ArchiveInfo(
            path=path,
            format="7z",
            total_size=total_size,
            compressed_size=compressed_size,
            file_count=len([e for e in entries if not e.is_directory]),
            entries=entries,
        )

    def _list_rar(self, path: Path) -> ArchiveInfo:
        """List RAR archive contents."""
        try:
            import rarfile
        except ImportError:
            raise ImportError("rarfile required for RAR support: pip install rarfile")

        entries = []
        total_size = 0
        compressed_size = 0

        with rarfile.RarFile(path, "r") as rf:
            for info in rf.infolist():
                is_dir = info.is_dir()
                size = info.file_size
                comp_size = info.compress_size

                modified = None
                if info.date_time:
                    try:
                        modified = datetime(*info.date_time)
                    except Exception:
                        pass

                entries.append(
                    ArchiveEntry(
                        name=info.filename,
                        size=size,
                        compressed_size=comp_size,
                        is_directory=is_dir,
                        modified_time=modified,
                    )
                )

                if not is_dir:
                    total_size += size
                    compressed_size += comp_size

        return ArchiveInfo(
            path=path,
            format="rar",
            total_size=total_size,
            compressed_size=compressed_size,
            file_count=len([e for e in entries if not e.is_directory]),
            entries=entries,
        )

    async def extract(
        self,
        archive_path: Path,
        output_dir: Path,
        patterns: list[str] | None = None,
    ) -> list[Path]:
        """Extract archive contents.

        Args:
            archive_path: Path to archive
            output_dir: Output directory
            patterns: Optional glob patterns to filter files

        Returns:
            List of extracted file paths
        """
        if not archive_path.exists():
            raise FileNotFoundError(f"Archive not found: {archive_path}")

        format_type = self.get_format(archive_path)
        if not format_type:
            raise ValueError(f"Unsupported archive format: {archive_path}")

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._extract_sync, archive_path, output_dir, format_type, patterns
        )

    def _extract_sync(
        self,
        archive_path: Path,
        output_dir: Path,
        format_type: str,
        patterns: list[str] | None,
    ) -> list[Path]:
        """Synchronous extraction."""
        output_dir.mkdir(parents=True, exist_ok=True)

        if format_type == "zip":
            return self._extract_zip(archive_path, output_dir, patterns)
        elif format_type == "tar":
            return self._extract_tar(archive_path, output_dir, patterns)
        elif format_type == "7z":
            return self._extract_7z(archive_path, output_dir, patterns)
        elif format_type == "rar":
            return self._extract_rar(archive_path, output_dir, patterns)
        else:
            raise ValueError(f"Unsupported format: {format_type}")

    def _matches_patterns(self, name: str, patterns: list[str] | None) -> bool:
        """Check if name matches any pattern."""
        if not patterns:
            return True
        return any(fnmatch.fnmatch(name, p) for p in patterns)

    def _extract_zip(
        self, path: Path, output_dir: Path, patterns: list[str] | None
    ) -> list[Path]:
        """Extract ZIP archive."""
        extracted = []

        with zipfile.ZipFile(path, "r") as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue

                if not self._matches_patterns(info.filename, patterns):
                    continue

                # Extract with security check
                dest = output_dir / info.filename
                if not str(dest.resolve()).startswith(str(output_dir.resolve())):
                    logger.warning(f"Skipping suspicious path: {info.filename}")
                    continue

                dest.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src, open(dest, "wb") as dst:
                    shutil.copyfileobj(src, dst)

                extracted.append(dest)

        return extracted

    def _extract_tar(
        self, path: Path, output_dir: Path, patterns: list[str] | None
    ) -> list[Path]:
        """Extract TAR archive."""
        extracted = []

        with tarfile.open(path, "r:*") as tf:
            for member in tf.getmembers():
                if member.isdir():
                    continue

                if not self._matches_patterns(member.name, patterns):
                    continue

                # Security check
                dest = output_dir / member.name
                if not str(dest.resolve()).startswith(str(output_dir.resolve())):
                    logger.warning(f"Skipping suspicious path: {member.name}")
                    continue

                dest.parent.mkdir(parents=True, exist_ok=True)
                src = tf.extractfile(member)
                if src:
                    with open(dest, "wb") as dst:
                        shutil.copyfileobj(src, dst)
                    extracted.append(dest)

        return extracted

    def _extract_7z(
        self, path: Path, output_dir: Path, patterns: list[str] | None
    ) -> list[Path]:
        """Extract 7-Zip archive."""
        import py7zr

        extracted = []

        with py7zr.SevenZipFile(path, "r") as szf:
            if patterns:
                # Filter files
                all_files = szf.getnames()
                targets = [f for f in all_files if self._matches_patterns(f, patterns)]
                szf.extract(output_dir, targets=targets)
            else:
                szf.extractall(output_dir)

            # Get extracted paths
            for name in szf.getnames():
                if patterns and not self._matches_patterns(name, patterns):
                    continue
                dest = output_dir / name
                if dest.is_file():
                    extracted.append(dest)

        return extracted

    def _extract_rar(
        self, path: Path, output_dir: Path, patterns: list[str] | None
    ) -> list[Path]:
        """Extract RAR archive."""
        import rarfile

        extracted = []

        with rarfile.RarFile(path, "r") as rf:
            for info in rf.infolist():
                if info.is_dir():
                    continue

                if not self._matches_patterns(info.filename, patterns):
                    continue

                dest = output_dir / info.filename
                if not str(dest.resolve()).startswith(str(output_dir.resolve())):
                    logger.warning(f"Skipping suspicious path: {info.filename}")
                    continue

                dest.parent.mkdir(parents=True, exist_ok=True)
                rf.extract(info, output_dir)
                extracted.append(dest)

        return extracted

    async def extract_file(
        self,
        archive_path: Path,
        file_name: str,
        output_path: Path | None = None,
    ) -> Path:
        """Extract a single file from an archive.

        Args:
            archive_path: Path to archive
            file_name: Name of file to extract
            output_path: Optional output path (defaults to file name in current dir)

        Returns:
            Path to extracted file
        """
        output = output_path or Path(file_name).name

        loop = asyncio.get_event_loop()
        format_type = self.get_format(archive_path)

        return await loop.run_in_executor(
            None, self._extract_file_sync, archive_path, file_name, output, format_type
        )

    def _extract_file_sync(
        self, archive_path: Path, file_name: str, output: Path, format_type: str
    ) -> Path:
        """Synchronous single file extraction."""
        output.parent.mkdir(parents=True, exist_ok=True)

        if format_type == "zip":
            with zipfile.ZipFile(archive_path, "r") as zf:
                with zf.open(file_name) as src, open(output, "wb") as dst:
                    shutil.copyfileobj(src, dst)

        elif format_type == "tar":
            with tarfile.open(archive_path, "r:*") as tf:
                member = tf.getmember(file_name)
                src = tf.extractfile(member)
                if src:
                    with open(output, "wb") as dst:
                        shutil.copyfileobj(src, dst)

        elif format_type == "7z":
            import py7zr

            with py7zr.SevenZipFile(archive_path, "r") as szf:
                szf.extract(output.parent, targets=[file_name])
                # Move to correct location if needed
                extracted = output.parent / file_name
                if extracted != output:
                    shutil.move(extracted, output)

        elif format_type == "rar":
            import rarfile

            with rarfile.RarFile(archive_path, "r") as rf:
                rf.extract(file_name, output.parent)
                extracted = output.parent / file_name
                if extracted != output:
                    shutil.move(extracted, output)

        return output
