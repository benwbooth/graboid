"""FTP source protocol implementation."""

import asyncio
import ftplib
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from .base import ProgressCallback, SourceFile, SourceProtocol

logger = logging.getLogger(__name__)


class FTPSource(SourceProtocol):
    """FTP source using ftplib with async wrapper."""

    def __init__(
        self,
        host: str,
        port: int = 21,
        username: str | None = None,
        password: str | None = None,
        passive: bool = True,
        timeout: float = 30.0,
        tls: bool = False,
    ):
        """Initialize FTP source.

        Args:
            host: FTP server hostname
            port: FTP port (default 21)
            username: Username (default: anonymous)
            password: Password
            passive: Use passive mode (default True)
            timeout: Connection timeout in seconds
            tls: Use FTPS (FTP over TLS)
        """
        self.host = host
        self.port = port
        self.username = username or "anonymous"
        self.password = password or "anonymous@"
        self.passive = passive
        self.timeout = timeout
        self.tls = tls
        self._ftp: ftplib.FTP | None = None

    async def connect(self) -> None:
        """Connect to FTP server."""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._connect_sync)

    def _connect_sync(self) -> None:
        """Synchronous connection (run in executor)."""
        if self.tls:
            self._ftp = ftplib.FTP_TLS(timeout=self.timeout)
        else:
            self._ftp = ftplib.FTP(timeout=self.timeout)

        self._ftp.connect(self.host, self.port)
        self._ftp.login(self.username, self.password)

        if self.tls:
            self._ftp.prot_p()  # Enable data encryption

        self._ftp.set_pasv(self.passive)
        logger.info(f"Connected to FTP server {self.host}:{self.port}")

    async def disconnect(self) -> None:
        """Disconnect from FTP server."""
        if self._ftp:
            loop = asyncio.get_event_loop()
            try:
                await loop.run_in_executor(None, self._ftp.quit)
            except Exception:
                try:
                    await loop.run_in_executor(None, self._ftp.close)
                except Exception:
                    pass
            self._ftp = None
            logger.info("Disconnected from FTP server")

    async def list_files(self, path: str = "/") -> list[SourceFile]:
        """List files in a directory."""
        if not self._ftp:
            raise ConnectionError("Not connected to FTP server")

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._list_files_sync, path)

    def _list_files_sync(self, path: str) -> list[SourceFile]:
        """Synchronous file listing."""
        files = []

        # Try MLSD first (more detailed)
        try:
            for name, facts in self._ftp.mlsd(path):
                if name in (".", ".."):
                    continue

                is_dir = facts.get("type") == "dir"
                size = int(facts.get("size", 0)) if not is_dir else 0

                # Parse modify time
                modify = facts.get("modify")
                modified_time = None
                if modify:
                    try:
                        modified_time = datetime.strptime(modify, "%Y%m%d%H%M%S")
                    except ValueError:
                        pass

                files.append(
                    SourceFile(
                        name=name,
                        path=f"{path.rstrip('/')}/{name}",
                        size=size,
                        is_directory=is_dir,
                        modified_time=modified_time,
                        permissions=facts.get("perm"),
                    )
                )
            return files

        except ftplib.error_perm:
            # Fall back to LIST parsing
            pass

        # Parse LIST output
        lines: list[str] = []
        self._ftp.retrlines(f"LIST {path}", lines.append)

        for line in lines:
            parsed = self._parse_list_line(line, path)
            if parsed:
                files.append(parsed)

        return files

    def _parse_list_line(self, line: str, base_path: str) -> SourceFile | None:
        """Parse a LIST output line (Unix format)."""
        # Example: drwxr-xr-x  2 user group 4096 Jan  1 12:00 dirname
        #          -rw-r--r--  1 user group 1234 Jan  1 12:00 filename
        parts = line.split(None, 8)
        if len(parts) < 9:
            return None

        permissions = parts[0]
        size = int(parts[4]) if parts[4].isdigit() else 0
        name = parts[8]

        if name in (".", ".."):
            return None

        is_dir = permissions.startswith("d")

        return SourceFile(
            name=name,
            path=f"{base_path.rstrip('/')}/{name}",
            size=size,
            is_directory=is_dir,
            permissions=permissions,
        )

    async def download(
        self,
        remote_path: str,
        local_path: Path,
        progress_callback: ProgressCallback | None = None,
    ) -> Path:
        """Download a file from FTP server."""
        if not self._ftp:
            raise ConnectionError("Not connected to FTP server")

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._download_sync, remote_path, local_path, progress_callback
        )

    def _download_sync(
        self,
        remote_path: str,
        local_path: Path,
        progress_callback: ProgressCallback | None,
    ) -> Path:
        """Synchronous download."""
        # Get file size for progress
        try:
            total_size = self._ftp.size(remote_path) or 0
        except Exception:
            total_size = 0

        local_path.parent.mkdir(parents=True, exist_ok=True)
        transferred = 0

        def callback(data: bytes) -> None:
            nonlocal transferred
            f.write(data)
            transferred += len(data)
            if progress_callback and total_size > 0:
                progress_callback(transferred, total_size)

        with open(local_path, "wb") as f:
            self._ftp.retrbinary(f"RETR {remote_path}", callback)

        logger.info(f"Downloaded {remote_path} to {local_path}")
        return local_path

    async def get_file_info(self, path: str) -> SourceFile | None:
        """Get information about a specific file."""
        if not self._ftp:
            raise ConnectionError("Not connected to FTP server")

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._get_file_info_sync, path)

    def _get_file_info_sync(self, path: str) -> SourceFile | None:
        """Synchronous file info retrieval."""
        # Get parent directory and filename
        if "/" in path:
            parent = "/".join(path.rsplit("/", 1)[:-1]) or "/"
            name = path.rsplit("/", 1)[-1]
        else:
            parent = "/"
            name = path

        # Try MLSD on parent
        try:
            for entry_name, facts in self._ftp.mlsd(parent):
                if entry_name == name:
                    is_dir = facts.get("type") == "dir"
                    size = int(facts.get("size", 0)) if not is_dir else 0
                    return SourceFile(
                        name=name,
                        path=path,
                        size=size,
                        is_directory=is_dir,
                    )
        except ftplib.error_perm:
            pass

        # Fall back to SIZE command for files
        try:
            size = self._ftp.size(path)
            if size is not None:
                return SourceFile(
                    name=name,
                    path=path,
                    size=size,
                    is_directory=False,
                )
        except ftplib.error_perm:
            pass

        return None
