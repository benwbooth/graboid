"""SFTP source protocol implementation using paramiko."""

import asyncio
import logging
import stat
from datetime import datetime
from pathlib import Path

from .base import ProgressCallback, SourceFile, SourceProtocol

logger = logging.getLogger(__name__)


class SFTPSource(SourceProtocol):
    """SFTP source using paramiko."""

    def __init__(
        self,
        host: str,
        port: int = 22,
        username: str | None = None,
        password: str | None = None,
        key_filename: str | None = None,
        key_password: str | None = None,
        timeout: float = 30.0,
    ):
        """Initialize SFTP source.

        Args:
            host: SSH server hostname
            port: SSH port (default 22)
            username: Username
            password: Password (if not using key)
            key_filename: Path to private key file
            key_password: Passphrase for private key
            timeout: Connection timeout in seconds
        """
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.key_filename = key_filename
        self.key_password = key_password
        self.timeout = timeout
        self._transport = None
        self._sftp = None

    async def connect(self) -> None:
        """Connect to SFTP server."""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._connect_sync)

    def _connect_sync(self) -> None:
        """Synchronous connection."""
        import paramiko

        self._transport = paramiko.Transport((self.host, self.port))

        # Authenticate
        if self.key_filename:
            # Load private key
            try:
                key = paramiko.RSAKey.from_private_key_file(
                    self.key_filename, password=self.key_password
                )
            except paramiko.ssh_exception.SSHException:
                try:
                    key = paramiko.Ed25519Key.from_private_key_file(
                        self.key_filename, password=self.key_password
                    )
                except paramiko.ssh_exception.SSHException:
                    key = paramiko.ECDSAKey.from_private_key_file(
                        self.key_filename, password=self.key_password
                    )

            self._transport.connect(username=self.username, pkey=key)
        else:
            self._transport.connect(username=self.username, password=self.password)

        self._sftp = paramiko.SFTPClient.from_transport(self._transport)
        logger.info(f"Connected to SFTP server {self.host}:{self.port}")

    async def disconnect(self) -> None:
        """Disconnect from SFTP server."""
        if self._sftp:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._sftp.close)
            self._sftp = None

        if self._transport:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._transport.close)
            self._transport = None

        logger.info("Disconnected from SFTP server")

    async def list_files(self, path: str = "/") -> list[SourceFile]:
        """List files in a directory."""
        if not self._sftp:
            raise ConnectionError("Not connected to SFTP server")

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._list_files_sync, path)

    def _list_files_sync(self, path: str) -> list[SourceFile]:
        """Synchronous file listing."""
        files = []

        for attr in self._sftp.listdir_attr(path):
            if attr.filename in (".", ".."):
                continue

            is_dir = stat.S_ISDIR(attr.st_mode or 0)
            size = attr.st_size or 0 if not is_dir else 0

            # Parse permissions
            mode = attr.st_mode or 0
            permissions = stat.filemode(mode)

            # Parse modify time
            modified_time = None
            if attr.st_mtime:
                modified_time = datetime.fromtimestamp(attr.st_mtime)

            files.append(
                SourceFile(
                    name=attr.filename,
                    path=f"{path.rstrip('/')}/{attr.filename}",
                    size=size,
                    is_directory=is_dir,
                    modified_time=modified_time,
                    permissions=permissions,
                )
            )

        return files

    async def download(
        self,
        remote_path: str,
        local_path: Path,
        progress_callback: ProgressCallback | None = None,
    ) -> Path:
        """Download a file from SFTP server."""
        if not self._sftp:
            raise ConnectionError("Not connected to SFTP server")

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
        local_path.parent.mkdir(parents=True, exist_ok=True)

        # Get file size
        try:
            attrs = self._sftp.stat(remote_path)
            total_size = attrs.st_size or 0
        except Exception:
            total_size = 0

        # Create progress callback wrapper
        def callback(transferred: int, total: int) -> None:
            if progress_callback:
                progress_callback(transferred, total)

        if progress_callback and total_size > 0:
            self._sftp.get(remote_path, str(local_path), callback=callback)
        else:
            self._sftp.get(remote_path, str(local_path))

        logger.info(f"Downloaded {remote_path} to {local_path}")
        return local_path

    async def get_file_info(self, path: str) -> SourceFile | None:
        """Get information about a specific file."""
        if not self._sftp:
            raise ConnectionError("Not connected to SFTP server")

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._get_file_info_sync, path)

    def _get_file_info_sync(self, path: str) -> SourceFile | None:
        """Synchronous file info retrieval."""
        try:
            attrs = self._sftp.stat(path)
        except IOError:
            return None

        name = path.rsplit("/", 1)[-1] if "/" in path else path
        is_dir = stat.S_ISDIR(attrs.st_mode or 0)
        size = attrs.st_size or 0 if not is_dir else 0

        modified_time = None
        if attrs.st_mtime:
            modified_time = datetime.fromtimestamp(attrs.st_mtime)

        return SourceFile(
            name=name,
            path=path,
            size=size,
            is_directory=is_dir,
            modified_time=modified_time,
            permissions=stat.filemode(attrs.st_mode or 0),
        )
