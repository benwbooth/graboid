"""SMB source protocol implementation using smbprotocol."""

import asyncio
import logging
from datetime import datetime
from pathlib import Path

from .base import ProgressCallback, SourceFile, SourceProtocol

logger = logging.getLogger(__name__)


class SMBSource(SourceProtocol):
    """SMB/CIFS source using smbprotocol."""

    def __init__(
        self,
        host: str,
        share: str,
        username: str | None = None,
        password: str | None = None,
        domain: str | None = None,
        port: int = 445,
        encrypt: bool = True,
    ):
        """Initialize SMB source.

        Args:
            host: SMB server hostname
            share: Share name
            username: Username
            password: Password
            domain: Windows domain (optional)
            port: SMB port (default 445)
            encrypt: Require encryption (default True)
        """
        self.host = host
        self.share = share
        self.username = username
        self.password = password
        self.domain = domain
        self.port = port
        self.encrypt = encrypt
        self._session = None
        self._tree = None

    @property
    def _share_path(self) -> str:
        """Get UNC-style share path."""
        return f"\\\\{self.host}\\{self.share}"

    async def connect(self) -> None:
        """Connect to SMB share."""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._connect_sync)

    def _connect_sync(self) -> None:
        """Synchronous connection."""
        from smbprotocol.connection import Connection
        from smbprotocol.session import Session
        from smbprotocol.tree import TreeConnect

        # Register the session
        connection = Connection(uuid=None, server=self.host, port=self.port)
        connection.connect()

        self._session = Session(
            connection, username=self.username, password=self.password
        )
        self._session.connect()

        # Connect to share
        self._tree = TreeConnect(self._session, self._share_path)
        self._tree.connect()

        logger.info(f"Connected to SMB share {self._share_path}")

    async def disconnect(self) -> None:
        """Disconnect from SMB share."""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._disconnect_sync)

    def _disconnect_sync(self) -> None:
        """Synchronous disconnect."""
        if self._tree:
            try:
                self._tree.disconnect()
            except Exception:
                pass
            self._tree = None

        if self._session:
            try:
                self._session.disconnect()
            except Exception:
                pass
            self._session = None

        logger.info("Disconnected from SMB share")

    async def list_files(self, path: str = "/") -> list[SourceFile]:
        """List files in a directory."""
        if not self._tree:
            raise ConnectionError("Not connected to SMB share")

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._list_files_sync, path)

    def _list_files_sync(self, path: str) -> list[SourceFile]:
        """Synchronous file listing."""
        from smbprotocol.open import (
            CreateDisposition,
            CreateOptions,
            DirectoryAccessMask,
            FileAttributes,
            FilePipePrinterAccessMask,
            ImpersonationLevel,
            Open,
            ShareAccess,
        )
        from smbprotocol.file_info import (
            FileDirectoryInformation,
            FileInformationClass,
        )

        # Convert path to Windows format
        smb_path = path.replace("/", "\\").lstrip("\\")
        if not smb_path:
            smb_path = ""

        files = []

        # Open directory
        dir_open = Open(self._tree, smb_path)
        dir_open.create(
            ImpersonationLevel.Impersonation,
            DirectoryAccessMask.FILE_LIST_DIRECTORY | DirectoryAccessMask.FILE_READ_ATTRIBUTES,
            FileAttributes.FILE_ATTRIBUTE_DIRECTORY,
            ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE,
            CreateDisposition.FILE_OPEN,
            CreateOptions.FILE_DIRECTORY_FILE,
        )

        try:
            # Query directory contents
            while True:
                entries = dir_open.query_directory(
                    "*", FileInformationClass.FILE_DIRECTORY_INFORMATION
                )
                if not entries:
                    break

                for entry in entries:
                    name = entry["file_name"].get_value().decode("utf-16-le")
                    if name in (".", ".."):
                        continue

                    attrs = entry["file_attributes"].get_value()
                    is_dir = bool(attrs & FileAttributes.FILE_ATTRIBUTE_DIRECTORY)
                    size = entry["end_of_file"].get_value() if not is_dir else 0

                    # Parse timestamps
                    modified_time = None
                    try:
                        # Windows FILETIME to datetime
                        filetime = entry["last_write_time"].get_value()
                        if filetime:
                            # Convert 100-ns intervals since 1601 to Unix timestamp
                            timestamp = (filetime - 116444736000000000) / 10000000
                            modified_time = datetime.fromtimestamp(timestamp)
                    except Exception:
                        pass

                    full_path = f"{path.rstrip('/')}/{name}"

                    files.append(
                        SourceFile(
                            name=name,
                            path=full_path,
                            size=size,
                            is_directory=is_dir,
                            modified_time=modified_time,
                        )
                    )
        finally:
            dir_open.close()

        return files

    async def download(
        self,
        remote_path: str,
        local_path: Path,
        progress_callback: ProgressCallback | None = None,
    ) -> Path:
        """Download a file from SMB share."""
        if not self._tree:
            raise ConnectionError("Not connected to SMB share")

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
        from smbprotocol.open import (
            CreateDisposition,
            CreateOptions,
            FileAttributes,
            FilePipePrinterAccessMask,
            ImpersonationLevel,
            Open,
            ShareAccess,
        )

        # Convert path
        smb_path = remote_path.replace("/", "\\").lstrip("\\")

        local_path.parent.mkdir(parents=True, exist_ok=True)

        # Open remote file
        file_open = Open(self._tree, smb_path)
        file_open.create(
            ImpersonationLevel.Impersonation,
            FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES,
            FileAttributes.FILE_ATTRIBUTE_NORMAL,
            ShareAccess.FILE_SHARE_READ,
            CreateDisposition.FILE_OPEN,
            CreateOptions.FILE_NON_DIRECTORY_FILE,
        )

        try:
            # Get file size
            file_info = file_open.query_info()
            total_size = file_info.end_of_file

            # Read and write in chunks
            chunk_size = 65536
            transferred = 0

            with open(local_path, "wb") as f:
                while transferred < total_size:
                    read_size = min(chunk_size, total_size - transferred)
                    data = file_open.read(transferred, read_size)
                    f.write(data)
                    transferred += len(data)

                    if progress_callback:
                        progress_callback(transferred, total_size)

        finally:
            file_open.close()

        logger.info(f"Downloaded {remote_path} to {local_path}")
        return local_path

    async def get_file_info(self, path: str) -> SourceFile | None:
        """Get information about a specific file."""
        if not self._tree:
            raise ConnectionError("Not connected to SMB share")

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._get_file_info_sync, path)

    def _get_file_info_sync(self, path: str) -> SourceFile | None:
        """Synchronous file info retrieval."""
        from smbprotocol.open import (
            CreateDisposition,
            CreateOptions,
            FileAttributes,
            FilePipePrinterAccessMask,
            ImpersonationLevel,
            Open,
            ShareAccess,
        )

        smb_path = path.replace("/", "\\").lstrip("\\")
        name = path.rsplit("/", 1)[-1] if "/" in path else path

        try:
            file_open = Open(self._tree, smb_path)
            file_open.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES,
                FileAttributes.FILE_ATTRIBUTE_NORMAL,
                ShareAccess.FILE_SHARE_READ,
                CreateDisposition.FILE_OPEN,
                CreateOptions.FILE_OPEN_REPARSE_POINT,
            )

            try:
                file_info = file_open.query_info()
                is_dir = bool(file_info.file_attributes & FileAttributes.FILE_ATTRIBUTE_DIRECTORY)
                size = file_info.end_of_file if not is_dir else 0

                return SourceFile(
                    name=name,
                    path=path,
                    size=size,
                    is_directory=is_dir,
                )
            finally:
                file_open.close()

        except Exception:
            return None
