"""
Torrent client implementations using unified libraries.

Supports:
- qBittorrent (via libtc)
- Transmission (via libtc)
- Deluge (via libtc)
- rTorrent (via libtc)
- aria2 (via aria2p) - also handles HTTP/FTP downloads
- Embedded libtorrent (via torrentp) - no external daemon needed
"""

import asyncio
import hashlib
import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class TorrentState(str, Enum):
    """Torrent download states."""

    QUEUED = "queued"
    CHECKING = "checking"
    DOWNLOADING = "downloading"
    PAUSED = "paused"
    SEEDING = "seeding"
    COMPLETED = "completed"
    ERROR = "error"
    UNKNOWN = "unknown"


@dataclass
class TorrentStatus:
    """Status information for a torrent."""

    hash: str
    name: str
    state: TorrentState
    progress: float  # 0.0 to 1.0
    size: int  # bytes
    downloaded: int  # bytes
    upload_speed: int  # bytes/sec
    download_speed: int  # bytes/sec
    eta: int  # seconds, -1 if unknown
    seeds: int
    peers: int
    save_path: Path


class FilePriority(int, Enum):
    """File download priority levels."""

    SKIP = 0  # Don't download
    LOW = 1
    NORMAL = 4
    HIGH = 7


@dataclass
class TorrentFile:
    """Information about a file within a torrent."""

    index: int  # File index within torrent
    name: str  # File name
    path: str  # Full path within torrent
    size: int  # Size in bytes
    progress: float  # Download progress 0.0 to 1.0
    priority: FilePriority  # Download priority
    downloaded: int = 0  # Bytes downloaded

    @property
    def is_selected(self) -> bool:
        """Check if file is selected for download."""
        return self.priority != FilePriority.SKIP


class TorrentClient(ABC):
    """Abstract base class for torrent clients."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the name of this client."""
        ...

    @abstractmethod
    async def is_available(self) -> bool:
        """Check if this client is available."""
        ...

    @abstractmethod
    async def add_torrent(
        self,
        source: str,
        save_path: Path | None = None,
        category: str | None = None,
    ) -> str:
        """
        Add a torrent from file path, URL, or magnet link.

        Returns:
            Torrent hash or ID
        """
        ...

    @abstractmethod
    async def get_status(self, torrent_id: str) -> TorrentStatus | None:
        """Get status of a torrent by hash/ID."""
        ...

    @abstractmethod
    async def list_torrents(self, category: str | None = None) -> list[TorrentStatus]:
        """List all torrents, optionally filtered by category."""
        ...

    @abstractmethod
    async def pause(self, torrent_id: str) -> bool:
        """Pause a torrent."""
        ...

    @abstractmethod
    async def resume(self, torrent_id: str) -> bool:
        """Resume a paused torrent."""
        ...

    @abstractmethod
    async def remove(self, torrent_id: str, delete_files: bool = False) -> bool:
        """Remove a torrent, optionally deleting files."""
        ...

    async def list_files(self, torrent_id: str) -> list[TorrentFile]:
        """List files within a torrent.

        Args:
            torrent_id: Torrent hash/ID

        Returns:
            List of TorrentFile objects

        Note: Not all clients support this. Default returns empty list.
        """
        return []

    async def set_file_priority(
        self,
        torrent_id: str,
        file_indices: list[int],
        priority: FilePriority,
    ) -> bool:
        """Set download priority for specific files.

        Args:
            torrent_id: Torrent hash/ID
            file_indices: List of file indices to update
            priority: Priority level (SKIP to not download)

        Returns:
            True if successful

        Note: Not all clients support this. Default returns False.
        """
        return False

    async def select_files(
        self,
        torrent_id: str,
        patterns: list[str] | None = None,
        extensions: list[str] | None = None,
    ) -> int:
        """Select files to download based on patterns or extensions.

        Args:
            torrent_id: Torrent hash/ID
            patterns: Glob patterns to match (e.g., ["*.mkv", "*.mp4"])
            extensions: File extensions to include (e.g., ["mkv", "mp4"])

        Returns:
            Number of files selected

        Note: Sets non-matching files to SKIP priority.
        """
        import fnmatch

        files = await self.list_files(torrent_id)
        if not files:
            return 0

        selected = []
        skipped = []

        for f in files:
            matches = False

            if patterns:
                for pattern in patterns:
                    if fnmatch.fnmatch(f.name, pattern) or fnmatch.fnmatch(f.path, pattern):
                        matches = True
                        break

            if extensions and not matches:
                ext = f.name.rsplit(".", 1)[-1].lower() if "." in f.name else ""
                if ext in [e.lower().lstrip(".") for e in extensions]:
                    matches = True

            if not patterns and not extensions:
                matches = True

            if matches:
                selected.append(f.index)
            else:
                skipped.append(f.index)

        # Skip non-matching files
        if skipped:
            await self.set_file_priority(torrent_id, skipped, FilePriority.SKIP)

        # Ensure selected files are normal priority
        if selected:
            await self.set_file_priority(torrent_id, selected, FilePriority.NORMAL)

        return len(selected)

    def _extract_hash_from_magnet(self, magnet: str) -> str:
        """Extract info hash from magnet link."""
        match = re.search(r"xt=urn:btih:([a-fA-F0-9]{40}|[a-zA-Z2-7]{32})", magnet)
        if match:
            hash_val = match.group(1)
            if len(hash_val) == 32:
                import base64
                hash_val = base64.b32decode(hash_val.upper()).hex()
            return hash_val.lower()
        return ""


# =============================================================================
# LibTC-based Client (qBittorrent, Transmission, Deluge, rTorrent)
# =============================================================================


class LibTCClient(TorrentClient):
    """
    Unified client using libtc library.

    Supports: qBittorrent, Transmission, Deluge, rTorrent

    Connection URL formats:
    - qBittorrent: qbittorrent+http://user:pass@host:8080
    - Transmission: transmission+http://host:9091/transmission/rpc
    - Deluge: deluge://user:pass@host:58846
    - rTorrent: rtorrent+scgi:///path/to/socket or rtorrent+http://host:8000/RPC2
    """

    def __init__(self, url: str, session_path: str | None = None):
        """
        Initialize LibTC client.

        Args:
            url: Connection URL (see class docstring for formats)
            session_path: Path to client's session/config directory
        """
        self.url = url
        self.session_path = session_path
        self._client = None
        self._available: bool | None = None
        self._client_type = self._parse_client_type(url)

    def _parse_client_type(self, url: str) -> str:
        """Extract client type from URL."""
        if url.startswith("qbittorrent"):
            return "qBittorrent"
        elif url.startswith("transmission"):
            return "Transmission"
        elif url.startswith("deluge"):
            return "Deluge"
        elif url.startswith("rtorrent"):
            return "rTorrent"
        return "Unknown"

    @property
    def name(self) -> str:
        return f"LibTC ({self._client_type})"

    async def is_available(self) -> bool:
        if self._available is not None:
            return self._available

        try:
            from libtc import parse_clients_from_url

            clients = parse_clients_from_url(self.url)
            if clients:
                self._client = clients[0]
                # Test connection by listing torrents
                list(self._client.list())
                self._available = True
                logger.debug(f"{self._client_type} available via libtc")
            else:
                self._available = False
        except Exception as e:
            logger.debug(f"LibTC client not available: {e}")
            self._available = False

        return self._available

    def _get_client(self):
        if self._client is None:
            from libtc import parse_clients_from_url

            clients = parse_clients_from_url(self.url)
            if not clients:
                raise RuntimeError(f"Failed to parse client URL: {self.url}")
            self._client = clients[0]
        return self._client

    def _map_state(self, libtc_state: str) -> TorrentState:
        """Map libtc state to TorrentState."""
        state_lower = libtc_state.lower() if libtc_state else ""
        if "download" in state_lower:
            return TorrentState.DOWNLOADING
        elif "seed" in state_lower or "upload" in state_lower:
            return TorrentState.SEEDING
        elif "pause" in state_lower or "stop" in state_lower:
            return TorrentState.PAUSED
        elif "check" in state_lower:
            return TorrentState.CHECKING
        elif "queue" in state_lower:
            return TorrentState.QUEUED
        elif "error" in state_lower:
            return TorrentState.ERROR
        elif "complete" in state_lower or "finish" in state_lower:
            return TorrentState.COMPLETED
        return TorrentState.UNKNOWN

    def _torrent_to_status(self, t) -> TorrentStatus:
        """Convert libtc torrent to TorrentStatus."""
        state = self._map_state(getattr(t, 'state', '') or '')

        # Check if completed based on progress
        progress = getattr(t, 'progress', 0) or 0
        if progress >= 1.0 and state in (TorrentState.PAUSED, TorrentState.SEEDING):
            state = TorrentState.COMPLETED

        return TorrentStatus(
            hash=getattr(t, 'infohash', '') or '',
            name=getattr(t, 'name', '') or 'Unknown',
            state=state,
            progress=progress,
            size=getattr(t, 'size', 0) or 0,
            downloaded=int(progress * (getattr(t, 'size', 0) or 0)),
            upload_speed=getattr(t, 'upload_rate', 0) or 0,
            download_speed=getattr(t, 'download_rate', 0) or 0,
            eta=getattr(t, 'eta', -1) or -1,
            seeds=getattr(t, 'seeders', 0) or 0,
            peers=getattr(t, 'leechers', 0) or 0,
            save_path=Path(getattr(t, 'download_path', '') or '.'),
        )

    async def add_torrent(
        self,
        source: str,
        save_path: Path | None = None,
        category: str | None = None,
    ) -> str:
        client = self._get_client()

        try:
            if source.startswith("magnet:"):
                torrent = client.add(source, download_path=str(save_path) if save_path else None)
                return self._extract_hash_from_magnet(source) or getattr(torrent, 'infohash', '')
            elif source.startswith(("http://", "https://")):
                torrent = client.add(source, download_path=str(save_path) if save_path else None)
                return getattr(torrent, 'infohash', '')
            else:
                # File path
                with open(source, "rb") as f:
                    torrent_data = f.read()
                torrent = client.add(torrent_data, download_path=str(save_path) if save_path else None)
                return getattr(torrent, 'infohash', '')
        except Exception as e:
            logger.error(f"Failed to add torrent: {e}")
            raise

    async def get_status(self, torrent_id: str) -> TorrentStatus | None:
        client = self._get_client()
        try:
            for t in client.list():
                if getattr(t, 'infohash', '').lower() == torrent_id.lower():
                    return self._torrent_to_status(t)
        except Exception as e:
            logger.debug(f"Failed to get torrent status: {e}")
        return None

    async def list_torrents(self, category: str | None = None) -> list[TorrentStatus]:
        client = self._get_client()
        try:
            return [self._torrent_to_status(t) for t in client.list()]
        except Exception as e:
            logger.error(f"Failed to list torrents: {e}")
            return []

    async def pause(self, torrent_id: str) -> bool:
        try:
            client = self._get_client()
            for t in client.list():
                if getattr(t, 'infohash', '').lower() == torrent_id.lower():
                    t.stop()
                    return True
            return False
        except Exception as e:
            logger.error(f"Failed to pause torrent: {e}")
            return False

    async def resume(self, torrent_id: str) -> bool:
        try:
            client = self._get_client()
            for t in client.list():
                if getattr(t, 'infohash', '').lower() == torrent_id.lower():
                    t.start()
                    return True
            return False
        except Exception as e:
            logger.error(f"Failed to resume torrent: {e}")
            return False

    async def remove(self, torrent_id: str, delete_files: bool = False) -> bool:
        try:
            client = self._get_client()
            for t in client.list():
                if getattr(t, 'infohash', '').lower() == torrent_id.lower():
                    t.remove(delete_files=delete_files)
                    return True
            return False
        except Exception as e:
            logger.error(f"Failed to remove torrent: {e}")
            return False


# Convenience classes for common clients
class QBittorrentClient(TorrentClient):
    """qBittorrent client via libtc."""

    def __init__(
        self,
        host: str = "localhost",
        port: int = 8080,
        username: str = "admin",
        password: str = "adminadmin",
        use_https: bool = False,
    ):
        protocol = "https" if use_https else "http"
        self.url = f"{protocol}://{host}:{port}"
        self.username = username
        self.password = password
        self._client = None
        self._available: bool | None = None

    @property
    def name(self) -> str:
        return "qBittorrent"

    def _get_client(self):
        if self._client is None:
            from libtc import QBittorrentClient as LibTCQBittorrent
            self._client = LibTCQBittorrent(
                url=self.url,
                username=self.username,
                password=self.password,
            )
        return self._client

    async def is_available(self) -> bool:
        if self._available is not None:
            return self._available
        try:
            client = self._get_client()
            list(client.list())  # Test connection
            self._available = True
        except Exception as e:
            logger.debug(f"qBittorrent not available: {e}")
            self._available = False
        return self._available

    def _map_state(self, state_str: str) -> TorrentState:
        state_lower = (state_str or "").lower()
        if "download" in state_lower:
            return TorrentState.DOWNLOADING
        elif "seed" in state_lower or "upload" in state_lower:
            return TorrentState.SEEDING
        elif "pause" in state_lower or "stop" in state_lower:
            return TorrentState.PAUSED
        elif "check" in state_lower:
            return TorrentState.CHECKING
        elif "queue" in state_lower:
            return TorrentState.QUEUED
        elif "error" in state_lower:
            return TorrentState.ERROR
        return TorrentState.UNKNOWN

    def _torrent_to_status(self, t) -> TorrentStatus:
        state = self._map_state(str(getattr(t, 'state', '')))
        progress = getattr(t, 'progress', 0) or 0
        if progress >= 1.0:
            state = TorrentState.COMPLETED
        return TorrentStatus(
            hash=getattr(t, 'infohash', '') or '',
            name=getattr(t, 'name', '') or 'Unknown',
            state=state,
            progress=progress,
            size=getattr(t, 'size', 0) or 0,
            downloaded=int(progress * (getattr(t, 'size', 0) or 0)),
            upload_speed=getattr(t, 'upload_rate', 0) or 0,
            download_speed=getattr(t, 'download_rate', 0) or 0,
            eta=getattr(t, 'eta', -1) or -1,
            seeds=getattr(t, 'seeders', 0) or 0,
            peers=getattr(t, 'leechers', 0) or 0,
            save_path=Path(getattr(t, 'download_path', '') or '.'),
        )

    async def add_torrent(self, source: str, save_path: Path | None = None, category: str | None = None) -> str:
        client = self._get_client()
        try:
            if source.startswith("magnet:"):
                torrent = client.add(source, download_path=str(save_path) if save_path else None)
                return self._extract_hash_from_magnet(source) or getattr(torrent, 'infohash', '')
            elif source.startswith(("http://", "https://")):
                torrent = client.add(source, download_path=str(save_path) if save_path else None)
                return getattr(torrent, 'infohash', '')
            else:
                with open(source, "rb") as f:
                    torrent_data = f.read()
                torrent = client.add(torrent_data, download_path=str(save_path) if save_path else None)
                return getattr(torrent, 'infohash', '')
        except Exception as e:
            logger.error(f"Failed to add torrent: {e}")
            raise

    async def get_status(self, torrent_id: str) -> TorrentStatus | None:
        client = self._get_client()
        try:
            for t in client.list():
                if getattr(t, 'infohash', '').lower() == torrent_id.lower():
                    return self._torrent_to_status(t)
        except Exception as e:
            logger.debug(f"Failed to get torrent status: {e}")
        return None

    async def list_torrents(self, category: str | None = None) -> list[TorrentStatus]:
        client = self._get_client()
        try:
            return [self._torrent_to_status(t) for t in client.list()]
        except Exception as e:
            logger.error(f"Failed to list torrents: {e}")
            return []

    async def pause(self, torrent_id: str) -> bool:
        try:
            client = self._get_client()
            for t in client.list():
                if getattr(t, 'infohash', '').lower() == torrent_id.lower():
                    t.stop()
                    return True
        except Exception as e:
            logger.error(f"Failed to pause torrent: {e}")
        return False

    async def resume(self, torrent_id: str) -> bool:
        try:
            client = self._get_client()
            for t in client.list():
                if getattr(t, 'infohash', '').lower() == torrent_id.lower():
                    t.start()
                    return True
        except Exception as e:
            logger.error(f"Failed to resume torrent: {e}")
        return False

    async def remove(self, torrent_id: str, delete_files: bool = False) -> bool:
        try:
            client = self._get_client()
            for t in client.list():
                if getattr(t, 'infohash', '').lower() == torrent_id.lower():
                    t.remove(delete_files=delete_files)
                    return True
        except Exception as e:
            logger.error(f"Failed to remove torrent: {e}")
        return False

    async def list_files(self, torrent_id: str) -> list[TorrentFile]:
        """List files in a torrent (qBittorrent specific)."""
        try:
            client = self._get_client()
            for t in client.list():
                if getattr(t, 'infohash', '').lower() == torrent_id.lower():
                    files = []
                    # Access qBittorrent's files API
                    raw_client = getattr(client, '_client', None)
                    if raw_client and hasattr(raw_client, 'torrents_files'):
                        file_list = raw_client.torrents_files(torrent_id)
                        for i, f in enumerate(file_list):
                            files.append(TorrentFile(
                                index=i,
                                name=Path(f.get('name', '')).name,
                                path=f.get('name', ''),
                                size=f.get('size', 0),
                                progress=f.get('progress', 0),
                                priority=FilePriority(f.get('priority', 4)),
                                downloaded=int(f.get('progress', 0) * f.get('size', 0)),
                            ))
                    return files
        except Exception as e:
            logger.debug(f"Failed to list torrent files: {e}")
        return []

    async def set_file_priority(
        self,
        torrent_id: str,
        file_indices: list[int],
        priority: FilePriority,
    ) -> bool:
        """Set file priority (qBittorrent specific)."""
        try:
            client = self._get_client()
            raw_client = getattr(client, '_client', None)
            if raw_client and hasattr(raw_client, 'torrents_file_priority'):
                raw_client.torrents_file_priority(
                    torrent_id,
                    file_ids=file_indices,
                    priority=priority.value,
                )
                return True
        except Exception as e:
            logger.error(f"Failed to set file priority: {e}")
        return False


class TransmissionClient(LibTCClient):
    """Transmission client via libtc."""

    def __init__(
        self,
        host: str = "localhost",
        port: int = 9091,
        username: str | None = None,
        password: str | None = None,
        path: str = "/transmission/rpc",
    ):
        auth = f"{username}:{password}@" if username else ""
        url = f"transmission+http://{auth}{host}:{port}{path}"
        super().__init__(url)


class DelugeClient(LibTCClient):
    """Deluge client via libtc."""

    def __init__(
        self,
        host: str = "localhost",
        port: int = 58846,
        username: str = "localclient",
        password: str = "",
    ):
        url = f"deluge://{username}:{password}@{host}:{port}"
        super().__init__(url)


class RTorrentClient(LibTCClient):
    """rTorrent client via libtc."""

    def __init__(
        self,
        # Socket connection (preferred)
        socket_path: str | None = None,
        # Or HTTP/SCGI connection
        host: str = "localhost",
        port: int = 8000,
        path: str = "/RPC2",
        use_scgi: bool = False,
    ):
        if socket_path:
            url = f"rtorrent+scgi://{socket_path}"
        elif use_scgi:
            url = f"rtorrent+scgi://{host}:{port}"
        else:
            url = f"rtorrent+http://{host}:{port}{path}"
        super().__init__(url)


# =============================================================================
# aria2 Client (also handles HTTP/FTP)
# =============================================================================


class Aria2Client(TorrentClient):
    """
    aria2 client via aria2p.

    aria2 is a lightweight multi-protocol download utility that supports:
    - HTTP/HTTPS
    - FTP
    - BitTorrent
    - Metalink

    This makes it useful as both a torrent client AND a general download manager.
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 6800,
        secret: str = "",
    ):
        self.host = host
        self.port = port
        self.secret = secret
        self._api = None
        self._available: bool | None = None

    @property
    def name(self) -> str:
        return "aria2"

    async def is_available(self) -> bool:
        if self._available is not None:
            return self._available

        try:
            import aria2p

            client = aria2p.Client(
                host=f"http://{self.host}",
                port=self.port,
                secret=self.secret,
            )
            api = aria2p.API(client)
            # Test connection
            api.get_global_stat()
            self._api = api
            self._available = True
            logger.debug(f"aria2 available at {self.host}:{self.port}")
        except Exception as e:
            logger.debug(f"aria2 not available: {e}")
            self._available = False

        return self._available

    def _get_api(self):
        if self._api is None:
            import aria2p

            client = aria2p.Client(
                host=f"http://{self.host}",
                port=self.port,
                secret=self.secret,
            )
            self._api = aria2p.API(client)
        return self._api

    def _map_state(self, status: str) -> TorrentState:
        """Map aria2 status to TorrentState."""
        status_map = {
            "active": TorrentState.DOWNLOADING,
            "waiting": TorrentState.QUEUED,
            "paused": TorrentState.PAUSED,
            "error": TorrentState.ERROR,
            "complete": TorrentState.COMPLETED,
            "removed": TorrentState.UNKNOWN,
        }
        return status_map.get(status, TorrentState.UNKNOWN)

    def _download_to_status(self, d) -> TorrentStatus:
        """Convert aria2p Download to TorrentStatus."""
        state = self._map_state(d.status)

        # Calculate progress
        total = d.total_length
        completed = d.completed_length
        progress = completed / total if total > 0 else 0.0

        return TorrentStatus(
            hash=d.gid,  # aria2 uses GID, not info hash
            name=d.name or "Unknown",
            state=state,
            progress=progress,
            size=total,
            downloaded=completed,
            upload_speed=d.upload_speed,
            download_speed=d.download_speed,
            eta=int(d.eta.total_seconds()) if d.eta else -1,
            seeds=d.connections,  # aria2 reports connections, not seeds specifically
            peers=d.connections,
            save_path=Path(d.dir),
        )

    async def add_torrent(
        self,
        source: str,
        save_path: Path | None = None,
        category: str | None = None,
    ) -> str:
        api = self._get_api()

        options = {}
        if save_path:
            options["dir"] = str(save_path)

        try:
            if source.startswith("magnet:"):
                downloads = api.add_magnet(source, options=options)
            elif source.startswith(("http://", "https://", "ftp://")):
                # aria2 can handle HTTP/FTP URLs too!
                downloads = api.add_uris([source], options=options)
            else:
                # Torrent file
                downloads = api.add_torrent(source, options=options)

            if downloads:
                return downloads[0].gid
            return ""
        except Exception as e:
            logger.error(f"Failed to add to aria2: {e}")
            raise

    async def get_status(self, torrent_id: str) -> TorrentStatus | None:
        api = self._get_api()
        try:
            download = api.get_download(torrent_id)
            if download:
                return self._download_to_status(download)
        except Exception as e:
            logger.debug(f"Failed to get aria2 download status: {e}")
        return None

    async def list_torrents(self, category: str | None = None) -> list[TorrentStatus]:
        api = self._get_api()
        try:
            downloads = api.get_downloads()
            return [self._download_to_status(d) for d in downloads]
        except Exception as e:
            logger.error(f"Failed to list aria2 downloads: {e}")
            return []

    async def pause(self, torrent_id: str) -> bool:
        try:
            api = self._get_api()
            download = api.get_download(torrent_id)
            if download:
                download.pause()
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to pause aria2 download: {e}")
            return False

    async def resume(self, torrent_id: str) -> bool:
        try:
            api = self._get_api()
            download = api.get_download(torrent_id)
            if download:
                download.resume()
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to resume aria2 download: {e}")
            return False

    async def remove(self, torrent_id: str, delete_files: bool = False) -> bool:
        try:
            api = self._get_api()
            download = api.get_download(torrent_id)
            if download:
                download.remove(force=True, files=delete_files)
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to remove aria2 download: {e}")
            return False

    # aria2-specific methods for HTTP/FTP downloads
    async def add_http_download(
        self,
        url: str,
        save_path: Path | None = None,
        filename: str | None = None,
    ) -> str:
        """Add an HTTP/HTTPS/FTP download (aria2's specialty)."""
        api = self._get_api()

        options = {}
        if save_path:
            options["dir"] = str(save_path)
        if filename:
            options["out"] = filename

        downloads = api.add_uris([url], options=options)
        return downloads[0].gid if downloads else ""


# =============================================================================
# Embedded Client (libtorrent via torrentp)
# =============================================================================


class EmbeddedTorrentClient(TorrentClient):
    """
    Embedded torrent client using torrentp (libtorrent wrapper).

    No external daemon required - runs in-process.
    """

    def __init__(self, download_dir: Path | None = None):
        self.download_dir = download_dir or Path.cwd() / "downloads" / "torrents"
        self.download_dir.mkdir(parents=True, exist_ok=True)
        self._sessions: dict[str, dict[str, Any]] = {}
        self._available: bool | None = None

    @property
    def name(self) -> str:
        return "Embedded (libtorrent)"

    async def is_available(self) -> bool:
        if self._available is not None:
            return self._available

        try:
            import torrentp
            self._available = True
            logger.debug("Embedded torrent client available")
        except ImportError:
            self._available = False
            logger.debug("torrentp not installed")

        return self._available

    async def add_torrent(
        self,
        source: str,
        save_path: Path | None = None,
        category: str | None = None,
    ) -> str:
        from torrentp import TorrentDownloader

        dest = save_path or self.download_dir
        if category:
            dest = dest / category
        dest.mkdir(parents=True, exist_ok=True)

        downloader = TorrentDownloader(source, str(dest))

        # Generate ID for tracking
        if source.startswith("magnet:"):
            torrent_id = self._extract_hash_from_magnet(source)
        else:
            torrent_id = hashlib.md5(source.encode()).hexdigest()

        self._sessions[torrent_id] = {
            "downloader": downloader,
            "source": source,
            "save_path": dest,
            "started": False,
            "completed": False,
            "error": None,
        }

        # Start download in background
        asyncio.create_task(self._download_task(torrent_id))

        return torrent_id

    async def _download_task(self, torrent_id: str) -> None:
        """Background download task."""
        session = self._sessions.get(torrent_id)
        if not session:
            return

        try:
            session["started"] = True
            downloader = session["downloader"]
            await downloader.start_download()
            session["completed"] = True
        except Exception as e:
            logger.error(f"Download error for {torrent_id}: {e}")
            session["error"] = str(e)

    async def get_status(self, torrent_id: str) -> TorrentStatus | None:
        session = self._sessions.get(torrent_id)
        if not session:
            return None

        state = TorrentState.QUEUED
        if session.get("error"):
            state = TorrentState.ERROR
        elif session["completed"]:
            state = TorrentState.COMPLETED
        elif session["started"]:
            state = TorrentState.DOWNLOADING

        return TorrentStatus(
            hash=torrent_id,
            name=Path(session["source"]).name if not session["source"].startswith("magnet:") else "Magnet download",
            state=state,
            progress=1.0 if session["completed"] else 0.5 if session["started"] else 0.0,
            size=0,
            downloaded=0,
            upload_speed=0,
            download_speed=0,
            eta=-1,
            seeds=0,
            peers=0,
            save_path=session["save_path"],
        )

    async def list_torrents(self, category: str | None = None) -> list[TorrentStatus]:
        statuses = []
        for torrent_id in self._sessions:
            status = await self.get_status(torrent_id)
            if status:
                if category is None or category in str(status.save_path):
                    statuses.append(status)
        return statuses

    async def pause(self, torrent_id: str) -> bool:
        logger.warning("Pause not fully supported for embedded client")
        return False

    async def resume(self, torrent_id: str) -> bool:
        logger.warning("Resume not fully supported for embedded client")
        return False

    async def remove(self, torrent_id: str, delete_files: bool = False) -> bool:
        session = self._sessions.get(torrent_id)
        if not session:
            return False

        try:
            if delete_files:
                import shutil
                save_path = session["save_path"]
                if save_path.exists():
                    shutil.rmtree(save_path, ignore_errors=True)

            del self._sessions[torrent_id]
            return True
        except Exception as e:
            logger.error(f"Failed to remove: {e}")
            return False


# =============================================================================
# Client Factory / Auto-detection
# =============================================================================


async def detect_available_clients(
    # qBittorrent
    qb_host: str = "localhost",
    qb_port: int = 8080,
    qb_user: str = "admin",
    qb_pass: str = "adminadmin",
    # Transmission
    transmission_host: str = "localhost",
    transmission_port: int = 9091,
    # Deluge
    deluge_host: str = "localhost",
    deluge_port: int = 58846,
    # rTorrent
    rtorrent_socket: str | None = None,
    rtorrent_host: str = "localhost",
    rtorrent_port: int = 8000,
    # aria2
    aria2_host: str = "localhost",
    aria2_port: int = 6800,
    aria2_secret: str = "",
    # Embedded
    download_dir: Path | None = None,
) -> list[TorrentClient]:
    """
    Detect all available torrent clients.

    Returns list of available clients, ordered by preference.
    """
    clients: list[TorrentClient] = [
        QBittorrentClient(host=qb_host, port=qb_port, username=qb_user, password=qb_pass),
        TransmissionClient(host=transmission_host, port=transmission_port),
        DelugeClient(host=deluge_host, port=deluge_port),
        Aria2Client(host=aria2_host, port=aria2_port, secret=aria2_secret),
    ]

    # Add rTorrent if socket specified
    if rtorrent_socket:
        clients.append(RTorrentClient(socket_path=rtorrent_socket))
    else:
        clients.append(RTorrentClient(host=rtorrent_host, port=rtorrent_port))

    # Always add embedded as fallback
    clients.append(EmbeddedTorrentClient(download_dir=download_dir))

    available = []
    for client in clients:
        try:
            if await client.is_available():
                available.append(client)
                logger.info(f"Found available client: {client.name}")
        except Exception as e:
            logger.debug(f"Client {client.name} not available: {e}")

    return available


async def get_available_client(**kwargs) -> TorrentClient:
    """
    Get the first available torrent client.

    Raises:
        RuntimeError: If no torrent client is available
    """
    clients = await detect_available_clients(**kwargs)

    if not clients:
        raise RuntimeError(
            "No torrent client available. Please start one of:\n"
            "  - qBittorrent (port 8080)\n"
            "  - Transmission (port 9091)\n"
            "  - Deluge (port 58846)\n"
            "  - rTorrent (SCGI socket or port 8000)\n"
            "  - aria2 with --enable-rpc (port 6800)\n"
            "Or the embedded client will be used as fallback."
        )

    logger.info(f"Using torrent client: {clients[0].name}")
    return clients[0]
