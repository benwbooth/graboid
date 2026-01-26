"""
BitTorrent client module with support for multiple clients.

Supported clients:
- qBittorrent (via libtc)
- Transmission (via libtc)
- Deluge (via libtc)
- rTorrent (via libtc)
- aria2 (via aria2p) - also handles HTTP/FTP
- Embedded libtorrent (via torrentp)
"""

from .client import (
    Aria2Client,
    DelugeClient,
    EmbeddedTorrentClient,
    LibTCClient,
    QBittorrentClient,
    RTorrentClient,
    TorrentClient,
    TorrentState,
    TorrentStatus,
    TransmissionClient,
    detect_available_clients,
    get_available_client,
)
from .manager import TorrentManager, download_torrents

__all__ = [
    # Base
    "TorrentClient",
    "TorrentState",
    "TorrentStatus",
    # Clients
    "Aria2Client",
    "DelugeClient",
    "EmbeddedTorrentClient",
    "LibTCClient",
    "QBittorrentClient",
    "RTorrentClient",
    "TransmissionClient",
    # Manager
    "TorrentManager",
    # Utilities
    "detect_available_clients",
    "download_torrents",
    "get_available_client",
]
