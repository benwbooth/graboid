"""Multi-protocol source module for file access."""

from .base import SourceProtocol, SourceFile
from .ftp import FTPSource
from .sftp import SFTPSource
from .smb import SMBSource
from .local import LocalSource

__all__ = [
    "SourceProtocol",
    "SourceFile",
    "FTPSource",
    "SFTPSource",
    "SMBSource",
    "LocalSource",
]


def get_source_for_url(url: str, **kwargs) -> SourceProtocol:
    """Get appropriate source handler for a URL.

    Args:
        url: URL to handle (ftp://, sftp://, smb://, file://)
        **kwargs: Additional arguments passed to source constructor

    Returns:
        Appropriate SourceProtocol implementation
    """
    from urllib.parse import urlparse

    parsed = urlparse(url)
    scheme = parsed.scheme.lower()

    if scheme == "ftp":
        return FTPSource(
            host=parsed.hostname or "localhost",
            port=parsed.port or 21,
            username=parsed.username,
            password=parsed.password,
            **kwargs,
        )
    elif scheme == "sftp":
        return SFTPSource(
            host=parsed.hostname or "localhost",
            port=parsed.port or 22,
            username=parsed.username,
            password=parsed.password,
            **kwargs,
        )
    elif scheme == "smb":
        return SMBSource(
            host=parsed.hostname or "localhost",
            share=parsed.path.split("/")[1] if parsed.path else "",
            username=parsed.username,
            password=parsed.password,
            **kwargs,
        )
    elif scheme in ("file", ""):
        return LocalSource(**kwargs)
    else:
        raise ValueError(f"Unsupported URL scheme: {scheme}")
