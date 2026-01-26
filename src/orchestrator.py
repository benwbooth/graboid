"""Main orchestrator for Graboid - LLM-driven browser automation agent."""

import argparse
import asyncio
import logging
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import tomllib
from pydantic import BaseModel
from pydantic_settings import BaseSettings
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

from .browser import BrowserAgent, DownloadController, get_notes_db
from .torrent import (
    TorrentManager,
    QBittorrentClient,
    TransmissionClient,
    DelugeClient,
    RTorrentClient,
    Aria2Client,
    EmbeddedTorrentClient,
    detect_available_clients,
)

logger = logging.getLogger(__name__)


CONFIG_SEARCH_PATHS = [
    Path.cwd() / "config.toml",
    Path.cwd() / "graboid.toml",
    Path.home() / ".config" / "graboid" / "config.toml",
]


def load_config_file(path: Path | None = None) -> dict[str, Any]:
    """Load configuration from a TOML file."""
    if path:
        paths_to_try = [path]
    else:
        paths_to_try = CONFIG_SEARCH_PATHS

    for config_path in paths_to_try:
        if config_path.exists():
            with open(config_path, "rb") as f:
                data = tomllib.load(f)
            logger.info(f"Loaded config from {config_path}")
            return data

    return {}


class Config(BaseSettings):
    """Application configuration.

    Configuration is loaded from (in order of priority, highest first):
    1. CLI arguments
    2. Environment variables (prefixed with GRABOID_)
    3. TOML config file (config.toml, graboid.toml, or ~/.config/graboid/config.toml)
    4. Default values
    """

    model_config = {"env_prefix": "GRABOID_"}

    # Paths
    download_dir: Path = Path.cwd() / "downloads"

    # LLM settings
    llm_provider: str = "claude_code"  # claude_code, anthropic, openai, ollama, etc.
    llm_model: str = "sonnet"  # Model name or alias
    ollama_model: str = "llama3.2"
    ollama_host: str = "http://localhost:11434"
    claude_model: str = "claude-sonnet-4-20250514"
    prefer_local_llm: bool = False

    # Browser settings
    headless: bool = True
    max_navigation_steps: int = 15

    # Torrent settings
    torrent_client: str = "auto"
    max_concurrent_torrents: int = 3

    # qBittorrent settings
    qbittorrent_host: str = "localhost"
    qbittorrent_port: int = 8080
    qbittorrent_username: str = "admin"
    qbittorrent_password: str = "adminadmin"
    qbittorrent_https: bool = False

    # Transmission settings
    transmission_host: str = "localhost"
    transmission_port: int = 9091
    transmission_username: str = ""
    transmission_password: str = ""
    transmission_https: bool = False

    # Deluge settings
    deluge_host: str = "localhost"
    deluge_port: int = 58846
    deluge_username: str = ""
    deluge_password: str = "deluge"

    # rTorrent settings
    rtorrent_url: str = ""

    # aria2 settings
    aria2_host: str = "localhost"
    aria2_port: int = 6800
    aria2_secret: str = ""
    aria2_https: bool = False

    # Path mappings for containerized torrent clients
    path_mappings: list[str] = []

    # General
    log_level: str = "INFO"

    def get_path_mappings(self) -> list[tuple[Path, Path]]:
        """Parse path mappings into (host_path, container_path) tuples."""
        mappings = []
        for mapping in self.path_mappings:
            if ":" not in mapping:
                continue
            parts = mapping.split(":")
            if len(parts) == 2:
                host, container = parts
            elif len(parts) == 3 and len(parts[0]) == 1:
                host = f"{parts[0]}:{parts[1]}"
                container = parts[2]
            elif len(parts) == 4 and len(parts[0]) == 1 and len(parts[2]) == 1:
                host = f"{parts[0]}:{parts[1]}"
                container = f"{parts[2]}:{parts[3]}"
            else:
                continue
            mappings.append((Path(host), Path(container)))
        return mappings

    def host_to_container_path(self, host_path: Path) -> Path:
        """Convert a host path to a container path using mappings."""
        for host_base, container_base in self.get_path_mappings():
            try:
                relative = host_path.relative_to(host_base)
                return container_base / relative
            except ValueError:
                continue
        return host_path

    def container_to_host_path(self, container_path: Path) -> Path:
        """Convert a container path to a host path using mappings."""
        for host_base, container_base in self.get_path_mappings():
            try:
                relative = container_path.relative_to(container_base)
                return host_base / relative
            except ValueError:
                continue
        return container_path


@dataclass
class TaskResult:
    """Result of a browser/download task."""

    url: str
    success: bool
    found_links: list[str] = field(default_factory=list)
    downloaded_files: list[Path] = field(default_factory=list)
    error: str | None = None
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: datetime | None = None


class Graboid:
    """
    Main orchestrator for Graboid.

    Coordinates:
    - Browser-based navigation and link discovery
    - Direct downloads via httpx
    - Torrent downloads via various BitTorrent clients
    """

    def __init__(self, config: Config | None = None):
        self.config = config or Config()
        self.console = Console()

        self._browser_agent: BrowserAgent | None = None
        self._download_controller: DownloadController | None = None
        self._torrent_manager: TorrentManager | None = None

    @property
    def download_controller(self) -> DownloadController:
        if self._download_controller is None:
            self._download_controller = DownloadController(
                download_dir=self.config.download_dir,
            )
        return self._download_controller

    async def get_browser_agent(self) -> BrowserAgent:
        if self._browser_agent is None:
            self._browser_agent = BrowserAgent(
                download_controller=self.download_controller,
                headless=self.config.headless,
            )
            await self._browser_agent._init_browser()
        return self._browser_agent

    async def get_torrent_manager(self) -> TorrentManager:
        if self._torrent_manager is None:
            client = await self._create_torrent_client()
            self._torrent_manager = TorrentManager(
                client=client,
                download_dir=self.config.download_dir,
                max_concurrent=self.config.max_concurrent_torrents,
                path_translator=self.config.host_to_container_path,
            )
            await self._torrent_manager.initialize()
        return self._torrent_manager

    async def _create_torrent_client(self):
        """Create torrent client based on configuration."""
        client_type = self.config.torrent_client.lower()

        if client_type == "qbittorrent":
            return QBittorrentClient(
                host=self.config.qbittorrent_host,
                port=self.config.qbittorrent_port,
                username=self.config.qbittorrent_username,
                password=self.config.qbittorrent_password,
                use_https=self.config.qbittorrent_https,
            )
        elif client_type == "transmission":
            return TransmissionClient(
                host=self.config.transmission_host,
                port=self.config.transmission_port,
                username=self.config.transmission_username or None,
                password=self.config.transmission_password or None,
                use_https=self.config.transmission_https,
            )
        elif client_type == "deluge":
            return DelugeClient(
                host=self.config.deluge_host,
                port=self.config.deluge_port,
                username=self.config.deluge_username or None,
                password=self.config.deluge_password,
            )
        elif client_type == "rtorrent":
            if not self.config.rtorrent_url:
                raise ValueError("rtorrent_url must be set for rTorrent client")
            return RTorrentClient(url=self.config.rtorrent_url)
        elif client_type == "aria2":
            return Aria2Client(
                host=self.config.aria2_host,
                port=self.config.aria2_port,
                secret=self.config.aria2_secret or None,
                use_https=self.config.aria2_https,
            )
        elif client_type == "embedded":
            return EmbeddedTorrentClient(download_dir=self.config.download_dir)
        elif client_type == "auto":
            available = await detect_available_clients()
            if available:
                logger.info(f"Auto-detected torrent client: {available[0][0]}")
                return available[0][1]
            logger.info("No external torrent client found, using embedded libtorrent")
            return EmbeddedTorrentClient(download_dir=self.config.download_dir)
        else:
            raise ValueError(f"Unknown torrent client: {client_type}")

    async def browse(self, url: str, task: str) -> TaskResult:
        """
        Navigate to a URL and perform a task using browser automation.

        Args:
            url: Starting URL
            task: Description of what to do (e.g., "find download links for X")

        Returns:
            TaskResult with found links and any downloads
        """
        result = TaskResult(url=url, success=False)

        try:
            agent = await self.get_browser_agent()
            nav_result = await agent.find_download_links(
                url=url,
                description=task,
                max_steps=self.config.max_navigation_steps,
            )

            result.success = nav_result.success
            result.found_links = nav_result.found_links
            result.error = nav_result.error

        except Exception as e:
            result.error = str(e)
            logger.error(f"Browse failed: {e}")

        result.completed_at = datetime.now()
        return result

    async def download(self, url: str) -> TaskResult:
        """
        Download a file directly.

        Args:
            url: URL to download

        Returns:
            TaskResult with downloaded file path
        """
        result = TaskResult(url=url, success=False)

        try:
            dl_result = await self.download_controller.download_file(url, show_progress=True)
            result.success = dl_result.success
            if dl_result.path:
                result.downloaded_files.append(dl_result.path)
            result.error = dl_result.error

        except Exception as e:
            result.error = str(e)
            logger.error(f"Download failed: {e}")

        result.completed_at = datetime.now()
        return result

    async def add_torrent(self, source: str, label: str = "") -> TaskResult:
        """
        Add a torrent for download.

        Args:
            source: Magnet link, torrent URL, or file path
            label: Optional label/category for organization

        Returns:
            TaskResult with torrent info
        """
        result = TaskResult(url=source, success=False)

        try:
            manager = await self.get_torrent_manager()
            await manager.add_download(source, label or "graboid")
            await manager.start()
            result.success = True
            self.console.print(f"[green]Torrent added: {source[:60]}...[/green]")

        except Exception as e:
            result.error = str(e)
            logger.error(f"Torrent add failed: {e}")

        result.completed_at = datetime.now()
        return result

    async def cleanup(self) -> None:
        """Cleanup resources."""
        if self._browser_agent:
            await self._browser_agent._close_browser()
        if self._torrent_manager:
            await self._torrent_manager.stop()


def setup_logging(level: str = "INFO") -> None:
    """Set up logging with rich handler."""
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format="%(message)s",
        handlers=[RichHandler(rich_tracebacks=True)],
    )


def build_config(args: argparse.Namespace) -> Config:
    """Build config from TOML file, env vars, and CLI args."""
    config_path = Path(args.config) if hasattr(args, 'config') and args.config else None
    file_config = load_config_file(config_path)

    cli_overrides = {}
    if hasattr(args, 'download_dir') and args.download_dir:
        cli_overrides["download_dir"] = Path(args.download_dir)
    if hasattr(args, 'visible') and args.visible:
        cli_overrides["headless"] = False
    if hasattr(args, 'log_level') and args.log_level:
        cli_overrides["log_level"] = args.log_level
    if hasattr(args, 'torrent_client') and args.torrent_client:
        cli_overrides["torrent_client"] = args.torrent_client

    merged = {**file_config, **cli_overrides}
    return Config(**merged)


async def run_browse(args: argparse.Namespace) -> int:
    """Run browser automation task."""
    config = build_config(args)
    setup_logging(config.log_level)

    graboid = Graboid(config)

    try:
        result = await graboid.browse(args.url, args.task)

        if result.success:
            Console().print(f"\n[green]Found {len(result.found_links)} links:[/green]")
            for link in result.found_links:
                Console().print(f"  {link}")
        else:
            Console().print(f"[red]Failed: {result.error}[/red]")

        return 0 if result.success else 1

    finally:
        await graboid.cleanup()


async def run_download(args: argparse.Namespace) -> int:
    """Run direct download."""
    config = build_config(args)
    setup_logging(config.log_level)

    graboid = Graboid(config)

    try:
        result = await graboid.download(args.url)

        if result.success:
            Console().print(f"[green]Downloaded: {result.downloaded_files}[/green]")
        else:
            Console().print(f"[red]Failed: {result.error}[/red]")

        return 0 if result.success else 1

    finally:
        await graboid.cleanup()


async def run_torrent(args: argparse.Namespace) -> int:
    """Add torrent for download."""
    config = build_config(args)
    setup_logging(config.log_level)

    graboid = Graboid(config)

    try:
        result = await graboid.add_torrent(args.source, args.label or "")
        return 0 if result.success else 1

    finally:
        await graboid.cleanup()


EXAMPLE_CONFIG = '''\
# Graboid Configuration
# Save as: config.toml, graboid.toml, or ~/.config/graboid/config.toml

# Paths
download_dir = "./downloads"

# LLM settings
ollama_model = "llama3.2"
ollama_host = "http://localhost:11434"
claude_model = "claude-sonnet-4-20250514"
prefer_local_llm = true

# Browser settings
headless = true
max_navigation_steps = 15

# Torrent client selection
# Options: auto, qbittorrent, transmission, deluge, rtorrent, aria2, embedded
torrent_client = "auto"
max_concurrent_torrents = 3

# qBittorrent settings (Web UI, default port 8080)
qbittorrent_host = "localhost"
qbittorrent_port = 8080
qbittorrent_username = "admin"
qbittorrent_password = "adminadmin"
qbittorrent_https = false

# Transmission settings (RPC, default port 9091)
transmission_host = "localhost"
transmission_port = 9091
transmission_username = ""
transmission_password = ""
transmission_https = false

# Deluge settings (daemon, default port 58846)
deluge_host = "localhost"
deluge_port = 58846
deluge_username = ""
deluge_password = "deluge"

# rTorrent settings (SCGI socket or network)
# rtorrent_url = "scgi:///var/run/rtorrent.sock"
rtorrent_url = ""

# aria2 settings (JSON-RPC, default port 6800)
aria2_host = "localhost"
aria2_port = 6800
aria2_secret = ""
aria2_https = false

# Path mappings for containerized torrent clients
# Maps host paths to container paths (host:container)
# Example: path_mappings = ["/home/user/downloads:/downloads"]
path_mappings = []

# General
log_level = "INFO"
'''


def run_notes(args: argparse.Namespace) -> int:
    """View and manage agent notes."""
    console = Console()
    notes_db = get_notes_db()

    if args.action == "stats":
        stats = notes_db.get_stats()
        console.print("\n[bold]Agent Notes Statistics[/bold]\n")
        console.print(f"Total notes: {stats['total_notes']}")
        console.print(f"Domains: {stats['domains']}")
        console.print(f"Successful sources: {stats['successful']}")
        console.print("\n[bold]By type:[/bold]")
        for note_type, count in stats['by_type'].items():
            console.print(f"  {note_type}: {count}")
        return 0

    elif args.action == "list":
        domains = notes_db.get_all_domains()
        console.print("\n[bold]Domains with notes:[/bold]\n")
        for domain in sorted(domains):
            notes = notes_db.get_notes_for_url(f"https://{domain}")
            console.print(f"  [cyan]{domain}[/cyan] ({len(notes)} notes)")
        return 0

    elif args.action == "show":
        if not args.domain:
            console.print("[red]Please specify a domain with --domain[/red]")
            return 1

        notes = notes_db.get_notes_for_url(
            f"https://{args.domain}",
            note_types=[args.type] if args.type else None,
        )

        if not notes:
            console.print(f"[yellow]No notes found for {args.domain}[/yellow]")
            return 0

        console.print(f"\n[bold]Notes for {args.domain}:[/bold]\n")

        table = Table()
        table.add_column("Type", style="cyan")
        table.add_column("Content", style="white")
        table.add_column("Success", style="yellow")
        table.add_column("Uses", style="blue")

        for note in notes:
            success_str = "✓" if note.success else ("✗" if note.success is False else "-")
            table.add_row(
                note.note_type,
                note.content[:60] + "..." if len(note.content) > 60 else note.content,
                success_str,
                str(note.use_count),
            )

        console.print(table)
        return 0

    elif args.action == "clear":
        console.print("[yellow]This will delete all agent notes. Are you sure?[/yellow]")
        confirm = input("Type 'yes' to confirm: ")
        if confirm.lower() == "yes":
            notes_db.notes_file.unlink(missing_ok=True)
            console.print("[green]Notes cleared.[/green]")
        else:
            console.print("Cancelled.")
        return 0

    return 0


def run_setup(args: argparse.Namespace) -> int:
    """Create config file."""
    console = Console()

    if args.output:
        output_path = Path(args.output)
    elif args.user:
        output_path = Path.home() / ".config" / "graboid" / "config.toml"
    else:
        output_path = Path.cwd() / "config.toml"

    console.print(f"\n[bold]Graboid Setup[/bold]\n")

    if output_path.exists() and not args.force:
        console.print(f"[yellow]Config file already exists: {output_path}[/yellow]")
        console.print("Use --force to overwrite.")
        return 1

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w") as f:
        f.write(EXAMPLE_CONFIG)

    console.print(f"[green]Created config file: {output_path}[/green]\n")
    console.print("Edit this file to configure your settings.")
    console.print("\n[bold]Torrent client options:[/bold]")
    console.print("  - [cyan]qbittorrent[/cyan]: qBittorrent Web UI (port 8080)")
    console.print("  - [cyan]transmission[/cyan]: Transmission RPC (port 9091)")
    console.print("  - [cyan]deluge[/cyan]: Deluge daemon (port 58846)")
    console.print("  - [cyan]rtorrent[/cyan]: rTorrent SCGI socket")
    console.print("  - [cyan]aria2[/cyan]: aria2 RPC (port 6800)")
    console.print("  - [cyan]embedded[/cyan]: Built-in libtorrent (no external client)")
    console.print("  - [cyan]auto[/cyan]: Auto-detect running client")

    return 0


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Graboid - LLM-driven browser automation agent with BitTorrent support",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Browse command
    browse_parser = subparsers.add_parser("browse", help="Navigate and find content using browser automation")
    browse_parser.add_argument("url", help="Starting URL")
    browse_parser.add_argument("task", help="Task description (e.g., 'find download links')")
    browse_parser.add_argument("--visible", "-v", action="store_true", help="Show browser window")
    browse_parser.add_argument("--download-dir", "-d", help="Download directory")
    browse_parser.add_argument("--config", "-c", help="Config file path")
    browse_parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], default="INFO")

    # Download command
    dl_parser = subparsers.add_parser("download", help="Download a file directly")
    dl_parser.add_argument("url", help="URL to download")
    dl_parser.add_argument("--download-dir", "-d", help="Download directory")
    dl_parser.add_argument("--config", "-c", help="Config file path")
    dl_parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], default="INFO")

    # Torrent command
    torrent_parser = subparsers.add_parser("torrent", help="Add a torrent for download")
    torrent_parser.add_argument("source", help="Magnet link, torrent URL, or file path")
    torrent_parser.add_argument("--label", "-l", help="Label/category for organization")
    torrent_parser.add_argument("--torrent-client", "-t",
        choices=["auto", "qbittorrent", "transmission", "deluge", "rtorrent", "aria2", "embedded"])
    torrent_parser.add_argument("--config", "-c", help="Config file path")
    torrent_parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], default="INFO")

    # Web UI command
    web_parser = subparsers.add_parser("web", help="Start the web UI")
    web_parser.add_argument("--host", "-H", default="127.0.0.1", help="Host to bind to")
    web_parser.add_argument("--port", "-p", type=int, default=8000, help="Port to bind to")

    # Setup command
    setup_parser = subparsers.add_parser("setup", help="Create a config file")
    setup_parser.add_argument("--output", "-o", help="Output path for config file")
    setup_parser.add_argument("--user", "-u", action="store_true", help="Create in ~/.config/graboid/")
    setup_parser.add_argument("--force", "-f", action="store_true", help="Overwrite existing config file")

    # Notes command
    notes_parser = subparsers.add_parser("notes", help="View and manage agent notes")
    notes_parser.add_argument("action", nargs="?", choices=["list", "show", "stats", "clear"], default="stats")
    notes_parser.add_argument("--domain", "-d", help="Domain to show notes for")
    notes_parser.add_argument("--type", "-t",
        choices=["source_quality", "navigation_tip", "obstacle", "workaround", "download_method", "site_structure"])

    args = parser.parse_args()

    # Handle commands
    if args.command == "browse":
        sys.exit(asyncio.run(run_browse(args)))
    elif args.command == "download":
        sys.exit(asyncio.run(run_download(args)))
    elif args.command == "torrent":
        sys.exit(asyncio.run(run_torrent(args)))
    elif args.command == "web":
        from .web import run_server
        console = Console()
        console.print(f"\n[bold]Starting Graboid Web UI[/bold]")
        console.print(f"Open [cyan]http://{args.host}:{args.port}[/cyan] in your browser\n")
        run_server(host=args.host, port=args.port)
    elif args.command == "setup":
        sys.exit(run_setup(args))
    elif args.command == "notes":
        sys.exit(run_notes(args))
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
