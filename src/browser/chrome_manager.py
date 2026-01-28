"""Chrome browser manager with CDP control for Graboid."""

import asyncio
import json
import logging
import shutil
from pathlib import Path
from typing import Any

import websockets
from platformdirs import user_cache_dir, user_data_dir

logger = logging.getLogger(__name__)

# App name for platformdirs
APP_NAME = "graboid"


class ChromeManager:
    """
    Manages a Chrome instance with remote debugging for full CDP control.

    This allows Graboid to:
    - Launch its own Chrome instance (headless or headed)
    - Configure download behavior via CDP (no Save As dialogs)
    - Let Claude Code connect via chrome-devtools-mcp
    - Capture downloads automatically to a specified directory
    """

    def __init__(
        self,
        debug_port: int = 9222,
        headless: bool = False,
        downloads_dir: Path | None = None,
        chrome_data_dir: Path | None = None,
    ):
        """
        Initialize Chrome manager.

        Args:
            debug_port: Remote debugging port (default 9222)
            headless: Run in headless mode
            downloads_dir: Directory for automatic downloads
            chrome_data_dir: Chrome user data directory (for persistence)
        """
        self.debug_port = debug_port
        self.headless = headless

        # Use platformdirs for proper OS-specific paths
        cache_dir = Path(user_cache_dir(APP_NAME))
        data_dir = Path(user_data_dir(APP_NAME))

        self.downloads_dir = downloads_dir or cache_dir / "downloads"
        self.user_data_dir = chrome_data_dir or data_dir / "chrome_profile"

        self._process: asyncio.subprocess.Process | None = None
        self._browser_ws_url: str | None = None  # Browser-level target
        self._page_ws_url: str | None = None  # Page-level target
        self._ws: Any = None  # Persistent page-level WS connection
        self._message_id = 0

    def _find_chrome(self) -> str | None:
        """Find Chrome/Chromium binary."""
        candidates = [
            "google-chrome-stable",
            "google-chrome",
            "chromium-browser",
            "chromium",
            "chrome",
        ]

        for name in candidates:
            path = shutil.which(name)
            if path:
                return path

        return None

    async def start(self) -> bool:
        """
        Start Chrome with remote debugging enabled.

        Returns:
            True if Chrome started successfully
        """
        chrome_path = self._find_chrome()
        if not chrome_path:
            logger.error("Chrome/Chromium not found in PATH")
            return False

        # Ensure directories exist
        self.downloads_dir.mkdir(parents=True, exist_ok=True)
        self.user_data_dir.mkdir(parents=True, exist_ok=True)

        # Build Chrome arguments
        args = [
            chrome_path,
            f"--remote-debugging-port={self.debug_port}",
            f"--user-data-dir={self.user_data_dir}",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-networking",
            "--disable-client-side-phishing-detection",
            "--disable-default-apps",
            "--disable-extensions",
            "--disable-hang-monitor",
            "--disable-popup-blocking",
            "--disable-prompt-on-repost",
            "--disable-sync",
            "--disable-translate",
            "--metrics-recording-only",
            "--safebrowsing-disable-auto-update",
            # Download settings
            f"--download-default-directory={self.downloads_dir}",
        ]

        if self.headless:
            args.append("--headless=new")

        # Start with a blank page
        args.append("about:blank")

        logger.info(f"Starting Chrome: {chrome_path}")
        logger.info(f"  Debug port: {self.debug_port}")
        logger.info(f"  Downloads: {self.downloads_dir}")
        logger.info(f"  Headless: {self.headless}")

        try:
            self._process = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            # Wait for Chrome to start and connect CDP
            await asyncio.sleep(1)

            if not await self._connect_cdp():
                logger.error("Failed to connect to Chrome CDP")
                await self.stop()
                return False

            # Configure download behavior via persistent connection
            await self._configure_downloads()

            logger.info(f"Chrome started successfully (PID: {self._process.pid})")
            return True

        except Exception as e:
            logger.error(f"Failed to start Chrome: {e}")
            return False

    async def _connect_cdp(self, retries: int = 5) -> bool:
        """Connect to Chrome's CDP via page target (supports all domains)."""
        import aiohttp

        for attempt in range(retries):
            try:
                async with aiohttp.ClientSession() as session:
                    # Get the browser-level WS URL
                    async with session.get(f"http://localhost:{self.debug_port}/json/version") as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            self._browser_ws_url = data.get("webSocketDebuggerUrl")
                            logger.info(f"CDP browser WS: {self._browser_ws_url}")

                    # Get a page target WS URL — needed for Page.*, Runtime.*, etc.
                    async with session.get(f"http://localhost:{self.debug_port}/json/list") as resp:
                        if resp.status == 200:
                            targets = await resp.json()
                            for target in targets:
                                if target.get("type") == "page":
                                    self._page_ws_url = target.get("webSocketDebuggerUrl")
                                    logger.info(f"CDP page WS: {self._page_ws_url}")
                                    break

                    if self._page_ws_url:
                        # Open a persistent connection to the page target
                        self._ws = await websockets.connect(self._page_ws_url)
                        logger.info("Persistent CDP page connection established")
                        return True
                    elif self._browser_ws_url:
                        logger.warning("No page target found, falling back to browser target")
                        self._page_ws_url = self._browser_ws_url
                        self._ws = await websockets.connect(self._browser_ws_url)
                        return True

            except Exception as e:
                logger.debug(f"CDP connection attempt {attempt + 1} failed: {e}")
                await asyncio.sleep(0.5)

        return False

    async def _send_cdp(self, method: str, params: dict | None = None) -> dict:
        """Send a CDP command over the persistent connection."""
        if not self._ws:
            raise RuntimeError("Not connected to Chrome CDP")

        self._message_id += 1
        msg_id = self._message_id
        message = {
            "id": msg_id,
            "method": method,
            "params": params or {},
        }

        try:
            await self._ws.send(json.dumps(message))

            while True:
                raw = await asyncio.wait_for(self._ws.recv(), timeout=10)
                response = json.loads(raw)
                if response.get("id") == msg_id:
                    if "error" in response:
                        raise RuntimeError(f"CDP error: {response['error']}")
                    return response.get("result", {})
                # Ignore events / responses for other message IDs
        except websockets.exceptions.ConnectionClosed:
            logger.warning("CDP connection closed, reconnecting...")
            await self._reconnect()
            return await self._send_cdp(method, params)

    async def _reconnect(self) -> None:
        """Re-establish CDP connection (e.g. after chrome-devtools-mcp creates new tabs)."""
        self._ws = None
        await self._refresh_page_target()
        if self._page_ws_url:
            self._ws = await websockets.connect(self._page_ws_url)
            await self._configure_downloads()
            logger.info("CDP reconnected and downloads reconfigured")

    async def _refresh_page_target(self) -> None:
        """Refresh the page target WS URL (picks the latest page)."""
        import aiohttp

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"http://localhost:{self.debug_port}/json/list") as resp:
                    if resp.status == 200:
                        targets = await resp.json()
                        # Prefer non-about:blank pages
                        for target in targets:
                            if target.get("type") == "page" and "about:blank" not in target.get("url", ""):
                                self._page_ws_url = target.get("webSocketDebuggerUrl")
                                logger.info(f"Refreshed page target: {self._page_ws_url}")
                                return
                        # Fall back to any page
                        for target in targets:
                            if target.get("type") == "page":
                                self._page_ws_url = target.get("webSocketDebuggerUrl")
                                logger.info(f"Refreshed page target (fallback): {self._page_ws_url}")
                                return
        except Exception as e:
            logger.warning(f"Failed to refresh page target: {e}")

    async def _configure_downloads(self) -> None:
        """Configure Chrome to auto-download to our directory."""
        download_path = str(self.downloads_dir.resolve())

        # Set download behavior at browser level (applies to all pages/tabs)
        try:
            await self._send_cdp("Browser.setDownloadBehavior", {
                "behavior": "allowAndName",
                "downloadPath": download_path,
                "eventsEnabled": True,
            })
            logger.info(f"Browser.setDownloadBehavior configured: {download_path}")
        except Exception as e:
            logger.warning(f"Browser.setDownloadBehavior failed: {e}")

        # Also set at page level for older Chrome and as reinforcement
        try:
            await self._send_cdp("Page.setDownloadBehavior", {
                "behavior": "allow",
                "downloadPath": download_path,
            })
            logger.info(f"Page.setDownloadBehavior configured: {download_path}")
        except Exception as e:
            logger.debug(f"Page.setDownloadBehavior failed (non-critical): {e}")

    async def take_screenshot(self) -> bytes | None:
        """Take a screenshot via CDP, returning PNG bytes."""
        try:
            # Reconnect to the active page if needed (chrome-devtools-mcp may
            # have opened new tabs since we last connected)
            await self._ensure_active_page()
            import base64
            result = await self._send_cdp("Page.captureScreenshot", {"format": "png"})
            data = result.get("data")
            if data:
                return base64.b64decode(data)
        except Exception as e:
            logger.debug(f"Screenshot failed: {e}")
        return None

    async def _ensure_active_page(self) -> None:
        """Switch to the active (non-blank) page target if it changed."""
        import aiohttp

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"http://localhost:{self.debug_port}/json/list") as resp:
                    if resp.status != 200:
                        return
                    targets = await resp.json()

            # Find the best page target (prefer non-blank)
            best = None
            for target in targets:
                if target.get("type") == "page":
                    url = target.get("url", "")
                    ws_url = target.get("webSocketDebuggerUrl")
                    if ws_url and "about:blank" not in url:
                        best = ws_url
                        break
                    elif ws_url and best is None:
                        best = ws_url

            if best and best != self._page_ws_url:
                logger.info(f"Switching to active page target: {best}")
                self._page_ws_url = best
                if self._ws:
                    await self._ws.close()
                self._ws = await websockets.connect(best)
                await self._configure_downloads()

        except Exception as e:
            logger.debug(f"_ensure_active_page failed: {e}")

    async def get_current_url(self) -> str:
        """Get the current page URL via CDP."""
        try:
            await self._ensure_active_page()
            result = await self._send_cdp("Runtime.evaluate", {
                "expression": "window.location.href"
            })
            return result.get("result", {}).get("value", "")
        except Exception:
            return ""

    async def navigate(self, url: str) -> None:
        """Navigate to a URL."""
        await self._send_cdp("Page.navigate", {"url": url})

    async def get_download_files(self) -> list[Path]:
        """Get list of files in the downloads directory."""
        if not self.downloads_dir.exists():
            return []
        return list(self.downloads_dir.iterdir())

    async def stop(self) -> None:
        """Stop Chrome and cleanup."""
        if self._ws:
            try:
                await self._ws.close()
            except Exception:
                pass
            self._ws = None

        if self._process:
            logger.info("Stopping Chrome...")
            try:
                self._process.terminate()
                await asyncio.wait_for(self._process.wait(), timeout=5)
            except asyncio.TimeoutError:
                self._process.kill()
                await self._process.wait()
            self._process = None

        self._browser_ws_url = None
        self._page_ws_url = None
        logger.info("Chrome stopped")

    @property
    def is_running(self) -> bool:
        """Check if Chrome is running."""
        return self._process is not None and self._process.returncode is None

    @property
    def debug_url(self) -> str:
        """Get the debugging URL for connecting tools."""
        return f"http://localhost:{self.debug_port}"

    async def __aenter__(self) -> "ChromeManager":
        """Async context manager entry."""
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.stop()


async def create_chrome_manager(
    debug_port: int = 9222,
    headless: bool = False,
    downloads_dir: Path | None = None,
) -> ChromeManager:
    """Factory function to create and start a Chrome manager."""
    manager = ChromeManager(
        debug_port=debug_port,
        headless=headless,
        downloads_dir=downloads_dir,
    )
    await manager.start()
    return manager
