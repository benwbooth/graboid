"""Browser-use agent wrapper for web navigation and content discovery."""

import asyncio
import logging
import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable

from pydantic import BaseModel

from .download_action import DownloadController, DownloadResult
from .notes import NotesDB, get_notes_db, NoteType

logger = logging.getLogger(__name__)


class LLMProvider(str, Enum):
    """Supported LLM providers for browser automation."""

    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    OLLAMA = "ollama"
    GOOGLE = "google"
    DEEPSEEK = "deepseek"
    GROQ = "groq"
    MISTRAL = "mistral"
    CEREBRAS = "cerebras"
    OPENROUTER = "openrouter"
    AWS_BEDROCK = "aws_bedrock"
    AZURE = "azure"
    BROWSER_USE = "browser_use"
    CLAUDE_CODE = "claude_code"  # Uses claude CLI with Max subscription


class NavigationTarget(BaseModel):
    """Target for browser navigation."""

    url: str
    description: str = ""
    source_type: str = ""  # Optional hint about the source


@dataclass
class NavigationResult:
    """Result of a navigation task."""

    success: bool
    downloads: list[DownloadResult] = field(default_factory=list)
    found_links: list[str] = field(default_factory=list)
    error: str | None = None
    final_url: str | None = None
    history: Any = None  # AgentHistoryList from browser-use
    screenshots: list[tuple[bytes, str, str]] = field(default_factory=list)  # (data, url, description)


def get_llm(
    provider: LLMProvider | str = LLMProvider.ANTHROPIC,
    model: str | None = None,
    **kwargs,
):
    """
    Get an LLM instance for browser-use.

    Args:
        provider: LLM provider to use
        model: Model name (provider-specific)
        **kwargs: Additional arguments passed to the chat class

    Returns:
        BaseChatModel instance for browser-use

    Environment variables used:
        ANTHROPIC_API_KEY, OPENAI_API_KEY, GOOGLE_API_KEY, GROQ_API_KEY,
        MISTRAL_API_KEY, DEEPSEEK_API_KEY, CEREBRAS_API_KEY, OPENROUTER_API_KEY,
        AZURE_OPENAI_KEY, AZURE_OPENAI_ENDPOINT, AWS_ACCESS_KEY_ID, etc.
    """
    if isinstance(provider, str):
        provider = LLMProvider(provider.lower())

    if provider == LLMProvider.ANTHROPIC:
        from browser_use.llm.anthropic.chat import ChatAnthropic

        return ChatAnthropic(
            model=model or "claude-sonnet-4-20250514",
            api_key=kwargs.get("api_key") or os.getenv("ANTHROPIC_API_KEY"),
            **{k: v for k, v in kwargs.items() if k != "api_key"},
        )

    elif provider == LLMProvider.OPENAI:
        from browser_use.llm.openai.chat import ChatOpenAI

        return ChatOpenAI(
            model=model or "gpt-4o",
            api_key=kwargs.get("api_key") or os.getenv("OPENAI_API_KEY"),
            **{k: v for k, v in kwargs.items() if k != "api_key"},
        )

    elif provider == LLMProvider.OLLAMA:
        from browser_use.llm.ollama.chat import ChatOllama

        return ChatOllama(
            model=model or "llama3.2",
            base_url=kwargs.get("base_url", "http://localhost:11434"),
            **{k: v for k, v in kwargs.items() if k != "base_url"},
        )

    elif provider == LLMProvider.GOOGLE:
        from browser_use.llm.google.chat import ChatGoogle

        return ChatGoogle(
            model=model or "gemini-2.0-flash",
            api_key=kwargs.get("api_key") or os.getenv("GOOGLE_API_KEY"),
            **{k: v for k, v in kwargs.items() if k != "api_key"},
        )

    elif provider == LLMProvider.DEEPSEEK:
        from browser_use.llm.deepseek.chat import ChatDeepSeek

        return ChatDeepSeek(
            model=model or "deepseek-chat",
            api_key=kwargs.get("api_key") or os.getenv("DEEPSEEK_API_KEY"),
            **{k: v for k, v in kwargs.items() if k != "api_key"},
        )

    elif provider == LLMProvider.GROQ:
        from browser_use.llm.groq.chat import ChatGroq

        return ChatGroq(
            model=model or "llama-3.3-70b-versatile",
            api_key=kwargs.get("api_key") or os.getenv("GROQ_API_KEY"),
            **{k: v for k, v in kwargs.items() if k != "api_key"},
        )

    elif provider == LLMProvider.MISTRAL:
        from browser_use.llm.mistral.chat import ChatMistral

        return ChatMistral(
            model=model or "mistral-large-latest",
            api_key=kwargs.get("api_key") or os.getenv("MISTRAL_API_KEY"),
            **{k: v for k, v in kwargs.items() if k != "api_key"},
        )

    elif provider == LLMProvider.CEREBRAS:
        from browser_use.llm.cerebras.chat import ChatCerebras

        return ChatCerebras(
            model=model or "llama-3.3-70b",
            api_key=kwargs.get("api_key") or os.getenv("CEREBRAS_API_KEY"),
            **{k: v for k, v in kwargs.items() if k != "api_key"},
        )

    elif provider == LLMProvider.OPENROUTER:
        from browser_use.llm.openrouter.chat import ChatOpenRouter

        return ChatOpenRouter(
            model=model or "anthropic/claude-3.5-sonnet",
            api_key=kwargs.get("api_key") or os.getenv("OPENROUTER_API_KEY"),
            **{k: v for k, v in kwargs.items() if k != "api_key"},
        )

    elif provider == LLMProvider.AWS_BEDROCK:
        from browser_use.llm.aws.chat_bedrock import ChatBedrock

        return ChatBedrock(
            model=model or "anthropic.claude-3-5-sonnet-20241022-v2:0",
            **kwargs,
        )

    elif provider == LLMProvider.AZURE:
        from browser_use.llm.azure.chat import ChatAzureOpenAI

        return ChatAzureOpenAI(
            model=model or "gpt-4o",
            api_key=kwargs.get("api_key") or os.getenv("AZURE_OPENAI_KEY"),
            azure_endpoint=kwargs.get("azure_endpoint") or os.getenv("AZURE_OPENAI_ENDPOINT"),
            **{k: v for k, v in kwargs.items() if k not in ("api_key", "azure_endpoint")},
        )

    elif provider == LLMProvider.BROWSER_USE:
        from browser_use.llm.browser_use.chat import ChatBrowserUse

        return ChatBrowserUse(
            model=model or "bu-latest",
            api_key=kwargs.get("api_key") or os.getenv("BROWSER_USE_API_KEY"),
            **{k: v for k, v in kwargs.items() if k != "api_key"},
        )

    elif provider == LLMProvider.CLAUDE_CODE:
        from .claude_code_llm import ClaudeCodeChat

        return ClaudeCodeChat(
            model=model or "sonnet",
            timeout=kwargs.get("timeout", 120),
        )

    else:
        raise ValueError(f"Unknown provider: {provider}")


ScreenshotCallback = Callable[[bytes, str, str], Any]  # (data, url, description)


class BrowserAgent:
    """
    Browser automation agent using browser-use for LLM-driven navigation.

    This wraps browser-use's Agent to provide:
    - Easy LLM provider selection
    - ROM-site specific task prompts
    - Integration with download controller for file handling
    - Learning system that records and uses notes about sites
    """

    def __init__(
        self,
        llm_provider: LLMProvider | str = LLMProvider.ANTHROPIC,
        llm_model: str | None = None,
        llm_kwargs: dict[str, Any] | None = None,
        download_controller: DownloadController | None = None,
        headless: bool = True,
        use_vision: bool = True,
        notes_db: NotesDB | None = None,
        screenshot_callback: ScreenshotCallback | None = None,
    ):
        """
        Initialize browser agent.

        Args:
            llm_provider: Which LLM provider to use
            llm_model: Specific model name (or use provider default)
            llm_kwargs: Additional kwargs for LLM initialization
            download_controller: For handling file downloads
            headless: Run browser without GUI
            use_vision: Send screenshots to LLM (recommended True)
            notes_db: Database for storing/retrieving navigation notes
            screenshot_callback: Optional callback for screenshots (data, url, description)
        """
        self.llm_provider = llm_provider
        self.llm_model = llm_model
        self.llm_kwargs = llm_kwargs or {}
        self.download_controller = download_controller or DownloadController()
        self.headless = headless
        self.use_vision = use_vision
        self.notes_db = notes_db or get_notes_db()
        self._screenshot_callback = screenshot_callback

        self._llm = None
        self._browser = None

    def set_screenshot_callback(self, callback: ScreenshotCallback | None) -> None:
        """Set or clear the screenshot callback."""
        self._screenshot_callback = callback

    def _get_llm(self):
        """Lazy-load LLM instance."""
        if self._llm is None:
            self._llm = get_llm(
                provider=self.llm_provider,
                model=self.llm_model,
                **self.llm_kwargs,
            )
        return self._llm

    async def _get_browser(self):
        """Lazy-load browser instance, using system Chrome if available."""
        if self._browser is None:
            from browser_use.browser.session import BrowserSession

            # Find system Chrome/Chromium (needed for NixOS and similar)
            chrome_path = self._find_system_chrome()
            logger.info(f"Creating browser session (headless={self.headless}, chrome_path={chrome_path})")

            self._browser = BrowserSession(
                headless=self.headless,
                disable_security=True,  # Needed for some ROM sites
                executable_path=chrome_path,  # Use system Chrome if found
            )

            # Start the browser session (required for browser-use 0.11.x)
            logger.info("Starting browser session...")
            await self._browser.start()
            logger.info("Browser session started successfully")

        return self._browser

    def _find_system_chrome(self) -> str | None:
        """Find system-installed Chrome/Chromium binary."""
        import shutil

        # Common Chrome/Chromium binary names
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
                logger.info(f"Using system Chrome: {path}")
                return path

        return None

    async def _ensure_browser_installed(self):
        """Install Playwright browser if not already installed."""
        import os
        import subprocess
        import sys

        # Clean environment - remove askpass programs that cause GUI popups
        clean_env = {k: v for k, v in os.environ.items()
                     if k not in ("SSH_ASKPASS", "SUDO_ASKPASS", "GIT_ASKPASS", "SSH_AUTH_SOCK")}
        clean_env["GIT_TERMINAL_PROMPT"] = "0"

        # Check if chromium is installed by looking for the browser path
        try:
            result = subprocess.run(
                [sys.executable, "-m", "playwright", "install", "--dry-run", "chromium"],
                capture_output=True,
                text=True,
                env=clean_env,
            )
            # If dry-run succeeds without "is not installed" message, browser exists
            if "is not installed" not in result.stdout and "is not installed" not in result.stderr:
                return
        except Exception:
            pass

        # Install chromium browser
        logger.info("Installing Chromium browser for Playwright (first-time setup)...")
        try:
            proc = await asyncio.create_subprocess_exec(
                sys.executable, "-m", "playwright", "install", "chromium",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=clean_env,
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode == 0:
                logger.info("Chromium browser installed successfully")
            else:
                logger.warning(f"Browser install returned {proc.returncode}: {stderr.decode()}")
        except Exception as e:
            logger.warning(f"Failed to auto-install browser: {e}")

    async def navigate_to_roms(
        self,
        target: NavigationTarget,
        max_steps: int = 50,
    ) -> NavigationResult:
        """
        Navigate to a ROM source and find download links.

        Browser-use handles:
        - Taking screenshots and sending to LLM
        - LLM deciding what actions to take (click, type, navigate)
        - Executing those actions
        - Repeating until task is complete

        Args:
            target: Navigation target with URL and platform info
            max_steps: Maximum navigation steps

        Returns:
            NavigationResult with found links and any downloads
        """
        from browser_use import Agent

        browser = await self._get_browser()
        llm = self._get_llm()

        # Build task prompt for browser-use agent
        task = self._build_task_prompt(target)

        logger.info(f"Starting browser navigation: {target.url}")
        logger.debug(f"Task: {task}")

        screenshots: list[tuple[bytes, str, str]] = []
        screenshot_stop = asyncio.Event()

        async def capture_screenshots():
            """Background task to capture screenshots periodically."""
            last_screenshot = None
            step_count = 0
            while not screenshot_stop.is_set():
                try:
                    # Get the current page from the browser context
                    if browser._context and browser._context.pages:
                        page = browser._context.pages[-1]
                        url = page.url
                        screenshot_data = await page.screenshot()

                        # Only save if screenshot changed (simple comparison)
                        if screenshot_data != last_screenshot:
                            last_screenshot = screenshot_data
                            step_count += 1
                            description = f"Step {step_count}: Viewing {url}"
                            screenshots.append((screenshot_data, url, description))

                            # Call callback if set
                            if self._screenshot_callback:
                                try:
                                    result = self._screenshot_callback(screenshot_data, url, description)
                                    if asyncio.iscoroutine(result):
                                        await result
                                except Exception as e:
                                    logger.warning(f"Screenshot callback error: {e}")
                except Exception as e:
                    logger.debug(f"Screenshot capture error: {e}")

                # Wait before next capture
                try:
                    await asyncio.wait_for(screenshot_stop.wait(), timeout=2.0)
                    break  # Event was set
                except asyncio.TimeoutError:
                    pass  # Continue capturing

        try:
            agent = Agent(
                task=task,
                llm=llm,
                browser=browser,
                use_vision=self.use_vision,
                max_failures=3,
                # Extend system message with ROM-specific instructions
                extend_system_message=self._get_system_extension(),
            )

            # Start screenshot capture task
            screenshot_task = asyncio.create_task(capture_screenshots())

            try:
                # Run the agent - browser-use handles everything
                history = await agent.run(max_steps=max_steps)
            finally:
                # Stop screenshot capture
                screenshot_stop.set()
                await screenshot_task

            # Extract results from history
            result = self._process_history(history, target)
            result.screenshots = screenshots
            return result

        except Exception as e:
            logger.error(f"Navigation failed: {e}")
            return NavigationResult(
                success=False,
                error=str(e),
                screenshots=screenshots,
            )

    def _build_task_prompt(self, target: NavigationTarget) -> str:
        """Build task prompt for browser-use agent."""
        # Get relevant notes from previous visits
        previous_knowledge = self.notes_db.format_notes_for_prompt(
            target.url,
            max_notes=8,
        )

        base_prompt = f"""Navigate to {target.url} and complete this task: {target.description or "find download links"}

{f"Additional context: {target.source_type}" if target.source_type else ""}

{previous_knowledge}

Steps:
1. Go to the URL and explore the page
2. Look for downloadable content (files, archives, torrents)
3. Identify all download links
4. Report the download URLs found

When you find download links, report them clearly with the full URLs.
If you encounter anti-bot measures or CAPTCHAs, describe what you see.

IMPORTANT: After completing the task (success or failure), provide learnings using this format:
[LEARNING: type=navigation_tip] How to navigate this site effectively
[LEARNING: type=obstacle] Any problems encountered
[LEARNING: type=workaround] Solutions that worked
[LEARNING: type=download_method] How downloads work on this site
[LEARNING: type=source_quality] Rating of this source (good/bad and why)
"""
        return base_prompt

    def _get_system_extension(self) -> str:
        """Additional system prompt for navigation."""
        return """
You are a browser automation agent helping to navigate websites and find downloadable content.

When identifying downloads:
- Look for file extensions: .zip, .7z, .rar, .torrent, .iso, .pdf, .exe, .dmg, .deb, .rpm
- Look for magnet: links (start with "magnet:?")
- Directory listings often have file sizes shown
- Look for download buttons, "Download" links, or direct file links

Report full URLs when you find downloads. Include file sizes if visible.
"""

    def _process_history(self, history, target: NavigationTarget) -> NavigationResult:
        """Process browser-use agent history to extract results and learnings."""
        import re

        found_links = []
        final_url = None
        all_text = []

        # Extract information from agent history
        if history and hasattr(history, "history"):
            for item in history.history:
                # Check for URLs in the agent's actions/observations
                if hasattr(item, "result") and item.result:
                    result_str = str(item.result)
                    all_text.append(result_str)

                    # Extract URLs from result
                    urls = re.findall(
                        r'https?://[^\s<>"\']+\.(?:zip|7z|rar|torrent|iso|chd)',
                        result_str,
                        re.IGNORECASE,
                    )
                    found_links.extend(urls)

                    # Extract magnet links
                    magnets = re.findall(r'magnet:\?[^\s<>"\']+', result_str)
                    found_links.extend(magnets)

                # Get final URL from browser state
                if hasattr(item, "state") and hasattr(item.state, "url"):
                    final_url = item.state.url

                # Collect agent messages for learning extraction
                if hasattr(item, "message") and item.message:
                    all_text.append(str(item.message))

        # Deduplicate links
        found_links = list(dict.fromkeys(found_links))
        success = len(found_links) > 0

        # Extract and save learnings from agent output
        self._extract_and_save_learnings(
            "\n".join(all_text),
            target,
            success=success,
        )

        return NavigationResult(
            success=success,
            found_links=found_links,
            final_url=final_url,
            history=history,
            error=None if found_links else "No download links found",
        )

    def _extract_and_save_learnings(
        self,
        text: str,
        target: NavigationTarget,
        success: bool,
    ) -> None:
        """Extract learning notes from agent output and save them."""
        import re

        # Pattern: [LEARNING: type=xxx] content
        pattern = r'\[LEARNING:\s*type=(\w+)\]\s*(.+?)(?=\[LEARNING:|$)'
        matches = re.findall(pattern, text, re.IGNORECASE | re.DOTALL)

        valid_types = {
            "navigation_tip", "obstacle", "workaround",
            "download_method", "source_quality", "site_structure"
        }

        for note_type, content in matches:
            note_type = note_type.lower()
            content = content.strip()

            if note_type not in valid_types or not content:
                continue

            # Determine success flag for source_quality notes
            note_success = None
            if note_type == "source_quality":
                note_success = success

            try:
                self.notes_db.add_note(
                    url_or_domain=target.url,
                    note_type=note_type,  # type: ignore
                    content=content,
                    platform=None,  # Platform not tracked for general navigation
                    success=note_success,
                )
                logger.debug(f"Saved learning: {note_type} - {content[:50]}...")
            except Exception as e:
                logger.warning(f"Failed to save learning: {e}")

    def add_note(
        self,
        url: str,
        note_type: NoteType,
        content: str,
        platform: str | None = None,
        success: bool | None = None,
    ) -> None:
        """Manually add a note about a site."""
        self.notes_db.add_note(
            url_or_domain=url,
            note_type=note_type,
            content=content,
            platform=platform,
            success=success,
        )

    async def find_download_links(
        self,
        url: str,
        description: str = "",
        max_steps: int = 30,
    ) -> NavigationResult:
        """
        Find download links on a page.

        Args:
            url: Page URL to scan
            description: Task description for the agent
            max_steps: Maximum steps

        Returns:
            NavigationResult with found links and screenshots
        """
        target = NavigationTarget(
            url=url,
            description=description or "Find download links",
            source_type="unknown",
        )
        return await self.navigate_to_roms(target, max_steps=max_steps)

    async def close(self):
        """Close browser and cleanup."""
        if self._browser:
            await self._browser.close()
            self._browser = None


async def create_browser_agent(
    llm_provider: LLMProvider | str = LLMProvider.ANTHROPIC,
    llm_model: str | None = None,
    download_dir: Path | None = None,
    headless: bool = True,
    **llm_kwargs,
) -> BrowserAgent:
    """Factory function to create a browser agent."""
    download_controller = DownloadController(download_dir=download_dir) if download_dir else None
    return BrowserAgent(
        llm_provider=llm_provider,
        llm_model=llm_model,
        llm_kwargs=llm_kwargs,
        download_controller=download_controller,
        headless=headless,
    )
