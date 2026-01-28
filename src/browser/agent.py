"""Browser-use agent wrapper for web navigation and content discovery."""

import asyncio
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable

from platformdirs import user_cache_dir
from pydantic import BaseModel

from .download_action import DownloadController, DownloadResult
from .notes import NotesDB, get_notes_db, NoteType
from .chrome_manager import ChromeManager

logger = logging.getLogger(__name__)

# App name for platformdirs
APP_NAME = "graboid"


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
class NavigationStep:
    """A single step in the navigation process."""
    step_number: int
    action: str  # What Claude did
    observation: str  # What Claude saw/found
    url: str | None = None
    screenshot_data: bytes | None = None  # Optional actual screenshot
    is_error: bool = False
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


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
    steps: list[NavigationStep] = field(default_factory=list)  # Step-by-step record
    raw_output: str = ""  # Full Claude output for debugging


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
        chrome_debug_port: int = 9222,
        downloads_dir: Path | None = None,
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
            chrome_debug_port: Port for Chrome remote debugging (for Claude Code)
            downloads_dir: Directory for browser downloads
        """
        self.llm_provider = llm_provider
        self.llm_model = llm_model
        self.llm_kwargs = llm_kwargs or {}
        self.download_controller = download_controller or DownloadController()
        self.headless = headless
        self.use_vision = use_vision
        self.notes_db = notes_db or get_notes_db()
        self._screenshot_callback = screenshot_callback
        self.chrome_debug_port = chrome_debug_port
        self.downloads_dir = downloads_dir or Path(user_cache_dir(APP_NAME)) / "downloads"

        self._llm = None
        self._browser = None
        self._chrome_manager: ChromeManager | None = None
        self._log_callback: Callable[[str, str], Any] | None = None

    def set_screenshot_callback(self, callback: ScreenshotCallback | None) -> None:
        """Set or clear the screenshot callback."""
        self._screenshot_callback = callback

    def set_log_callback(self, callback: "Callable[[str, str], Any] | None") -> None:
        """Set or clear the log callback for streaming output to job logs."""
        self._log_callback = callback

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

    async def _ensure_chrome_manager(self) -> ChromeManager:
        """Ensure Chrome manager is running with CDP configured."""
        if self._chrome_manager is None or not self._chrome_manager.is_running:
            logger.info("Starting managed Chrome instance with CDP...")
            self._chrome_manager = ChromeManager(
                debug_port=self.chrome_debug_port,
                headless=self.headless,
                downloads_dir=self.downloads_dir,
            )
            if not await self._chrome_manager.start():
                raise RuntimeError("Failed to start managed Chrome instance")
            logger.info(f"Chrome ready at {self._chrome_manager.debug_url}")
        return self._chrome_manager

    async def _navigate_with_claude_chrome(
        self,
        target: NavigationTarget,
        max_steps: int = 50,
    ) -> NavigationResult:
        """
        Navigate using Claude Code with a managed Chrome instance.

        This launches our own Chrome with CDP configured for:
        - Automatic downloads to a known directory (no Save As dialog)
        - Remote debugging for Claude to connect to
        """
        import re

        # Start managed Chrome with CDP
        chrome = await self._ensure_chrome_manager()
        logger.info(f"Using managed Chrome at {chrome.debug_url}")
        logger.info(f"Downloads will go to: {chrome.downloads_dir}")

        # Build task prompt
        task = self._build_task_prompt(target)

        # Create MCP config for chrome-devtools pointing to our managed Chrome
        import json as json_module
        mcp_config = {
            "mcpServers": {
                "chrome-devtools": {
                    "command": "npx",
                    "args": [
                        "chrome-devtools-mcp@latest",
                        "--browserUrl", chrome.debug_url,
                    ],
                }
            }
        }
        mcp_config_json = json_module.dumps(mcp_config)

        # Build command with MCP config for chrome-devtools
        cmd = [
            "claude",
            "-p",
            "--model", self.llm_model or "sonnet",
            "--mcp-config", mcp_config_json,
            "--strict-mcp-config",  # Only use our config, not user's
            "--dangerously-skip-permissions",
            "--output-format", "text",
            f"""You have access to chrome-devtools MCP tools to control a browser.
The browser is already running with downloads configured to: {chrome.downloads_dir}

Navigate to {target.url} and complete this task:

{task}

BROWSER CONTROL:
Use the chrome-devtools MCP tools to control the browser. Available tools include:
- cdp_navigate: Navigate to URLs
- cdp_screenshot: Take screenshots
- cdp_click: Click elements
- cdp_type: Type text
- cdp_evaluate: Run JavaScript

Downloads are automatically saved to {chrome.downloads_dir} - no Save As dialog.
You CAN click download buttons - files will download automatically.

OUTPUT FORMAT (REQUIRED):
Document every action with these labels:

[STEP N] ACTION: <what you're doing>
[STEP N] URL: <current page URL>
[STEP N] OBSERVATION: <what you see>

When you find/trigger downloads:
[DOWNLOAD] URL: <the download URL>
[DOWNLOAD] NAME: <filename>
[DOWNLOAD] TRIGGERED: <true if you clicked a download button>

If errors occur:
[ERROR] PROBLEM: <what went wrong>

At the end:
[RESULT] SUCCESS: <true/false>
[RESULT] FINAL_URL: <last URL>

Learnings:
[LEARNING: type=navigation_tip] <tips for this site>

Start by using cdp_navigate to go to {target.url}.""",
        ]

        logger.info(f"Running Claude CLI with chrome-devtools MCP")

        # Record existing files in downloads dir before navigation
        existing_files = set()
        if chrome.downloads_dir.exists():
            existing_files = {f.name for f in chrome.downloads_dir.iterdir() if f.is_file()}

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            # Stream output in real-time instead of waiting for completion
            output_lines = []
            steps_so_far = []
            screenshots_collected: list[tuple[bytes, str, str]] = []

            last_screenshot_step = 0

            async def _capture_step_screenshot(step: NavigationStep):
                """Take a CDP screenshot and fire the callback."""
                nonlocal last_screenshot_step
                if step.step_number == last_screenshot_step:
                    return
                last_screenshot_step = step.step_number
                try:
                    url = await chrome.get_current_url() or step.url or ""
                    screenshot_data = await chrome.take_screenshot()
                    if screenshot_data:
                        description = f"Step {step.step_number}: {step.action}"
                        if step.observation:
                            description += f" - {step.observation[:80]}"
                        step.screenshot_data = screenshot_data
                        screenshots_collected.append((screenshot_data, url, description))
                        if self._screenshot_callback:
                            cb_result = self._screenshot_callback(screenshot_data, url, description)
                            if asyncio.iscoroutine(cb_result):
                                await cb_result
                except Exception as e:
                    logger.debug(f"Step screenshot failed: {e}")

            async def read_stream(stream, prefix=""):
                """Read stream line by line and log in real-time."""
                while True:
                    line = await stream.readline()
                    if not line:
                        break
                    decoded = line.decode().rstrip()
                    if decoded:
                        logger.info(f"[CLAUDE {prefix}] {decoded}")
                        output_lines.append(decoded)

                        # Stream to job log callback
                        if self._log_callback:
                            try:
                                result = self._log_callback(decoded, "INFO")
                                if asyncio.iscoroutine(result):
                                    await result
                            except Exception:
                                pass

                        # Try to parse steps in real-time
                        step = self._try_parse_step_line(decoded, len(steps_so_far) + 1)
                        if step:
                            steps_so_far.append(step)
                            logger.info(f"[STEP {step.step_number}] {step.action}: {step.observation[:100] if step.observation else ''}")
                            # Capture a screenshot for this step
                            await _capture_step_screenshot(step)

            # Read stdout and stderr concurrently
            try:
                await asyncio.wait_for(
                    asyncio.gather(
                        read_stream(proc.stdout, "OUT"),
                        read_stream(proc.stderr, "ERR"),
                    ),
                    timeout=300,  # 5 minute timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                raise

            await proc.wait()
            response = "\n".join(output_lines)

            # Log summary
            logger.info(f"=== CLAUDE CHROME COMPLETE ({len(output_lines)} lines) ===")

            # Use steps collected during streaming (they include screenshots);
            # fall back to post-hoc parsing only when streaming captured nothing.
            if steps_so_far:
                steps = steps_so_far
                logger.info(f"Using {len(steps)} steps captured during streaming")
            else:
                steps = self._parse_navigation_steps(response)
                logger.info(f"Parsed {len(steps)} navigation steps from response")

            if proc.returncode != 0:
                error_msg = stderr.decode() if stderr else "Unknown error"
                logger.error(f"Claude CLI error: {error_msg}")
                return NavigationResult(
                    success=False,
                    error=f"Claude CLI failed: {error_msg}",
                    steps=steps,
                    raw_output=response,
                )

            # Extract URLs from response - prefer explicitly marked URLs first
            found_links = []

            # 1. First look for [DOWNLOAD] URL: format
            download_urls = re.findall(
                r'\[DOWNLOAD\]\s*URL:\s*(https?://[^\s<>"\']+)',
                response,
                re.IGNORECASE,
            )
            found_links.extend(download_urls)

            # 2. Look for DOWNLOAD_URL: format (legacy)
            explicit_urls = re.findall(
                r'DOWNLOAD_URL:\s*(https?://[^\s<>"\']+)',
                response,
                re.IGNORECASE,
            )
            found_links.extend(explicit_urls)

            # 3. Look for URLs in markdown link format [text](url)
            markdown_urls = re.findall(
                r'\[.*?\]\((https?://[^\s<>"\'(){}]+\.(?:zip|7z|rar|torrent|iso|chd|bin|cue)[^\s<>"\'(){}]*)\)',
                response,
                re.IGNORECASE,
            )
            found_links.extend(markdown_urls)

            # 4. Find other direct download URLs (but these may be less reliable)
            urls = re.findall(
                r'https?://[^\s<>"\'{}]+\.(?:zip|7z|rar|torrent|iso|chd|bin|cue)(?:\?[^\s<>"\'{}]*)?',
                response,
                re.IGNORECASE,
            )
            found_links.extend(urls)

            # 5. Find magnet links
            magnets = re.findall(r'magnet:\?[^\s<>"\']+', response)
            found_links.extend(magnets)

            # Deduplicate while preserving order
            found_links = list(dict.fromkeys(found_links))

            # Filter out template URLs (containing {placeholders})
            found_links = [url for url in found_links if '{' not in url and '}' not in url]

            # Clean URLs (remove trailing punctuation)
            found_links = [url.rstrip('.,;:)') for url in found_links]

            logger.info(f"Found {len(found_links)} download links:")
            for url in found_links:
                logger.info(f"  - {url}")

            # Extract error information if no links found
            error_msg = None
            if not found_links:
                # Look for [ERROR] sections
                errors = re.findall(
                    r'\[ERROR\]\s*PROBLEM:\s*(.+?)(?:\n|$)',
                    response,
                    re.IGNORECASE,
                )
                if errors:
                    error_msg = f"Navigation errors: {'; '.join(errors)}"
                else:
                    error_msg = "No download links found in Claude's response"

                # Add a failure step
                steps.append(NavigationStep(
                    step_number=len(steps) + 1,
                    action="Search complete",
                    observation=error_msg,
                    is_error=True,
                ))

            success = len(found_links) > 0

            # Check for new files in downloads directory
            downloaded_files: list[DownloadResult] = []
            if chrome.downloads_dir.exists():
                current_files = {f.name for f in chrome.downloads_dir.iterdir() if f.is_file()}
                new_files = current_files - existing_files
                if new_files:
                    logger.info(f"New files downloaded: {new_files}")
                    for filename in new_files:
                        filepath = chrome.downloads_dir / filename
                        downloaded_files.append(DownloadResult(
                            success=True,
                            filepath=filepath,
                            url="",  # URL unknown from browser download
                        ))
                    # If we got downloads, consider it a success even if no URLs extracted
                    if not success and downloaded_files:
                        success = True
                        error_msg = None

            # Extract learnings
            self._extract_and_save_learnings(response, target, success)

            # Extract final URL
            final_url_match = re.search(
                r'\[RESULT\]\s*FINAL_URL:\s*(https?://[^\s<>"\']+)',
                response,
                re.IGNORECASE,
            )
            final_url = final_url_match.group(1) if final_url_match else target.url

            return NavigationResult(
                success=success,
                found_links=found_links,
                downloads=downloaded_files,
                final_url=final_url,
                error=error_msg,
                steps=steps,
                screenshots=screenshots_collected,
                raw_output=response,
            )

        except asyncio.TimeoutError:
            logger.error("Claude CLI timeout")
            return NavigationResult(
                success=False,
                error="Claude CLI timeout after 5 minutes",
                steps=[NavigationStep(
                    step_number=1,
                    action="Timeout",
                    observation="Claude CLI did not respond within 5 minutes",
                    is_error=True,
                )],
            )
        except Exception as e:
            logger.error(f"Navigation failed: {e}")
            return NavigationResult(
                success=False,
                error=str(e),
                steps=[NavigationStep(
                    step_number=1,
                    action="Exception",
                    observation=str(e),
                    is_error=True,
                )],
            )

    def _try_parse_step_line(self, line: str, default_step_num: int) -> NavigationStep | None:
        """Try to parse a single line as a step entry."""
        import re

        # Look for [STEP N] patterns
        step_match = re.match(r'\[STEP\s*(\d+)\]\s*(ACTION|URL|OBSERVATION):\s*(.+)', line, re.IGNORECASE)
        if step_match:
            return NavigationStep(
                step_number=int(step_match.group(1)),
                action=step_match.group(2).upper(),
                observation=step_match.group(3).strip(),
            )

        # Look for common action descriptions
        action_patterns = [
            (r'navigat(?:ing|ed?) to (.+)', 'Navigate'),
            (r'click(?:ing|ed?) (?:on )?(.+)', 'Click'),
            (r'scroll(?:ing|ed?) (.+)', 'Scroll'),
            (r'typing (.+)', 'Type'),
            (r'waiting (.+)', 'Wait'),
            (r'found (.+)', 'Found'),
            (r'error[:\s]+(.+)', 'Error'),
        ]

        for pattern, action_type in action_patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                return NavigationStep(
                    step_number=default_step_num,
                    action=action_type,
                    observation=match.group(1).strip()[:200],
                    is_error=(action_type == 'Error'),
                )

        return None

    def _parse_navigation_steps(self, response: str) -> list[NavigationStep]:
        """Parse [STEP N] entries from Claude's response."""
        import re

        steps = []

        # Find all step entries
        step_pattern = r'\[STEP\s*(\d+)\]\s*(ACTION|URL|OBSERVATION):\s*(.+?)(?=\[STEP|\[DOWNLOAD|\[ERROR|\[RESULT|\[LEARNING|$)'
        matches = re.findall(step_pattern, response, re.IGNORECASE | re.DOTALL)

        # Group by step number
        step_data: dict[int, dict[str, str]] = {}
        for step_num, field_type, content in matches:
            num = int(step_num)
            if num not in step_data:
                step_data[num] = {}
            step_data[num][field_type.upper()] = content.strip()

        # Create NavigationStep objects
        for num in sorted(step_data.keys()):
            data = step_data[num]
            steps.append(NavigationStep(
                step_number=num,
                action=data.get('ACTION', 'Unknown action'),
                observation=data.get('OBSERVATION', ''),
                url=data.get('URL'),
            ))

        # If no structured steps found, try to extract actions from the text
        if not steps:
            # Look for common action patterns
            action_patterns = [
                (r'navigat(?:ing|ed?) to ([^\n]+)', 'Navigate'),
                (r'click(?:ing|ed?) (?:on )?([^\n]+)', 'Click'),
                (r'scroll(?:ing|ed?) ([^\n]+)', 'Scroll'),
                (r'found? ([^\n]+)', 'Found'),
                (r'looking for ([^\n]+)', 'Search'),
            ]

            step_num = 1
            for pattern, action_type in action_patterns:
                for match in re.finditer(pattern, response, re.IGNORECASE):
                    steps.append(NavigationStep(
                        step_number=step_num,
                        action=action_type,
                        observation=match.group(1).strip()[:200],  # Limit length
                    ))
                    step_num += 1

        return steps

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

        For claude_code provider, uses Claude's native --chrome integration.
        For other providers, uses browser-use.

        Args:
            target: Navigation target with URL and platform info
            max_steps: Maximum navigation steps

        Returns:
            NavigationResult with found links and any downloads
        """
        # Use Claude's native chrome integration for claude_code provider
        if self.llm_provider == LLMProvider.CLAUDE_CODE or self.llm_provider == "claude_code":
            return await self._navigate_with_claude_chrome(target, max_steps)

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
        label: str | None = None,
        success: bool | None = None,
    ) -> None:
        """Manually add a note about a site."""
        self.notes_db.add_note(
            url_or_domain=url,
            note_type=note_type,
            content=content,
            label=label,
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
        if self._chrome_manager:
            await self._chrome_manager.stop()
            self._chrome_manager = None


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
