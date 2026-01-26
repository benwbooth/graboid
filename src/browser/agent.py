"""Browser-use agent wrapper for web navigation and content discovery."""

import asyncio
import logging
import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

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

    else:
        raise ValueError(f"Unknown provider: {provider}")


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
        """
        self.llm_provider = llm_provider
        self.llm_model = llm_model
        self.llm_kwargs = llm_kwargs or {}
        self.download_controller = download_controller or DownloadController()
        self.headless = headless
        self.use_vision = use_vision
        self.notes_db = notes_db or get_notes_db()

        self._llm = None
        self._browser = None

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
        """Lazy-load browser instance."""
        if self._browser is None:
            from browser_use import Browser

            self._browser = Browser(
                headless=self.headless,
                disable_security=True,  # Needed for some ROM sites
            )
        return self._browser

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

        logger.info(f"Starting browser navigation: {target.platform}")
        logger.debug(f"Task: {task}")

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

            # Run the agent - browser-use handles everything
            history = await agent.run(max_steps=max_steps)

            # Extract results from history
            return self._process_history(history, target)

        except Exception as e:
            logger.error(f"Navigation failed: {e}")
            return NavigationResult(
                success=False,
                error=str(e),
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
                    platform=target.platform,
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
        platform: str,
        max_steps: int = 30,
    ) -> list[str]:
        """
        Convenience method to find download links on a page.

        Args:
            url: Page URL to scan
            platform: Platform name for context
            max_steps: Maximum steps

        Returns:
            List of download URLs found
        """
        target = NavigationTarget(
            url=url,
            platform=platform,
            source_type="unknown",
        )
        result = await self.navigate_to_roms(target, max_steps=max_steps)
        return result.found_links

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
