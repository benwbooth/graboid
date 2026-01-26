"""Browser agent using Claude Code's native Chrome integration."""

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .notes import NotesDB, get_notes_db, NoteType

logger = logging.getLogger(__name__)


@dataclass
class ChromeNavigationResult:
    """Result of a Chrome navigation task."""
    success: bool
    downloads: list[str] = field(default_factory=list)  # Download URLs found
    magnets: list[str] = field(default_factory=list)    # Magnet links found
    error: str | None = None
    final_url: str | None = None
    raw_output: str = ""


class ChromeBrowserAgent:
    """
    Browser agent using Claude Code's native Chrome integration.

    This uses `claude --chrome` to control the browser directly,
    leveraging Claude's built-in browser tools:
    - navigate: Go to URLs
    - read_page: Get page elements
    - find: Find elements with natural language
    - computer: Mouse/keyboard/screenshots
    - form_input: Fill forms
    - get_page_text: Extract text
    - javascript_tool: Run JS
    """

    def __init__(
        self,
        model: str = "sonnet",
        timeout: int = 300,
        headless: bool = False,
        notes_db: NotesDB | None = None,
    ):
        """
        Initialize Chrome browser agent.

        Args:
            model: Claude model to use (sonnet, opus, haiku)
            timeout: Timeout in seconds for navigation tasks
            headless: Use Xvfb for headless operation (requires xvfb-run)
            notes_db: Database for storing/retrieving navigation notes
        """
        self.model = model
        self.timeout = timeout
        self.headless = headless
        self.notes_db = notes_db or get_notes_db()

    async def navigate_and_find_downloads(
        self,
        url: str,
        description: str = "",
        label: str | None = None,
    ) -> ChromeNavigationResult:
        """
        Navigate to URL and find download links.

        Args:
            url: URL to navigate to
            description: What to look for (optional)
            label: Label for categorization (optional)

        Returns:
            ChromeNavigationResult with found downloads
        """
        # Get any previous knowledge about this site
        previous_knowledge = self.notes_db.format_notes_for_prompt(url, max_notes=5)

        task_description = description or "find downloadable content"

        prompt = f"""Navigate to {url} and {task_description}.

{previous_knowledge}

Instructions:
1. Go to the URL
2. Look for downloadable content - files, archives, torrents, magnet links
3. If there are lists or directories, explore them
4. Handle any popups, cookie banners, or age verification if needed
5. Report ALL download URLs you find

When done, output your findings in this exact format:
---DOWNLOADS---
[list each download URL on its own line]
---MAGNETS---
[list each magnet link on its own line]
---FINAL_URL---
[the final URL you ended up on]
---LEARNINGS---
[any tips about navigating this site for future reference]
---END---
"""

        try:
            result = await self._run_chrome_task(prompt)
            return self._parse_result(result, url, label)
        except Exception as e:
            logger.error(f"Chrome navigation failed: {e}")
            return ChromeNavigationResult(
                success=False,
                error=str(e),
            )

    async def _run_chrome_task(self, prompt: str) -> str:
        """Run a task using Claude's Chrome integration."""
        claude_cmd = [
            "claude",
            "--chrome",
            "--model", self.model,
            "--dangerously-skip-permissions",
            "-p",
            prompt,
        ]

        # Wrap with xvfb-run for headless operation
        if self.headless:
            cmd = ["xvfb-run", "-a", "--server-args=-screen 0 1920x1080x24"] + claude_cmd
        else:
            cmd = claude_cmd

        logger.info(f"Running Chrome task with model {self.model} (headless={self.headless})")
        logger.debug(f"Prompt: {prompt[:200]}...")

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=self.timeout,
            )
        except asyncio.TimeoutError:
            proc.kill()
            raise RuntimeError(f"Chrome task timed out after {self.timeout}s")

        if proc.returncode != 0:
            error = stderr.decode() if stderr else "Unknown error"
            raise RuntimeError(f"Chrome task failed: {error}")

        return stdout.decode()

    def _parse_result(
        self,
        output: str,
        url: str,
        label: str | None,
    ) -> ChromeNavigationResult:
        """Parse the structured output from Claude."""
        result = ChromeNavigationResult(
            success=False,
            raw_output=output,
        )

        # Extract downloads section
        downloads_match = re.search(
            r'---DOWNLOADS---\s*(.*?)\s*---',
            output,
            re.DOTALL | re.IGNORECASE
        )
        if downloads_match:
            lines = downloads_match.group(1).strip().split('\n')
            for line in lines:
                line = line.strip()
                if line and line.startswith(('http://', 'https://', 'ftp://')):
                    result.downloads.append(line)

        # Extract magnets section
        magnets_match = re.search(
            r'---MAGNETS---\s*(.*?)\s*---',
            output,
            re.DOTALL | re.IGNORECASE
        )
        if magnets_match:
            lines = magnets_match.group(1).strip().split('\n')
            for line in lines:
                line = line.strip()
                if line.startswith('magnet:'):
                    result.magnets.append(line)

        # Extract final URL
        url_match = re.search(
            r'---FINAL_URL---\s*(.*?)\s*---',
            output,
            re.DOTALL | re.IGNORECASE
        )
        if url_match:
            result.final_url = url_match.group(1).strip()

        # Extract and save learnings
        learnings_match = re.search(
            r'---LEARNINGS---\s*(.*?)\s*---END---',
            output,
            re.DOTALL | re.IGNORECASE
        )
        if learnings_match:
            learning = learnings_match.group(1).strip()
            if learning and learning.lower() not in ('none', 'n/a', ''):
                try:
                    self.notes_db.add_note(
                        url_or_domain=url,
                        note_type="navigation_tip",
                        content=learning,
                        label=label,
                        success=len(result.downloads) > 0 or len(result.magnets) > 0,
                    )
                except Exception as e:
                    logger.warning(f"Failed to save learning: {e}")

        # Determine success
        result.success = len(result.downloads) > 0 or len(result.magnets) > 0

        # Also try to extract URLs from raw output if structured parsing failed
        if not result.success:
            # Look for download-like URLs anywhere in output
            url_pattern = r'https?://[^\s<>"\']+\.(?:zip|7z|rar|tar|gz|iso|torrent|chd|bin|cue)'
            found_urls = re.findall(url_pattern, output, re.IGNORECASE)
            result.downloads.extend(found_urls)

            # Look for magnet links
            magnet_pattern = r'magnet:\?[^\s<>"\']+'
            found_magnets = re.findall(magnet_pattern, output)
            result.magnets.extend(found_magnets)

            result.success = len(result.downloads) > 0 or len(result.magnets) > 0

        # Deduplicate
        result.downloads = list(dict.fromkeys(result.downloads))
        result.magnets = list(dict.fromkeys(result.magnets))

        logger.info(f"Found {len(result.downloads)} downloads, {len(result.magnets)} magnets")
        return result

    async def execute_custom_task(self, prompt: str) -> str:
        """
        Execute a custom browser task.

        Args:
            prompt: The task description for Claude

        Returns:
            Raw output from Claude
        """
        return await self._run_chrome_task(prompt)

    async def take_screenshot(self, url: str | None = None) -> bytes | None:
        """
        Take a screenshot of the current page or navigate to URL first.

        Returns:
            Screenshot bytes or None if failed
        """
        prompt = f"""{"Navigate to " + url + " and then t" if url else "T"}ake a screenshot of the current page.

Save the screenshot and tell me the file path where you saved it."""

        try:
            result = await self._run_chrome_task(prompt)
            # Try to extract file path from result
            path_match = re.search(r'/[^\s]+\.(?:png|jpg|jpeg)', result)
            if path_match:
                path = Path(path_match.group())
                if path.exists():
                    return path.read_bytes()
        except Exception as e:
            logger.error(f"Screenshot failed: {e}")

        return None


async def create_chrome_agent(
    model: str = "sonnet",
    timeout: int = 300,
    headless: bool = False,
) -> ChromeBrowserAgent:
    """Factory function to create a Chrome browser agent."""
    return ChromeBrowserAgent(model=model, timeout=timeout, headless=headless)
