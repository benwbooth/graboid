"""Claude Code CLI wrapper for browser-use LLM interface."""

import asyncio
import base64
import json
import logging
import os
import tempfile
import uuid
from pathlib import Path
from typing import Any, AsyncIterator, Iterator

logger = logging.getLogger(__name__)


class ClaudeCodeChat:
    """
    LLM wrapper that shells out to Claude Code CLI.

    This allows using Claude Max subscription for browser-use
    by routing requests through the claude CLI.
    """

    def __init__(
        self,
        model: str = "sonnet",
        timeout: int = 120,
        max_tokens: int = 4096,
    ):
        """
        Initialize Claude Code wrapper.

        Args:
            model: Model alias (sonnet, opus, haiku) or full name
            timeout: Timeout in seconds for CLI calls
            max_tokens: Max tokens for response (informational, CLI handles this)
        """
        self.model = model
        self.timeout = timeout
        self.max_tokens = max_tokens
        self._temp_dir = Path(tempfile.gettempdir()) / "graboid_screenshots"
        self._temp_dir.mkdir(exist_ok=True)

    def _save_image(self, base64_data: str) -> Path:
        """Save base64 image to temp file, return path."""
        img_path = self._temp_dir / f"{uuid.uuid4()}.png"
        img_bytes = base64.b64decode(base64_data)
        img_path.write_bytes(img_bytes)
        return img_path

    def _cleanup_image(self, path: Path) -> None:
        """Remove temp image file."""
        try:
            path.unlink(missing_ok=True)
        except Exception:
            pass

    def _extract_images_and_text(self, messages: list[dict]) -> tuple[str, list[Path]]:
        """
        Extract text and images from messages.

        Returns:
            Tuple of (combined text prompt, list of image paths)
        """
        text_parts = []
        image_paths = []

        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")

            if isinstance(content, str):
                text_parts.append(f"[{role}]: {content}")
            elif isinstance(content, list):
                # Handle multimodal content
                for part in content:
                    if isinstance(part, dict):
                        if part.get("type") == "text":
                            text_parts.append(f"[{role}]: {part.get('text', '')}")
                        elif part.get("type") == "image_url":
                            # Handle image URL (base64 or file)
                            url = part.get("image_url", {}).get("url", "")
                            if url.startswith("data:image"):
                                # Extract base64 data
                                _, b64 = url.split(",", 1)
                                img_path = self._save_image(b64)
                                image_paths.append(img_path)
                                text_parts.append(f"[{role}]: [See image: {img_path}]")
                        elif part.get("type") == "image":
                            # Direct base64 image
                            if "source" in part and "data" in part["source"]:
                                img_path = self._save_image(part["source"]["data"])
                                image_paths.append(img_path)
                                text_parts.append(f"[{role}]: [See image: {img_path}]")
                    elif isinstance(part, str):
                        text_parts.append(f"[{role}]: {part}")

        return "\n\n".join(text_parts), image_paths

    def _build_prompt(self, text: str, image_paths: list[Path]) -> str:
        """Build the prompt for Claude CLI."""
        if not image_paths:
            return text

        # Include instructions to read images
        image_instructions = []
        for i, path in enumerate(image_paths, 1):
            image_instructions.append(f"Image {i}: Read and analyze the image at {path}")

        return f"""You are a browser automation assistant. Analyze the following conversation and images to decide what action to take.

IMAGES TO ANALYZE:
{chr(10).join(image_instructions)}

IMPORTANT: Use the Read tool to view each image file listed above before responding.

CONVERSATION:
{text}

Based on the screenshots and conversation, decide the next browser action. Respond with your analysis and the action to take."""

    async def _call_claude_cli(self, prompt: str, image_paths: list[Path]) -> str:
        """Call claude CLI and return response."""
        # Build command
        cmd = [
            "claude",
            "-p",  # Print mode (non-interactive)
            "--model", self.model,
            "--dangerously-skip-permissions",  # Need this to read files without prompts
            "--output-format", "text",
            prompt,
        ]

        logger.debug(f"Calling claude CLI with {len(image_paths)} images")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(self._temp_dir),  # Run in temp dir so it can read images
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=self.timeout,
            )

            if proc.returncode != 0:
                error_msg = stderr.decode() if stderr else "Unknown error"
                logger.error(f"Claude CLI error: {error_msg}")
                raise RuntimeError(f"Claude CLI failed: {error_msg}")

            response = stdout.decode().strip()
            logger.debug(f"Claude CLI response: {response[:200]}...")
            return response

        except asyncio.TimeoutError:
            logger.error(f"Claude CLI timeout after {self.timeout}s")
            raise RuntimeError(f"Claude CLI timeout after {self.timeout}s")

    async def ainvoke(self, messages: list[dict], **kwargs) -> "AIMessage":
        """
        Async invoke - main entry point for browser-use.

        Args:
            messages: List of message dicts with role and content
            **kwargs: Additional arguments (ignored)

        Returns:
            AIMessage-like object with content
        """
        text, image_paths = self._extract_images_and_text(messages)
        prompt = self._build_prompt(text, image_paths)

        try:
            response = await self._call_claude_cli(prompt, image_paths)
            return AIMessage(content=response)
        finally:
            # Cleanup temp images
            for path in image_paths:
                self._cleanup_image(path)

    def invoke(self, messages: list[dict], **kwargs) -> "AIMessage":
        """Sync invoke - runs async version."""
        return asyncio.run(self.ainvoke(messages, **kwargs))

    async def astream(self, messages: list[dict], **kwargs) -> AsyncIterator["AIMessage"]:
        """Async stream - browser-use may use this."""
        result = await self.ainvoke(messages, **kwargs)
        yield result

    def stream(self, messages: list[dict], **kwargs) -> Iterator["AIMessage"]:
        """Sync stream."""
        result = self.invoke(messages, **kwargs)
        yield result

    def bind_tools(self, tools: list[Any], **kwargs) -> "ClaudeCodeChat":
        """Bind tools - browser-use calls this but we handle tools via prompt."""
        # Return self since we handle everything via prompt engineering
        return self

    def with_structured_output(self, schema: Any, **kwargs) -> "ClaudeCodeChat":
        """Structured output - return self, we'll parse from text."""
        return self


class AIMessage:
    """Simple message class to match LangChain interface."""

    def __init__(self, content: str, tool_calls: list | None = None):
        self.content = content
        self.tool_calls = tool_calls or []
        self.additional_kwargs = {}

    def __str__(self) -> str:
        return self.content


def get_claude_code_llm(
    model: str = "sonnet",
    timeout: int = 120,
    **kwargs,
) -> ClaudeCodeChat:
    """
    Factory function to create Claude Code CLI wrapper.

    Args:
        model: Model alias (sonnet, opus, haiku)
        timeout: CLI timeout in seconds

    Returns:
        ClaudeCodeChat instance
    """
    return ClaudeCodeChat(model=model, timeout=timeout, **kwargs)
