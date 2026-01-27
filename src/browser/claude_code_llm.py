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

# Try to import LangChain message types for proper type checking
try:
    from langchain_core.messages import BaseMessage
    HAS_LANGCHAIN = True
except ImportError:
    HAS_LANGCHAIN = False
    BaseMessage = None


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
        self.model_name = model  # Required by browser-use
        self.timeout = timeout
        self.max_tokens = max_tokens
        self.provider = "claude_code"  # Required by browser-use
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

    def _extract_images_and_text(self, messages: list) -> tuple[str, list[Path]]:
        """
        Extract text and images from messages.

        Handles both dict messages and LangChain message objects.

        Returns:
            Tuple of (combined text prompt, list of image paths)
        """
        text_parts = []
        image_paths = []

        for msg in messages:
            # Handle both dict and LangChain message objects
            # Check for LangChain BaseMessage first (more reliable than hasattr)
            if HAS_LANGCHAIN and BaseMessage is not None and isinstance(msg, BaseMessage):
                # LangChain message object
                role = msg.type  # 'system', 'human', 'ai'
                content = msg.content
            elif isinstance(msg, dict):
                role = msg.get("role", "user")
                content = msg.get("content", "")
            else:
                # Fallback: try to access .type and .content attributes
                role = getattr(msg, 'type', 'user')
                content = getattr(msg, 'content', str(msg))

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

    def _build_prompt(self, text: str, image_paths: list[Path], output_format: Any = None) -> str:
        """Build the prompt for Claude CLI."""
        parts = []

        if image_paths:
            # Include instructions to read images
            image_instructions = []
            for i, path in enumerate(image_paths, 1):
                image_instructions.append(f"Image {i}: Read and analyze the image at {path}")
            parts.append(f"IMAGES TO ANALYZE:\n{chr(10).join(image_instructions)}")
            parts.append("IMPORTANT: Use the Read tool to view each image file listed above before responding.")

        parts.append(f"CONVERSATION:\n{text}")

        # If output_format is provided, include JSON schema instructions
        if output_format is not None:
            try:
                schema = output_format.model_json_schema()
                schema_str = json.dumps(schema, indent=2)
                parts.append(f"""
IMPORTANT: You MUST respond with ONLY valid JSON matching this schema:
{schema_str}

Required fields: evaluation_previous_goal, memory, next_goal, action

The 'action' field must be a list with at least one action object. Each action should have exactly ONE action type.
Common action types: go_to_url, click_element, input_text, scroll_down, scroll_up, done

Example response format:
{{
  "evaluation_previous_goal": "Evaluating what happened after the last action",
  "memory": "Key information to remember",
  "next_goal": "What I will do next",
  "action": [
    {{"go_to_url": {{"url": "https://example.com"}}}}
  ]
}}

Respond with ONLY the JSON object, no other text or markdown.""")
            except Exception as e:
                logger.warning(f"Could not get JSON schema: {e}")

        return "\n\n".join(parts)

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

    def _extract_json(self, text: str) -> str:
        """Extract JSON from response text, handling markdown code blocks."""
        text = text.strip()
        # Try to extract from markdown code blocks
        if "```json" in text:
            start = text.find("```json") + 7
            end = text.find("```", start)
            if end > start:
                text = text[start:end].strip()
        elif "```" in text:
            start = text.find("```") + 3
            end = text.find("```", start)
            if end > start:
                text = text[start:end].strip()
        # Find JSON object boundaries
        if text.startswith("{"):
            # Find matching closing brace
            depth = 0
            for i, c in enumerate(text):
                if c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        return text[:i+1]
        return text

    async def ainvoke(self, messages: list[dict], *args, **kwargs) -> "AIMessage":
        """
        Async invoke - main entry point for browser-use.

        Args:
            messages: List of message dicts with role and content
            *args: Additional positional arguments (ignored)
            **kwargs: Additional keyword arguments including output_format

        Returns:
            AIMessage-like object with content and completion
        """
        output_format = kwargs.get("output_format")
        text, image_paths = self._extract_images_and_text(messages)
        prompt = self._build_prompt(text, image_paths, output_format)

        try:
            response = await self._call_claude_cli(prompt, image_paths)

            # Try to parse structured output if output_format is provided
            completion = None
            if output_format is not None:
                logger.info(f"Attempting to parse response into {output_format.__name__}")
                logger.info(f"Raw response (first 1000 chars): {response[:1000]}")
                try:
                    json_str = self._extract_json(response)
                    logger.info(f"Extracted JSON (first 500 chars): {json_str[:500]}")
                    data = json.loads(json_str)
                    completion = output_format.model_validate(data)
                    logger.info(f"Successfully parsed response into {output_format.__name__}")
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse JSON from response: {e}")
                    logger.error(f"Response was: {response[:1000]}")
                except Exception as e:
                    logger.error(f"Failed to validate response against schema: {e}")
                    logger.error(f"JSON data: {json_str[:1000] if 'json_str' in dir() else 'N/A'}")

            return AIMessage(content=response, completion=completion)
        finally:
            # Cleanup temp images
            for path in image_paths:
                self._cleanup_image(path)

    def invoke(self, messages: list[dict], *args, **kwargs) -> "AIMessage":
        """Sync invoke - runs async version."""
        return asyncio.run(self.ainvoke(messages, *args, **kwargs))

    async def astream(self, messages: list[dict], *args, **kwargs) -> AsyncIterator["AIMessage"]:
        """Async stream - browser-use may use this."""
        result = await self.ainvoke(messages, *args, **kwargs)
        yield result

    def stream(self, messages: list[dict], *args, **kwargs) -> Iterator["AIMessage"]:
        """Sync stream."""
        result = self.invoke(messages, *args, **kwargs)
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

    def __init__(self, content: str, tool_calls: list | None = None, completion: Any = None):
        self.content = content
        self.tool_calls = tool_calls or []
        self.additional_kwargs = {}
        self.response_metadata = {}  # LangChain compatibility
        self.id = None  # Message ID
        self.completion = completion  # Parsed structured output for browser-use
        # Mock usage stats as dict (browser-use/pydantic expects specific fields)
        output_tokens = len(content.split()) * 2  # Rough estimate
        self.usage_metadata = {
            'input_tokens': 0,
            'output_tokens': output_tokens,
            'total_tokens': output_tokens,
        }
        # browser-use expects these exact fields for TokenUsageEntry
        self.usage = {
            'prompt_tokens': 0,
            'prompt_cached_tokens': 0,
            'prompt_cache_creation_tokens': 0,
            'prompt_image_tokens': 0,
            'completion_tokens': output_tokens,
            'total_tokens': output_tokens,
        }

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
