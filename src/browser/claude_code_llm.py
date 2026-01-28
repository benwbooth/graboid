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

        # If output_format is provided, include JSON schema instructions FIRST
        if output_format is not None:
            try:
                schema = output_format.model_json_schema()
                schema_str = json.dumps(schema, indent=2)
                parts.insert(0, f"""⚠️ CRITICAL: YOUR ENTIRE RESPONSE MUST BE VALID JSON. NO OTHER TEXT. ⚠️

You are a browser automation agent. Output ONLY a JSON object matching this schema:
{schema_str}

Required fields: evaluation_previous_goal, memory, next_goal, action

The 'action' field must be a list with at least one action. Each action has exactly ONE action type.
Common action types: go_to_url, click_element, input_text, scroll_down, scroll_up, done

Example (your response must look EXACTLY like this, just JSON):
{{"evaluation_previous_goal": "Starting task", "memory": "Need to navigate", "next_goal": "Go to website", "action": [{{"go_to_url": {{"url": "https://example.com"}}}}]}}

DO NOT include any explanations, markdown, or text outside the JSON object.""")
            except Exception as e:
                logger.warning(f"Could not get JSON schema: {e}")

        parts.append(f"CONVERSATION:\n{text}")

        return "\n\n".join(parts)

    async def _call_claude_cli(self, prompt: str, image_paths: list[Path], use_chrome: bool = False) -> str:
        """Call claude CLI and return response."""
        # Build command
        cmd = [
            "claude",
            "-p",  # Print mode (non-interactive)
            "--model", self.model,
            "--dangerously-skip-permissions",  # Need this to read files without prompts
            "--output-format", "text",
        ]

        # Add chrome integration if requested
        if use_chrome:
            cmd.append("--chrome")

        cmd.append(prompt)

        logger.debug(f"Calling claude CLI with {len(image_paths)} images, chrome={use_chrome}")

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

    async def ainvoke(self, messages: list[dict], *args, **kwargs):
        """
        Async invoke - main entry point for browser-use.

        Args:
            messages: List of message dicts with role and content
            *args: Additional positional arguments (ignored)
            **kwargs: Additional keyword arguments including output_format

        Returns:
            AIMessage-like object with content and completion
        """
        import sys
        print(f"[ClaudeCodeLLM] ainvoke called with {len(messages)} messages, args={args}, kwargs={list(kwargs.keys())}", file=sys.stderr)
        # output_format can be passed as positional arg or kwarg
        output_format = kwargs.get("output_format")
        if output_format is None and args:
            output_format = args[0]
        print(f"[ClaudeCodeLLM] output_format={output_format}", file=sys.stderr)
        text, image_paths = self._extract_images_and_text(messages)
        prompt = self._build_prompt(text, image_paths, output_format)

        try:
            response = await self._call_claude_cli(prompt, image_paths)

            # Try to parse structured output if output_format is provided
            completion = None
            if output_format is not None:
                import sys
                print(f"[ClaudeCodeLLM] Attempting to parse response into {output_format.__name__}", file=sys.stderr)
                print(f"[ClaudeCodeLLM] Raw response (first 500 chars): {response[:500]}", file=sys.stderr)
                try:
                    json_str = self._extract_json(response)
                    print(f"[ClaudeCodeLLM] Extracted JSON (first 300 chars): {json_str[:300]}", file=sys.stderr)
                    data = json.loads(json_str)
                    completion = output_format.model_validate(data)
                    print(f"[ClaudeCodeLLM] Successfully parsed response!", file=sys.stderr)
                except json.JSONDecodeError as e:
                    print(f"[ClaudeCodeLLM] Failed to parse JSON: {e}", file=sys.stderr)
                    print(f"[ClaudeCodeLLM] Response was: {response[:500]}", file=sys.stderr)
                except Exception as e:
                    print(f"[ClaudeCodeLLM] Failed to validate: {e}", file=sys.stderr)
                    print(f"[ClaudeCodeLLM] JSON data: {json_str[:500] if 'json_str' in dir() else 'N/A'}", file=sys.stderr)
            else:
                import sys
                print(f"[ClaudeCodeLLM] No output_format provided, skipping parsing", file=sys.stderr)

            return _create_completion_response(response, completion, output_format)
        finally:
            # Cleanup temp images
            for path in image_paths:
                self._cleanup_image(path)

    def invoke(self, messages: list[dict], *args, **kwargs):
        """Sync invoke - runs async version."""
        return asyncio.run(self.ainvoke(messages, *args, **kwargs))

    async def astream(self, messages: list[dict], *args, **kwargs) -> AsyncIterator:
        """Async stream - browser-use may use this."""
        result = await self.ainvoke(messages, *args, **kwargs)
        yield result

    def stream(self, messages: list[dict], *args, **kwargs) -> Iterator:
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


def _create_completion_response(content: str, completion: Any, output_format: Any = None) -> Any:
    """Create a ChatInvokeCompletion response for browser-use."""
    from browser_use.llm.views import ChatInvokeCompletion, ChatInvokeUsage

    output_tokens = len(content.split()) * 2  # Rough estimate
    usage = ChatInvokeUsage(
        prompt_tokens=0,
        prompt_cached_tokens=0,
        prompt_cache_creation_tokens=0,
        prompt_image_tokens=0,
        completion_tokens=output_tokens,
        total_tokens=output_tokens,
    )

    # If we have a parsed completion, use it
    # If not and output_format was expected, raise an error
    if completion is not None:
        final_completion = completion
    elif output_format is not None:
        # Parsing failed but structured output was expected - raise error
        raise ValueError(f"Failed to parse response into {output_format.__name__}. Response: {content[:200]}")
    else:
        # No structured output expected, use raw content
        final_completion = content

    return ChatInvokeCompletion(
        completion=final_completion,
        usage=usage,
        thinking=None,
        redacted_thinking=None,
        stop_reason="end_turn",
    )


class AIMessage:
    """Simple message class for fallback/compatibility."""

    def __init__(self, content: str, tool_calls: list | None = None, completion: Any = None):
        self.content = content
        self.tool_calls = tool_calls or []
        self.completion = completion

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
