"""Claude (Anthropic) LLM backend."""

import os
from typing import Any

from .base import (
    LLMBackend,
    LLMError,
    LLMMessage,
    LLMRateLimitError,
    LLMResponse,
    LLMUnavailableError,
    MessageRole,
)


class ClaudeBackend(LLMBackend):
    """Claude API backend using the Anthropic SDK."""

    def __init__(self, model: str = "claude-sonnet-4-20250514", api_key: str | None = None):
        self.model = model
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self._client = None

    @property
    def name(self) -> str:
        return f"claude ({self.model})"

    @property
    def is_available(self) -> bool:
        if not self._api_key:
            return False
        try:
            import anthropic

            return True
        except ImportError:
            return False

    def _get_client(self):
        if self._client is None:
            if not self._api_key:
                raise LLMUnavailableError("ANTHROPIC_API_KEY not set")
            import anthropic

            self._client = anthropic.AsyncAnthropic(api_key=self._api_key)
        return self._client

    def _convert_messages(
        self, messages: list[LLMMessage]
    ) -> tuple[str | None, list[dict[str, str]]]:
        """Convert messages to Anthropic format, extracting system message."""
        system_message = None
        converted = []

        for msg in messages:
            if msg.role == MessageRole.SYSTEM:
                system_message = msg.content
            else:
                converted.append({"role": msg.role.value, "content": msg.content})

        return system_message, converted

    async def complete(
        self,
        messages: list[LLMMessage],
        *,
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> LLMResponse:
        import anthropic

        client = self._get_client()
        system_msg, converted_messages = self._convert_messages(messages)

        try:
            kwargs = {
                "model": self.model,
                "max_tokens": max_tokens,
                "messages": converted_messages,
                "temperature": temperature,
            }
            if system_msg:
                kwargs["system"] = system_msg

            response = await client.messages.create(**kwargs)

            return LLMResponse(
                content=response.content[0].text,
                model=response.model,
                usage={
                    "input_tokens": response.usage.input_tokens,
                    "output_tokens": response.usage.output_tokens,
                },
                raw_response=response,
            )
        except anthropic.RateLimitError as e:
            raise LLMRateLimitError(f"Claude rate limited: {e}") from e
        except anthropic.APIError as e:
            raise LLMError(f"Claude API error: {e}") from e

    async def complete_with_tools(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]],
        *,
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> LLMResponse:
        import anthropic

        client = self._get_client()
        system_msg, converted_messages = self._convert_messages(messages)

        # Convert tools to Anthropic format
        anthropic_tools = []
        for tool in tools:
            anthropic_tools.append(
                {
                    "name": tool["name"],
                    "description": tool.get("description", ""),
                    "input_schema": tool.get("parameters", {"type": "object", "properties": {}}),
                }
            )

        try:
            kwargs = {
                "model": self.model,
                "max_tokens": max_tokens,
                "messages": converted_messages,
                "tools": anthropic_tools,
                "temperature": temperature,
            }
            if system_msg:
                kwargs["system"] = system_msg

            response = await client.messages.create(**kwargs)

            # Extract text and tool use from response
            content_parts = []
            for block in response.content:
                if hasattr(block, "text"):
                    content_parts.append(block.text)
                elif hasattr(block, "type") and block.type == "tool_use":
                    content_parts.append(f"[TOOL_USE: {block.name}({block.input})]")

            return LLMResponse(
                content="\n".join(content_parts),
                model=response.model,
                usage={
                    "input_tokens": response.usage.input_tokens,
                    "output_tokens": response.usage.output_tokens,
                },
                raw_response=response,
            )
        except anthropic.RateLimitError as e:
            raise LLMRateLimitError(f"Claude rate limited: {e}") from e
        except anthropic.APIError as e:
            raise LLMError(f"Claude API error: {e}") from e
