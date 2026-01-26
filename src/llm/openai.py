"""OpenAI LLM backend."""

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


class OpenAIBackend(LLMBackend):
    """OpenAI API backend."""

    def __init__(self, model: str = "gpt-4o", api_key: str | None = None):
        self.model = model
        self._api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self._client = None

    @property
    def name(self) -> str:
        return f"openai ({self.model})"

    @property
    def is_available(self) -> bool:
        if not self._api_key:
            return False
        try:
            import openai

            return True
        except ImportError:
            return False

    def _get_client(self):
        if self._client is None:
            if not self._api_key:
                raise LLMUnavailableError("OPENAI_API_KEY not set")
            import openai

            self._client = openai.AsyncOpenAI(api_key=self._api_key)
        return self._client

    def _convert_messages(self, messages: list[LLMMessage]) -> list[dict[str, str]]:
        """Convert messages to OpenAI format."""
        return [{"role": msg.role.value, "content": msg.content} for msg in messages]

    async def complete(
        self,
        messages: list[LLMMessage],
        *,
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> LLMResponse:
        import openai

        client = self._get_client()
        converted_messages = self._convert_messages(messages)

        try:
            response = await client.chat.completions.create(
                model=self.model,
                messages=converted_messages,
                max_tokens=max_tokens,
                temperature=temperature,
            )

            return LLMResponse(
                content=response.choices[0].message.content or "",
                model=response.model,
                usage={
                    "prompt_tokens": response.usage.prompt_tokens if response.usage else 0,
                    "completion_tokens": response.usage.completion_tokens if response.usage else 0,
                },
                raw_response=response,
            )
        except openai.RateLimitError as e:
            raise LLMRateLimitError(f"OpenAI rate limited: {e}") from e
        except openai.APIError as e:
            raise LLMError(f"OpenAI API error: {e}") from e

    async def complete_with_tools(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]],
        *,
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> LLMResponse:
        import openai

        client = self._get_client()
        converted_messages = self._convert_messages(messages)

        # Convert tools to OpenAI format
        openai_tools = []
        for tool in tools:
            openai_tools.append(
                {
                    "type": "function",
                    "function": {
                        "name": tool["name"],
                        "description": tool.get("description", ""),
                        "parameters": tool.get("parameters", {"type": "object", "properties": {}}),
                    },
                }
            )

        try:
            response = await client.chat.completions.create(
                model=self.model,
                messages=converted_messages,
                tools=openai_tools if openai_tools else None,
                max_tokens=max_tokens,
                temperature=temperature,
            )

            message = response.choices[0].message
            content = message.content or ""

            # Format tool calls into content if present
            if message.tool_calls:
                for tc in message.tool_calls:
                    content += f"\n[TOOL_USE: {tc.function.name}({tc.function.arguments})]"

            return LLMResponse(
                content=content,
                model=response.model,
                usage={
                    "prompt_tokens": response.usage.prompt_tokens if response.usage else 0,
                    "completion_tokens": response.usage.completion_tokens if response.usage else 0,
                },
                raw_response=response,
            )
        except openai.RateLimitError as e:
            raise LLMRateLimitError(f"OpenAI rate limited: {e}") from e
        except openai.APIError as e:
            raise LLMError(f"OpenAI API error: {e}") from e
