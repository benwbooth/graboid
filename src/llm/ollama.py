"""Ollama local LLM backend."""

import asyncio
from typing import Any

from .base import (
    LLMBackend,
    LLMError,
    LLMMessage,
    LLMResponse,
    LLMUnavailableError,
    MessageRole,
)


class OllamaBackend(LLMBackend):
    """Ollama local LLM backend."""

    def __init__(
        self,
        model: str = "llama3.2",
        host: str = "http://localhost:11434",
    ):
        self.model = model
        self.host = host
        self._client = None
        self._available: bool | None = None

    @property
    def name(self) -> str:
        return f"ollama ({self.model})"

    @property
    def is_available(self) -> bool:
        if self._available is not None:
            return self._available

        try:
            import ollama

            # Try to connect synchronously for the property check
            client = ollama.Client(host=self.host)
            client.list()
            self._available = True
        except Exception:
            self._available = False

        return self._available

    async def _check_available(self) -> bool:
        """Async availability check."""
        try:
            client = self._get_client()
            await client.list()
            self._available = True
            return True
        except Exception:
            self._available = False
            return False

    def _get_client(self):
        if self._client is None:
            try:
                import ollama

                self._client = ollama.AsyncClient(host=self.host)
            except ImportError:
                raise LLMUnavailableError("ollama package not installed")
        return self._client

    def _convert_messages(self, messages: list[LLMMessage]) -> list[dict[str, str]]:
        """Convert messages to Ollama format."""
        return [{"role": msg.role.value, "content": msg.content} for msg in messages]

    async def complete(
        self,
        messages: list[LLMMessage],
        *,
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> LLMResponse:
        client = self._get_client()
        converted_messages = self._convert_messages(messages)

        try:
            response = await client.chat(
                model=self.model,
                messages=converted_messages,
                options={
                    "num_predict": max_tokens,
                    "temperature": temperature,
                },
            )

            return LLMResponse(
                content=response["message"]["content"],
                model=self.model,
                usage={
                    "prompt_tokens": response.get("prompt_eval_count", 0),
                    "completion_tokens": response.get("eval_count", 0),
                },
                raw_response=response,
            )
        except Exception as e:
            if "connection" in str(e).lower():
                self._available = False
                raise LLMUnavailableError(f"Ollama not available: {e}") from e
            raise LLMError(f"Ollama error: {e}") from e

    async def complete_with_tools(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]],
        *,
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> LLMResponse:
        """Complete with tool support (Ollama has limited tool support)."""
        client = self._get_client()
        converted_messages = self._convert_messages(messages)

        # Convert tools to Ollama format
        ollama_tools = []
        for tool in tools:
            ollama_tools.append(
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
            response = await client.chat(
                model=self.model,
                messages=converted_messages,
                tools=ollama_tools if ollama_tools else None,
                options={
                    "num_predict": max_tokens,
                    "temperature": temperature,
                },
            )

            content = response["message"]["content"]
            tool_calls = response["message"].get("tool_calls", [])

            # Format tool calls into content if present
            if tool_calls:
                for tc in tool_calls:
                    func = tc.get("function", {})
                    content += f"\n[TOOL_USE: {func.get('name')}({func.get('arguments', {})})]"

            return LLMResponse(
                content=content,
                model=self.model,
                usage={
                    "prompt_tokens": response.get("prompt_eval_count", 0),
                    "completion_tokens": response.get("eval_count", 0),
                },
                raw_response=response,
            )
        except Exception as e:
            if "connection" in str(e).lower():
                self._available = False
                raise LLMUnavailableError(f"Ollama not available: {e}") from e
            raise LLMError(f"Ollama error: {e}") from e


async def ensure_model_available(backend: OllamaBackend) -> bool:
    """Ensure the Ollama model is pulled and available."""
    try:
        client = backend._get_client()
        models = await client.list()
        model_names = [m["name"].split(":")[0] for m in models.get("models", [])]

        if backend.model.split(":")[0] not in model_names:
            # Model not found, try to pull it
            await client.pull(backend.model)

        return True
    except Exception:
        return False
