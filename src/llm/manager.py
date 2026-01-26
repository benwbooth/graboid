"""LLM backend manager with fallback support."""

import logging
from typing import Any

from .base import (
    LLMBackend,
    LLMError,
    LLMMessage,
    LLMRateLimitError,
    LLMResponse,
    LLMUnavailableError,
)
from .claude import ClaudeBackend
from .ollama import OllamaBackend
from .openai import OpenAIBackend

logger = logging.getLogger(__name__)


class LLMManager:
    """Manages multiple LLM backends with automatic fallback."""

    def __init__(
        self,
        backends: list[LLMBackend] | None = None,
        max_retries: int = 2,
    ):
        """
        Initialize the LLM manager.

        Args:
            backends: List of backends in priority order. If None, uses default order:
                      Ollama (local) -> Claude -> OpenAI
            max_retries: Max retries per backend before falling back
        """
        self.backends = backends or self._create_default_backends()
        self.max_retries = max_retries
        self._current_backend_idx = 0

    def _create_default_backends(self) -> list[LLMBackend]:
        """Create default backends in priority order."""
        return [
            OllamaBackend(model="llama3.2"),
            ClaudeBackend(),
            OpenAIBackend(),
        ]

    @property
    def current_backend(self) -> LLMBackend | None:
        """Get the currently active backend."""
        available = self.available_backends
        if not available:
            return None
        return available[0]

    @property
    def available_backends(self) -> list[LLMBackend]:
        """Get list of available backends."""
        return [b for b in self.backends if b.is_available]

    async def complete(
        self,
        messages: list[LLMMessage],
        *,
        max_tokens: int = 4096,
        temperature: float = 0.7,
        prefer_local: bool = True,
    ) -> LLMResponse:
        """
        Generate a completion, automatically falling back between backends.

        Args:
            messages: The messages to complete
            max_tokens: Maximum tokens in response
            temperature: Sampling temperature
            prefer_local: If True, always try local (Ollama) first

        Returns:
            LLMResponse from whichever backend succeeds

        Raises:
            LLMUnavailableError: If no backends are available
            LLMError: If all backends fail
        """
        backends_to_try = self._get_backends_to_try(prefer_local)

        if not backends_to_try:
            raise LLMUnavailableError("No LLM backends available")

        last_error: Exception | None = None

        for backend in backends_to_try:
            for attempt in range(self.max_retries):
                try:
                    logger.debug(f"Trying {backend.name} (attempt {attempt + 1})")
                    response = await backend.complete(
                        messages,
                        max_tokens=max_tokens,
                        temperature=temperature,
                    )
                    logger.info(f"Success with {backend.name}")
                    return response

                except LLMRateLimitError as e:
                    logger.warning(f"{backend.name} rate limited: {e}")
                    last_error = e
                    # Don't retry rate limits, fall back immediately
                    break

                except LLMUnavailableError as e:
                    logger.warning(f"{backend.name} unavailable: {e}")
                    last_error = e
                    break

                except LLMError as e:
                    logger.warning(f"{backend.name} error (attempt {attempt + 1}): {e}")
                    last_error = e
                    continue

        raise LLMError(f"All backends failed. Last error: {last_error}")

    async def complete_with_tools(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]],
        *,
        max_tokens: int = 4096,
        temperature: float = 0.7,
        prefer_local: bool = True,
    ) -> LLMResponse:
        """Generate a completion with tool support, with automatic fallback."""
        backends_to_try = self._get_backends_to_try(prefer_local)

        if not backends_to_try:
            raise LLMUnavailableError("No LLM backends available")

        last_error: Exception | None = None

        for backend in backends_to_try:
            for attempt in range(self.max_retries):
                try:
                    logger.debug(f"Trying {backend.name} with tools (attempt {attempt + 1})")
                    response = await backend.complete_with_tools(
                        messages,
                        tools,
                        max_tokens=max_tokens,
                        temperature=temperature,
                    )
                    logger.info(f"Success with {backend.name}")
                    return response

                except LLMRateLimitError as e:
                    logger.warning(f"{backend.name} rate limited: {e}")
                    last_error = e
                    break

                except LLMUnavailableError as e:
                    logger.warning(f"{backend.name} unavailable: {e}")
                    last_error = e
                    break

                except LLMError as e:
                    logger.warning(f"{backend.name} error (attempt {attempt + 1}): {e}")
                    last_error = e
                    continue

        raise LLMError(f"All backends failed. Last error: {last_error}")

    def _get_backends_to_try(self, prefer_local: bool) -> list[LLMBackend]:
        """Get ordered list of backends to try."""
        available = self.available_backends

        if not prefer_local:
            return available

        # Move Ollama to front if available
        ollama_backends = [b for b in available if isinstance(b, OllamaBackend)]
        other_backends = [b for b in available if not isinstance(b, OllamaBackend)]

        return ollama_backends + other_backends
