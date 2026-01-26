"""Abstract base class for LLM backends."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class MessageRole(str, Enum):
    """Message roles for chat interactions."""

    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"


@dataclass
class LLMMessage:
    """A message in a conversation."""

    role: MessageRole
    content: str


@dataclass
class LLMResponse:
    """Response from an LLM backend."""

    content: str
    model: str
    usage: dict[str, int] = field(default_factory=dict)
    raw_response: Any = None


class LLMBackend(ABC):
    """Abstract base class for LLM backends."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the name of this backend."""
        ...

    @property
    @abstractmethod
    def is_available(self) -> bool:
        """Check if this backend is currently available."""
        ...

    @abstractmethod
    async def complete(
        self,
        messages: list[LLMMessage],
        *,
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> LLMResponse:
        """Generate a completion for the given messages."""
        ...

    @abstractmethod
    async def complete_with_tools(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]],
        *,
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> LLMResponse:
        """Generate a completion with tool use support."""
        ...


class LLMError(Exception):
    """Base exception for LLM-related errors."""

    pass


class LLMUnavailableError(LLMError):
    """Raised when an LLM backend is not available."""

    pass


class LLMRateLimitError(LLMError):
    """Raised when rate limited by an LLM backend."""

    pass
