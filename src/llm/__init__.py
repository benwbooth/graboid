"""LLM backend abstraction layer."""

from .base import LLMBackend, LLMError, LLMMessage, LLMResponse, MessageRole
from .claude import ClaudeBackend
from .manager import LLMManager
from .ollama import OllamaBackend
from .openai import OpenAIBackend

__all__ = [
    "LLMBackend",
    "LLMError",
    "LLMManager",
    "LLMMessage",
    "LLMResponse",
    "MessageRole",
    "ClaudeBackend",
    "OllamaBackend",
    "OpenAIBackend",
]
