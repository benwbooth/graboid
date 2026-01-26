"""Browser automation module using browser-use."""

from .agent import (
    BrowserAgent,
    LLMProvider,
    NavigationResult,
    NavigationTarget,
    create_browser_agent,
    get_llm,
)
from .download_action import DownloadController, DownloadResult
from .notes import AgentNote, NotesDB, NoteType, get_notes_db

__all__ = [
    "AgentNote",
    "BrowserAgent",
    "DownloadController",
    "DownloadResult",
    "LLMProvider",
    "NavigationResult",
    "NavigationTarget",
    "NotesDB",
    "NoteType",
    "create_browser_agent",
    "get_llm",
    "get_notes_db",
]
