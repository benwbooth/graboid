"""Browser automation module using browser-use and Claude Chrome integration."""

from .agent import (
    BrowserAgent,
    LLMProvider,
    NavigationResult,
    NavigationTarget,
    create_browser_agent,
    get_llm,
)
from .chrome_agent import (
    ChromeBrowserAgent,
    ChromeNavigationResult,
    create_chrome_agent,
)
from .download_action import DownloadController, DownloadResult
from .notes import AgentNote, NotesDB, NoteType, get_notes_db

__all__ = [
    "AgentNote",
    "BrowserAgent",
    "ChromeBrowserAgent",
    "ChromeNavigationResult",
    "DownloadController",
    "DownloadResult",
    "LLMProvider",
    "NavigationResult",
    "NavigationTarget",
    "NotesDB",
    "NoteType",
    "create_browser_agent",
    "create_chrome_agent",
    "get_llm",
    "get_notes_db",
]
