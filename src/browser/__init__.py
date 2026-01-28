"""Browser automation module using browser-use and Claude Chrome integration."""

from .agent import (
    BrowserAgent,
    LLMProvider,
    NavigationResult,
    NavigationStep,
    NavigationTarget,
    create_browser_agent,
    get_llm,
)
from .chrome_manager import ChromeManager, create_chrome_manager
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
    "ChromeManager",
    "ChromeNavigationResult",
    "DownloadController",
    "DownloadResult",
    "LLMProvider",
    "NavigationResult",
    "NavigationStep",
    "NavigationTarget",
    "NotesDB",
    "NoteType",
    "create_browser_agent",
    "create_chrome_agent",
    "create_chrome_manager",
    "get_llm",
    "get_notes_db",
]
