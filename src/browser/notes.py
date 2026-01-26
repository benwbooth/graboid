"""Agent notes and learning system for browser navigation."""

import json
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

NoteType = Literal[
    "source_quality",    # Rating/review of a source
    "navigation_tip",    # How to navigate a site effectively
    "obstacle",          # Problems encountered (captcha, anti-bot, etc.)
    "workaround",        # Solutions to obstacles
    "download_method",   # How to find/trigger downloads
    "site_structure",    # How the site is organized
]


@dataclass
class AgentNote:
    """A note recorded by the browser agent."""

    domain: str                          # Site domain
    note_type: NoteType
    content: str                         # The actual note
    label: str | None = None             # Optional label/category
    url_pattern: str | None = None       # URL pattern this applies to
    success: bool | None = None          # Whether this led to success
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    use_count: int = 0                   # How many times this note was used

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "AgentNote":
        return cls(**data)


class NotesDB:
    """
    Persistent storage for agent notes.

    Notes are stored in a JSON file organized by domain for quick lookup.
    """

    def __init__(self, notes_file: Path | None = None):
        self.notes_file = notes_file or self._default_path()
        self._notes: dict[str, list[AgentNote]] = {}  # domain -> notes
        self._load()

    @staticmethod
    def _default_path() -> Path:
        """Default path for notes storage."""
        config_dir = Path.home() / ".config" / "graboid"
        config_dir.mkdir(parents=True, exist_ok=True)
        return config_dir / "agent_notes.json"

    def _load(self) -> None:
        """Load notes from disk."""
        if not self.notes_file.exists():
            self._notes = {}
            return

        try:
            with open(self.notes_file) as f:
                data = json.load(f)

            self._notes = {}
            for domain, notes_list in data.items():
                self._notes[domain] = [AgentNote.from_dict(n) for n in notes_list]

            total = sum(len(notes) for notes in self._notes.values())
            logger.info(f"Loaded {total} agent notes from {self.notes_file}")
        except Exception as e:
            logger.warning(f"Failed to load notes: {e}")
            self._notes = {}

    def _save(self) -> None:
        """Save notes to disk."""
        try:
            data = {
                domain: [n.to_dict() for n in notes]
                for domain, notes in self._notes.items()
            }

            self.notes_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.notes_file, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save notes: {e}")

    @staticmethod
    def _extract_domain(url: str) -> str:
        """Extract domain from URL."""
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        parsed = urlparse(url)
        return parsed.netloc.lower()

    def add_note(
        self,
        url_or_domain: str,
        note_type: NoteType,
        content: str,
        label: str | None = None,
        url_pattern: str | None = None,
        success: bool | None = None,
    ) -> AgentNote:
        """Add a new note."""
        domain = self._extract_domain(url_or_domain)

        note = AgentNote(
            domain=domain,
            note_type=note_type,
            content=content,
            label=label,
            url_pattern=url_pattern,
            success=success,
        )

        if domain not in self._notes:
            self._notes[domain] = []

        # Check for duplicate/similar notes
        for existing in self._notes[domain]:
            if (existing.note_type == note_type and
                existing.content.lower() == content.lower() and
                existing.label == label):
                # Update existing note
                existing.updated_at = datetime.now().isoformat()
                existing.use_count += 1
                if success is not None:
                    existing.success = success
                self._save()
                logger.debug(f"Updated existing note for {domain}")
                return existing

        self._notes[domain].append(note)
        self._save()
        logger.info(f"Added new {note_type} note for {domain}")
        return note

    def get_notes_for_url(
        self,
        url: str,
        label: str | None = None,
        note_types: list[NoteType] | None = None,
    ) -> list[AgentNote]:
        """Get all relevant notes for a URL."""
        domain = self._extract_domain(url)

        if domain not in self._notes:
            return []

        notes = self._notes[domain]

        # Filter by note type
        if note_types:
            notes = [n for n in notes if n.note_type in note_types]

        # Filter by label (include label-specific and general notes)
        if label:
            notes = [n for n in notes if n.label is None or n.label.lower() == label.lower()]

        # Sort by relevance: label-specific first, then by use_count
        def sort_key(note: AgentNote) -> tuple:
            label_match = 1 if note.label and label and note.label.lower() == label.lower() else 0
            return (-label_match, -note.use_count, note.created_at)

        return sorted(notes, key=sort_key)

    def get_notes_by_type(self, note_type: NoteType) -> list[AgentNote]:
        """Get all notes of a specific type across all domains."""
        result = []
        for notes in self._notes.values():
            result.extend(n for n in notes if n.note_type == note_type)
        return result

    def get_successful_sources(self, label: str | None = None) -> list[AgentNote]:
        """Get notes about sources that worked well."""
        result = []
        for notes in self._notes.values():
            for note in notes:
                if note.note_type == "source_quality" and note.success:
                    if label is None or note.label is None or note.label.lower() == label.lower():
                        result.append(note)
        return sorted(result, key=lambda n: -n.use_count)

    def format_notes_for_prompt(
        self,
        url: str,
        label: str | None = None,
        max_notes: int = 10,
    ) -> str:
        """Format relevant notes as text to include in agent prompt."""
        notes = self.get_notes_for_url(url, label)[:max_notes]

        if not notes:
            return ""

        lines = ["## Previous Knowledge About This Site\n"]

        for note in notes:
            type_label = note.note_type.replace("_", " ").title()
            label_info = f" ({note.label})" if note.label else ""
            success_info = " ✓" if note.success else (" ✗" if note.success is False else "")

            lines.append(f"**{type_label}{label_info}{success_info}**: {note.content}")

        return "\n".join(lines)

    def record_use(self, note: AgentNote) -> None:
        """Record that a note was used (for tracking usefulness)."""
        note.use_count += 1
        note.updated_at = datetime.now().isoformat()
        self._save()

    def get_all_domains(self) -> list[str]:
        """Get all domains with notes."""
        return list(self._notes.keys())

    def get_stats(self) -> dict:
        """Get statistics about the notes database."""
        total_notes = sum(len(notes) for notes in self._notes.values())
        by_type: dict[str, int] = {}
        successful = 0

        for notes in self._notes.values():
            for note in notes:
                by_type[note.note_type] = by_type.get(note.note_type, 0) + 1
                if note.success:
                    successful += 1

        return {
            "total_notes": total_notes,
            "domains": len(self._notes),
            "by_type": by_type,
            "successful": successful,
        }


# Global instance for easy access
_notes_db: NotesDB | None = None


def get_notes_db(notes_file: Path | None = None) -> NotesDB:
    """Get the global notes database instance."""
    global _notes_db
    if _notes_db is None:
        _notes_db = NotesDB(notes_file)
    return _notes_db
