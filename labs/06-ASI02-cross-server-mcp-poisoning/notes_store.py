from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

LAB_DIR = Path(__file__).resolve().parent
DATA_DIR = LAB_DIR / "data"
SEED_NOTES_PATH = DATA_DIR / "notes_seed.json"
NOTES_STORE_PATH = DATA_DIR / "notes_store.json"
EXFIL_LOG_PATH = DATA_DIR / "exfil_log.json"


def _ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def _read_json(path: Path, default):
    _ensure_parent(path)
    if not path.exists():
        return deepcopy(default)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return deepcopy(default)


def _write_json(path: Path, value) -> None:
    _ensure_parent(path)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def load_seed_notes() -> list[dict[str, str]]:
    data = _read_json(SEED_NOTES_PATH, [])
    return data if isinstance(data, list) else []


def load_notes() -> list[dict[str, str]]:
    data = _read_json(NOTES_STORE_PATH, [])
    return data if isinstance(data, list) else []


def save_notes(notes: list[dict[str, str]]) -> None:
    _write_json(NOTES_STORE_PATH, notes)


def reset_notes() -> list[dict[str, str]]:
    notes = load_seed_notes()
    save_notes(notes)
    return notes


def clear_notes() -> None:
    save_notes([])


def clear_exfil_log() -> None:
    _write_json(EXFIL_LOG_PATH, [])


def add_note(title: str, content: str, classification: str = "internal") -> dict[str, str]:
    notes = load_notes()
    note = {
        "title": title,
        "content": content,
        "classification": classification,
    }

    for index, existing in enumerate(notes):
        if existing.get("title") == title:
            notes[index] = note
            save_notes(notes)
            return note

    notes.append(note)
    save_notes(notes)
    return note


def delete_note(title: str) -> bool:
    notes = load_notes()
    kept = [note for note in notes if note.get("title") != title]
    removed = len(kept) != len(notes)
    if removed:
        save_notes(kept)
    return removed


def get_note(title: str) -> dict[str, str] | None:
    for note in load_notes():
        if note.get("title") == title:
            return note
    return None


def format_notes(notes: list[dict[str, str]] | None = None) -> str:
    return json.dumps(notes if notes is not None else load_notes(), indent=2)