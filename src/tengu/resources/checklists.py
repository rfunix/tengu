"""Pentest checklist MCP resources."""

from __future__ import annotations

import json
from pathlib import Path

_DATA_PATH = Path(__file__).parent / "data" / "checklists.json"


def _load_data() -> dict:
    with _DATA_PATH.open(encoding="utf-8") as f:
        return json.load(f)


def get_checklist(checklist_type: str) -> dict | None:
    """Return a checklist by type: 'web-application', 'api', or 'network'."""
    data = _load_data()
    return data["checklists"].get(checklist_type)


def list_checklists() -> list[str]:
    """Return available checklist types."""
    data = _load_data()
    return list(data["checklists"].keys())
