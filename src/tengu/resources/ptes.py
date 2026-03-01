"""PTES (Penetration Testing Execution Standard) MCP resources."""

from __future__ import annotations

import json
from pathlib import Path

_DATA_PATH = Path(__file__).parent / "data" / "ptes_phases.json"


def _load_data() -> dict:
    with _DATA_PATH.open(encoding="utf-8") as f:
        return json.load(f)


def get_phases_overview() -> dict:
    """Return a summary of all 7 PTES phases."""
    data = _load_data()
    return {
        "methodology": data["methodology"],
        "full_name": data["full_name"],
        "url": data["url"],
        "phases": [
            {
                "number": p["number"],
                "name": p["name"],
                "description": p["description"],
            }
            for p in data["phases"]
        ],
    }


def get_phase(phase_number: int) -> dict | None:
    """Return details for a specific PTES phase (1-7)."""
    data = _load_data()

    for phase in data["phases"]:
        if phase["number"] == phase_number:
            return phase

    return None
