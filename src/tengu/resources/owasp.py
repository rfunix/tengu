"""OWASP Top 10 MCP resources."""

from __future__ import annotations

import json
from pathlib import Path

_DATA_PATH = Path(__file__).parent / "data" / "owasp_top10_2025.json"


def _load_data() -> dict:
    with _DATA_PATH.open(encoding="utf-8") as f:
        return json.load(f)


def get_top10_list() -> dict:
    """Return the full OWASP Top 10:2025 list."""
    data = _load_data()
    return {
        "title": data["title"],
        "version": data["version"],
        "categories": [
            {
                "id": c["id"],
                "title": c["title"],
                "description": c["description"][:300] + "...",
                "cwe_count": len(c.get("cwe_ids", [])),
            }
            for c in data["categories"]
        ],
    }


def get_category(category_id: str) -> dict | None:
    """Return details for a specific OWASP category (e.g. 'A01')."""
    data = _load_data()
    category_id = category_id.upper()

    for category in data["categories"]:
        if category["id"] == category_id:
            return category

    return None


def get_category_checklist(category_id: str) -> dict | None:
    """Return the testing checklist for a specific OWASP category."""
    category = get_category(category_id)
    if not category:
        return None

    return {
        "id": category["id"],
        "title": category["title"],
        "how_to_test": category.get("how_to_test", []),
        "tools": category.get("tools", []),
        "cwe_ids": category.get("cwe_ids", []),
        "references": category.get("references", []),
    }
