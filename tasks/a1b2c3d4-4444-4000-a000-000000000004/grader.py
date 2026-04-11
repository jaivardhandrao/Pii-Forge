"""
Grader for task: Insurance Claim Processing
Task ID: a1b2c3d4-4444-4000-a000-000000000004

Evaluates whether PII has been properly removed from the document
while preserving non-PII content.

Scoring:
  final_score = pii_removal_score * content_preservation_score

  - pii_removal_score: fraction of PII values removed (0.0 - 1.0)
  - content_preservation_score: fraction of non-PII words preserved (0.0 - 1.0)
"""

from __future__ import annotations

import json
import re
from pathlib import Path

TASK_DIR = Path(__file__).parent


def _load_auxiliary_data() -> list:
    with open(TASK_DIR / "auxiliary_data.json") as f:
        return json.load(f)["pii"]


def _load_document() -> str:
    with open(TASK_DIR / "task.json") as f:
        return json.load(f)["document"]


def _extract_non_pii_words(document: str, pii_list: list) -> set:
    all_words = set(re.findall(r"[a-zA-Z]{4,}", document.lower()))
    pii_words = set()
    for item in pii_list:
        pii_words.update(re.findall(r"[a-zA-Z]{4,}", item["value"].lower()))
    return all_words - pii_words


def grade(result_text: str | None = None) -> dict:
    """
    Grade a submitted redacted paragraph.

    Args:
        result_text: The redacted document submitted by the user.
                     If None/empty, returns score 0.0 with the original document.

    Returns:
        dict with score, pii_removal_score, content_preservation,
        total_pii, removed, leaked, and per-PII details.
    """
    pii_list = _load_auxiliary_data()
    document = _load_document()

    if not result_text or not result_text.strip():
        return {
            "task_id": "a1b2c3d4-4444-4000-a000-000000000004",
            "score": 0.0,
            "total_pii": len(pii_list),
            "removed": 0,
            "leaked": len(pii_list),
            "content_preservation": 0.0,
            "original_document": document,
            "details": [
                {"pii_type": p["type"], "value": p["value"], "removed": False, "score": 0.0}
                for p in pii_list
            ],
            "message": "No result submitted. Returning original document with score 0.0.",
        }

    result_lower = result_text.lower()
    details = []
    removed_count = 0

    for item in pii_list:
        present = item["value"].lower() in result_lower
        if not present:
            removed_count += 1
        details.append({
            "pii_type": item["type"],
            "value": item["value"],
            "removed": not present,
            "score": 0.0 if present else 1.0,
        })

    total = len(pii_list)
    pii_score = removed_count / total if total > 0 else 0.0

    non_pii_words = _extract_non_pii_words(document, pii_list)
    if non_pii_words:
        result_words = set(re.findall(r"[a-zA-Z]{4,}", result_lower))
        preservation_score = len(non_pii_words & result_words) / len(non_pii_words)
    else:
        preservation_score = 1.0

    return {
        "task_id": "a1b2c3d4-4444-4000-a000-000000000004",
        "score": round(pii_score * preservation_score, 4),
        "pii_removal_score": round(pii_score, 4),
        "content_preservation": round(preservation_score, 4),
        "total_pii": total,
        "removed": removed_count,
        "leaked": total - removed_count,
        "details": details,
    }
