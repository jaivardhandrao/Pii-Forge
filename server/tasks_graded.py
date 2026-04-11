"""
PII-Forge — Graded Tasks (loader).

Loads tasks from the tasks/ directory. Each task lives in its own
UUID-named subdirectory containing:
  - task.json          — task metadata (title, difficulty, document)
  - auxiliary_data.json — PII ground truth
  - grader.py          — standalone grading script

This module reads all task directories at import time and exposes
TASKS, TASKS_BY_ID, and grade_result() for the API layer.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

TASKS_ROOT = Path(__file__).parent.parent / "tasks"


def _load_all_tasks() -> List[Dict[str, Any]]:
    """Scan tasks/ directory and load every task."""
    tasks = []
    if not TASKS_ROOT.is_dir():
        return tasks

    for task_dir in sorted(TASKS_ROOT.iterdir()):
        if not task_dir.is_dir():
            continue

        task_file = task_dir / "task.json"
        aux_file = task_dir / "auxiliary_data.json"

        if not task_file.exists() or not aux_file.exists():
            continue

        with open(task_file, "r", encoding="utf-8") as f:
            task_data = json.load(f)

        with open(aux_file, "r", encoding="utf-8") as f:
            aux_data = json.load(f)

        tasks.append({
            "task_id": task_data["task_id"],
            "title": task_data["title"],
            "difficulty": task_data["difficulty"],
            "document": task_data["document"],
            "pii": aux_data["pii"],
            "_dir": str(task_dir),
        })

    return tasks


TASKS = _load_all_tasks()
TASKS_BY_ID = {t["task_id"]: t for t in TASKS}


def grade_result(task_id: str, result_text: Optional[str] = None) -> dict:
    """
    Grade a submission by loading and calling the task's own grader.py.

    Falls back to the built-in grading logic if grader.py is missing.
    """
    task = TASKS_BY_ID.get(task_id)
    if task is None:
        return {"error": f"Task '{task_id}' not found."}

    task_dir = Path(task["_dir"])
    grader_file = task_dir / "grader.py"

    if grader_file.exists():
        # Dynamically load the task's grader.py and call grade()
        spec = importlib.util.spec_from_file_location(
            f"grader_{task_id}", str(grader_file)
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod.grade(result_text)

    # Fallback: built-in grading
    return _builtin_grade(task, result_text)


def _builtin_grade(task: dict, result_text: Optional[str] = None) -> dict:
    """Built-in grading logic (same as each grader.py but without file I/O)."""
    import re

    task_id = task["task_id"]
    pii_list = task["pii"]
    document = task["document"]

    if not result_text or not result_text.strip():
        return {
            "task_id": task_id,
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

    # Content preservation (anti-gaming)
    all_words = set(re.findall(r"[a-zA-Z]{4,}", document.lower()))
    pii_words = set()
    for item in pii_list:
        pii_words.update(re.findall(r"[a-zA-Z]{4,}", item["value"].lower()))
    non_pii_words = all_words - pii_words

    if non_pii_words:
        result_words = set(re.findall(r"[a-zA-Z]{4,}", result_lower))
        preservation_score = len(non_pii_words & result_words) / len(non_pii_words)
    else:
        preservation_score = 1.0

    return {
        "task_id": task_id,
        "score": round(pii_score * preservation_score, 4),
        "pii_removal_score": round(pii_score, 4),
        "content_preservation": round(preservation_score, 4),
        "total_pii": total,
        "removed": removed_count,
        "leaked": total - removed_count,
        "details": details,
    }
