"""
PII Scanner Environment — Core OpenEnv Environment.

Implements reset() / step() / state() for the PII detection challenge.
Supports 6 task types: easy, medium_contextual, medium_obfuscated,
medium_crossref, hard_audit, hard_adversarial.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from openenv.core.env_server.interfaces import Environment

from models import (
    ComplianceReport,
    PIIAction,
    PIIEntity,
    PIIObservation,
    PIIState,
    TaskDifficulty,
)
from server.grader import grade_submission
from server.tasks import (
    EASY_INSTRUCTIONS,
    MEDIUM_CONTEXTUAL_INSTRUCTIONS,
    MEDIUM_OBFUSCATED_INSTRUCTIONS,
    MEDIUM_CROSSREF_INSTRUCTIONS,
    HARD_AUDIT_INSTRUCTIONS,
    HARD_ADVERSARIAL_INSTRUCTIONS,
)

DATA_DIR = Path(__file__).parent / "data"

# Maps each task type to its data file and instructions
_TASK_CONFIG = {
    TaskDifficulty.EASY: {
        "file": "easy_documents.json",
        "instructions": EASY_INSTRUCTIONS,
    },
    # Legacy "medium" alias maps to contextual
    TaskDifficulty.MEDIUM: {
        "file": "medium_contextual_documents.json",
        "instructions": MEDIUM_CONTEXTUAL_INSTRUCTIONS,
    },
    TaskDifficulty.MEDIUM_CONTEXTUAL: {
        "file": "medium_contextual_documents.json",
        "instructions": MEDIUM_CONTEXTUAL_INSTRUCTIONS,
    },
    TaskDifficulty.MEDIUM_OBFUSCATED: {
        "file": "medium_obfuscated_documents.json",
        "instructions": MEDIUM_OBFUSCATED_INSTRUCTIONS,
    },
    TaskDifficulty.MEDIUM_CROSSREF: {
        "file": "medium_crossref_documents.json",
        "instructions": MEDIUM_CROSSREF_INSTRUCTIONS,
    },
    # Legacy "hard" alias maps to audit
    TaskDifficulty.HARD: {
        "file": "hard_documents.json",
        "instructions": HARD_AUDIT_INSTRUCTIONS,
    },
    TaskDifficulty.HARD_AUDIT: {
        "file": "hard_documents.json",
        "instructions": HARD_AUDIT_INSTRUCTIONS,
    },
    TaskDifficulty.HARD_ADVERSARIAL: {
        "file": "hard_adversarial_documents.json",
        "instructions": HARD_ADVERSARIAL_INSTRUCTIONS,
    },
}


def _is_hard_task(difficulty: TaskDifficulty) -> bool:
    """Check if a task type uses hard-mode grading (detection + redaction + compliance)."""
    return difficulty in (
        TaskDifficulty.HARD,
        TaskDifficulty.HARD_AUDIT,
        TaskDifficulty.HARD_ADVERSARIAL,
    )


def _load_documents(difficulty: TaskDifficulty) -> List[Dict[str, Any]]:
    """Load document dataset for the given difficulty."""
    config = _TASK_CONFIG[difficulty]
    filepath = DATA_DIR / config["file"]
    with open(filepath, "r") as f:
        return json.load(f)


def _get_instructions(difficulty: TaskDifficulty) -> str:
    """Get task instructions for the given difficulty."""
    return _TASK_CONFIG[difficulty]["instructions"]


class PIIScannerEnvironment(Environment[PIIAction, PIIObservation, PIIState]):
    """
    PII Scanner Environment following the OpenEnv pattern.

    Each episode presents a sequence of documents to scan for PII.
    The agent submits detected entities and receives F1-based rewards.
    """

    SUPPORTS_CONCURRENT_SESSIONS = True

    def __init__(self):
        super().__init__()
        self._state = PIIState()
        self._documents: List[Dict[str, Any]] = []
        self._current_doc: Optional[Dict[str, Any]] = None
        self._difficulty = TaskDifficulty.EASY

    def reset(
        self,
        seed: Optional[int] = None,
        episode_id: Optional[str] = None,
        task_type: str = "easy",
        **kwargs,
    ) -> PIIObservation:
        """
        Start a new episode.

        Args:
            task_type: one of "easy", "medium_contextual", "medium_obfuscated",
                       "medium_crossref", "hard_audit", "hard_adversarial"
                       (also accepts legacy "medium" and "hard")
        """
        self._difficulty = TaskDifficulty(task_type)
        self._documents = _load_documents(self._difficulty)
        self._current_doc = self._documents[0]

        self._state = PIIState(
            episode_id=episode_id or str(uuid.uuid4()),
            step_count=0,
            current_task_index=0,
            total_tasks=len(self._documents),
            task_type=self._difficulty,
            scores=[],
            overall_score=0.0,
        )

        return PIIObservation(
            done=False,
            reward=None,
            document=self._current_doc["document"],
            task_type=self._difficulty,
            task_id=self._current_doc["id"],
            instructions=_get_instructions(self._difficulty),
            feedback=None,
            total_tasks=len(self._documents),
            current_task_number=1,
        )

    def step(self, action: PIIAction, timeout_s: Optional[float] = None, **kwargs) -> PIIObservation:
        """
        Process agent's PII detection submission.

        Grades the submission against ground truth and advances to the next document.
        """
        if self._current_doc is None:
            return PIIObservation(
                done=True,
                reward=0.0,
                document="",
                task_type=self._difficulty,
                task_id="",
                instructions="Episode has ended. Call reset() to start a new episode.",
                feedback="No active document.",
            )

        self._state.step_count += 1

        # Grade the submission
        ground_truth = self._current_doc["ground_truth"]
        grade_result = grade_submission(
            predictions=action.detected_pii,
            ground_truth=ground_truth,
            task_difficulty=self._difficulty,
            predicted_redacted=action.redacted_text,
            expected_redacted=self._current_doc.get("expected_redacted"),
            predicted_report=action.compliance_report,
            expected_findings=self._current_doc.get("expected_findings"),
        )

        reward = grade_result["reward"]
        self._state.scores.append(reward)
        self._state.overall_score = (
            sum(self._state.scores) / len(self._state.scores)
            if self._state.scores
            else 0.0
        )

        # Advance to next document
        self._state.current_task_index += 1
        done = self._state.current_task_index >= len(self._documents)

        if done:
            self._current_doc = None
            return PIIObservation(
                done=True,
                reward=reward,
                document="",
                task_type=self._difficulty,
                task_id="",
                instructions="All tasks complete!",
                feedback=grade_result["feedback"],
                total_tasks=self._state.total_tasks,
                current_task_number=self._state.total_tasks,
                metadata={
                    "breakdown": grade_result["breakdown"],
                    "overall_score": round(self._state.overall_score, 4),
                    "all_scores": [round(s, 4) for s in self._state.scores],
                },
            )

        # Load next document
        self._current_doc = self._documents[self._state.current_task_index]

        return PIIObservation(
            done=False,
            reward=reward,
            document=self._current_doc["document"],
            task_type=self._difficulty,
            task_id=self._current_doc["id"],
            instructions=_get_instructions(self._difficulty),
            feedback=grade_result["feedback"],
            total_tasks=self._state.total_tasks,
            current_task_number=self._state.current_task_index + 1,
            metadata={"breakdown": grade_result["breakdown"]},
        )

    @property
    def state(self) -> PIIState:
        return self._state

    def close(self) -> None:
        """Clean up resources."""
        pass

    def get_metadata(self) -> Dict[str, Any]:
        return {
            "name": "pii_scanner",
            "description": "PII Scanner Environment — detect, classify, and redact personally identifiable information",
            "version": "1.0.0",
            "task_types": [
                "easy",
                "medium_contextual",
                "medium_obfuscated",
                "medium_crossref",
                "hard_audit",
                "hard_adversarial",
            ],
        }
