"""
PII Scanner — OpenEnv SDK Client.

Provides the EnvClient subclass for connecting to the PII Scanner environment
via WebSocket (compatible with from_docker_image() and from_env()).
"""

from __future__ import annotations

from typing import Dict

from openenv.core import EnvClient
from openenv.core.client_types import StepResult
from openenv.core.env_server.types import State

from models import (
    PIIAction,
    PIIObservation,
    PIIState,
    PIIType,
    TaskDifficulty,
)


class PIIScannerEnv(EnvClient[PIIAction, PIIObservation, State]):
    """
    Client for the PII Scanner Environment.

    Example with Docker:
        >>> env = await PIIScannerEnv.from_docker_image("pii-scanner:latest")
        >>> result = await env.reset(task_type="easy")
        >>> print(result.observation.document)
        >>> action = PIIAction(detected_pii=[...])
        >>> result = await env.step(action)
    """

    def _step_payload(self, action: PIIAction) -> Dict:
        """Convert PIIAction to JSON payload for step message."""
        return {
            "detected_pii": [e.model_dump() for e in action.detected_pii],
            "redacted_text": action.redacted_text,
            "compliance_report": (
                action.compliance_report.model_dump()
                if action.compliance_report
                else None
            ),
        }

    def _parse_result(self, payload: Dict) -> StepResult[PIIObservation]:
        """Parse server response into StepResult[PIIObservation]."""
        obs_data = payload.get("observation", {})

        observation = PIIObservation(
            document=obs_data.get("document", ""),
            task_type=obs_data.get("task_type", "easy"),
            task_id=obs_data.get("task_id", ""),
            instructions=obs_data.get("instructions", ""),
            feedback=obs_data.get("feedback"),
            total_tasks=obs_data.get("total_tasks", 0),
            current_task_number=obs_data.get("current_task_number", 0),
            done=payload.get("done", False),
            reward=payload.get("reward"),
        )

        return StepResult(
            observation=observation,
            reward=payload.get("reward"),
            done=payload.get("done", False),
        )

    def _parse_state(self, payload: Dict) -> State:
        """Parse server response into State object."""
        return State(
            episode_id=payload.get("episode_id"),
            step_count=payload.get("step_count", 0),
        )
