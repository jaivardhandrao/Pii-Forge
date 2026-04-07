"""
PII Scanner Environment - Data Models

Defines the typed Pydantic models for actions, observations, and state
following the OpenEnv specification.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ── PII Entity Types ──────────────────────────────────────────────────────────

class PIIType(str, Enum):
    """Supported PII entity types."""
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    SSN = "SSN"
    CREDIT_CARD = "CREDIT_CARD"
    DATE_OF_BIRTH = "DATE_OF_BIRTH"
    NAME = "NAME"
    AGE = "AGE"
    ADDRESS = "ADDRESS"
    LOCATION = "LOCATION"
    IP_ADDRESS = "IP_ADDRESS"
    EMPLOYEE_ID = "EMPLOYEE_ID"
    MEDICAL_CONDITION = "MEDICAL_CONDITION"
    MEDICATION = "MEDICATION"
    ORGANIZATION = "ORGANIZATION"
    SALARY = "SALARY"
    BANK_ACCOUNT = "BANK_ACCOUNT"
    PASSPORT = "PASSPORT"
    LICENSE_NUMBER = "LICENSE_NUMBER"
    USERNAME = "USERNAME"
    PASSWORD = "PASSWORD"


class RiskLevel(str, Enum):
    """Risk classification for detected PII."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TaskDifficulty(str, Enum):
    """Task difficulty levels (6 tiers)."""
    EASY = "easy"
    MEDIUM = "medium"
    MEDIUM_CONTEXTUAL = "medium_contextual"
    MEDIUM_OBFUSCATED = "medium_obfuscated"
    MEDIUM_CROSSREF = "medium_crossref"
    HARD = "hard"
    HARD_AUDIT = "hard_audit"
    HARD_ADVERSARIAL = "hard_adversarial"


# ── Sub-models ────────────────────────────────────────────────────────────────

class PIIEntity(BaseModel):
    """A single detected PII entity."""
    pii_type: PIIType = Field(..., description="Category of PII detected")
    value: str = Field(..., description="The actual PII text found")
    start: int = Field(..., description="Character offset start in document")
    end: int = Field(..., description="Character offset end in document")


class ComplianceFinding(BaseModel):
    """A compliance finding for a detected PII entity (hard task)."""
    value: str = Field(..., description="The PII text")
    pii_type: PIIType = Field(..., description="Category of PII")
    risk_level: RiskLevel = Field(..., description="Risk classification")
    regulation: str = Field(..., description="Applicable regulation (e.g., GDPR Art.9, HIPAA, DPDP Sec.4)")
    recommended_action: str = Field(..., description="What should be done about this PII")


class ComplianceReport(BaseModel):
    """Full compliance report for hard task."""
    findings: List[ComplianceFinding] = Field(default_factory=list)
    summary: str = Field(default="", description="Executive summary of findings")


# ── OpenEnv Action ────────────────────────────────────────────────────────────

class PIIAction(BaseModel):
    """Action submitted by the agent: detected PII entities + optional redaction."""
    detected_pii: List[PIIEntity] = Field(
        default_factory=list,
        description="List of PII entities detected in the document"
    )
    redacted_text: Optional[str] = Field(
        default=None,
        description="Redacted version of the document (required for hard tasks)"
    )
    compliance_report: Optional[ComplianceReport] = Field(
        default=None,
        description="Compliance report (required for hard tasks)"
    )
    metadata: Dict[str, Any] = Field(default_factory=dict)


# ── OpenEnv Observation ───────────────────────────────────────────────────────

class PIIObservation(BaseModel):
    """Observation returned by the environment after each step."""
    done: bool = Field(default=False, description="Whether the episode is complete")
    reward: Optional[float] = Field(default=None, description="Reward for this step (0.0-1.0)")
    document: str = Field(default="", description="The document text to scan for PII")
    task_type: TaskDifficulty = Field(default=TaskDifficulty.EASY, description="Current task difficulty")
    task_id: str = Field(default="", description="Unique task identifier")
    instructions: str = Field(default="", description="What the agent should do")
    feedback: Optional[str] = Field(default=None, description="Grading feedback after action")
    total_tasks: int = Field(default=0, description="Total tasks in this episode")
    current_task_number: int = Field(default=0, description="Current task number (1-indexed)")
    metadata: Dict[str, Any] = Field(default_factory=dict)


# ── OpenEnv State ─────────────────────────────────────────────────────────────

class PIIState(BaseModel):
    """Internal environment state for the episode."""
    episode_id: Optional[str] = Field(default=None)
    step_count: int = Field(default=0)
    current_task_index: int = Field(default=0)
    total_tasks: int = Field(default=0)
    task_type: TaskDifficulty = Field(default=TaskDifficulty.EASY)
    scores: List[float] = Field(default_factory=list)
    overall_score: float = Field(default=0.0)
