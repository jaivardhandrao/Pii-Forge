"""
PII Scanner — Inference Script
===================================
MANDATORY
- Before submitting, ensure the following variables are defined in your environment configuration:
    API_BASE_URL   The API endpoint for the LLM.
    MODEL_NAME     The model identifier to use for inference.
    HF_TOKEN       Your Hugging Face / API key.
    IMAGE_NAME     The name of the local Docker image for the environment.

- The inference script must be named `inference.py` and placed in the root directory of the project
- Participants must use OpenAI Client for all LLM calls using above variables

STDOUT FORMAT
- The script must emit exactly three line types to stdout, in this order:

    [START] task=<task_name> env=<benchmark> model=<model_name>
    [STEP]  step=<n> action=<action_str> reward=<0.00> done=<true|false> error=<msg|null>
    [END]   success=<true|false> steps=<n> score=<score> rewards=<r1,r2,...,rn>
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
from typing import List, Optional

from openai import OpenAI

from client import PIIScannerEnv
from models import (
    ComplianceFinding,
    ComplianceReport,
    PIIAction,
    PIIEntity,
    PIIObservation,
    PIIType,
    RiskLevel,
)

# ── Configuration ─────────────────────────────────────────────────────────────

IMAGE_NAME = os.getenv("IMAGE_NAME")
API_KEY = os.getenv("HF_TOKEN") or os.getenv("API_KEY") or os.getenv("OPENAI_API_KEY", "")
API_BASE_URL = os.getenv("API_BASE_URL", "https://api.openai.com/v1")
MODEL_NAME = os.getenv("MODEL_NAME", "gpt-4o-mini")

BENCHMARK = "pii_scanner"
SUCCESS_THRESHOLD = 0.1
LLM_TIMEOUT = 20

client = OpenAI(base_url=API_BASE_URL, api_key=API_KEY)

TASK_TYPES = [
    "easy",
    "medium_contextual",
    "medium_obfuscated",
    "medium_crossref",
    "hard_audit",
    "hard_adversarial",
]

# ── Structured Logging ───────────────────────────────────────────────────────


def log_start(task: str, env: str, model: str) -> None:
    print(f"[START] task={task} env={env} model={model}", flush=True)


def log_step(step: int, action: str, reward: float, done: bool, error: Optional[str]) -> None:
    error_val = error if error else "null"
    done_val = str(done).lower()
    print(
        f"[STEP] step={step} action={action} reward={reward:.2f} done={done_val} error={error_val}",
        flush=True,
    )


def log_end(success: bool, steps: int, score: float, rewards: List[float]) -> None:
    rewards_str = ",".join(f"{r:.2f}" for r in rewards)
    print(
        f"[END] success={str(success).lower()} steps={steps} score={score:.2f} rewards={rewards_str}",
        flush=True,
    )


# ── Regex-based PII Detection (fast, reliable, no LLM dependency) ────────────

# Patterns ordered by specificity (most specific first to avoid overlapping matches)
PII_PATTERNS = {
    PIIType.EMAIL: r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
    PIIType.SSN: r'\b\d{3}-\d{2}-\d{4}\b',
    PIIType.CREDIT_CARD: r'\b(?:\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}|\d{16}|X{4}[\s-]?X{4}[\s-]?\d{4}[\s-]?\d{4})\b',
    PIIType.IP_ADDRESS: r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    PIIType.PHONE: r'(?:\+\d{1,3}[\s-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}',
    PIIType.DATE_OF_BIRTH: r'\b(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}[/-]\d{1,2}[/-]\d{1,2}|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*[\s,]+\d{1,2}[\s,]+\d{4}|\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*[\s,]+\d{4})\b',
    PIIType.PASSPORT: r'\b[A-Z]\d{7,8}\b',
    PIIType.LICENSE_NUMBER: r'\b[A-Z]{1,2}\d{6,8}\b',
    PIIType.EMPLOYEE_ID: r'\b(?:EMP|ID|Employee\s*(?:ID|#|No))\s*[:\-#]?\s*\d{3,10}\b',
    PIIType.SALARY: r'\b(?:\$\s*\d[\d,.]+|\d[\d,.]+\s*(?:LPA|lpa|CTC|ctc|per\s*annum|p\.a\.)|(?:Rs\.?|INR|USD|EUR|GBP)\s*[\d,.]+)\b',
    PIIType.BANK_ACCOUNT: r'\b\d{9,18}\b',
    PIIType.USERNAME: r'@[a-zA-Z0-9_]{3,30}\b',
    PIIType.AGE: r'\b(?:age[d]?\s*(?:of\s*)?\d{1,3}|\d{1,3}\s*(?:years?\s*old|yrs?\s*old|y/?o))\b',
    PIIType.MEDICATION: r'\b(?:Metformin|Lisinopril|Atorvastatin|Omeprazole|Amlodipine|Losartan|Gabapentin|Sertraline|Insulin|Prednisone|Ibuprofen|Aspirin|Warfarin|Xanax|Adderall|Oxycodone|Morphine|Prozac|Zoloft|Lexapro)\s*(?:\d+\s*mg)?\b',
    PIIType.MEDICAL_CONDITION: r'\b(?:diabetes|hypertension|cancer|HIV|AIDS|asthma|epilepsy|depression|anxiety|bipolar|schizophrenia|arthritis|Alzheimer|dementia|COPD|hepatitis|tuberculosis|malaria|pneumonia|stroke|heart\s*(?:disease|attack|failure)|kidney\s*(?:disease|failure)|liver\s*disease|chemotherapy|dialysis|AA\s*meetings?|diabetic|pregnant|pregnancy)\b',
}

# Name patterns (separate — more heuristic)
NAME_PREFIXES = r'(?:Mr\.?|Mrs\.?|Ms\.?|Dr\.?|Prof\.?)\s+'
NAME_PATTERN = re.compile(
    rf'(?:{NAME_PREFIXES})?[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+',
)

# Address pattern (loose)
ADDRESS_PATTERN = re.compile(
    r'\b\d{1,5}\s+[A-Z][a-zA-Z\s]+(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Drive|Dr|Lane|Ln|Way|Court|Ct|Place|Pl|Circle|Cir)\b'
    r'|(?:Suite|Apt|Unit|#)\s*\d+',
    re.IGNORECASE,
)


def detect_pii_regex(document: str) -> list[PIIEntity]:
    """Detect PII using regex patterns. Fast and reliable."""
    entities = []
    used_spans = set()

    def _add(pii_type: PIIType, match: re.Match):
        span = (match.start(), match.end())
        # Avoid overlapping matches
        for s, e in used_spans:
            if span[0] < e and span[1] > s:
                return
        used_spans.add(span)
        entities.append(PIIEntity(
            pii_type=pii_type,
            value=match.group(),
            start=match.start(),
            end=match.end(),
        ))

    # Apply typed patterns
    for pii_type, pattern in PII_PATTERNS.items():
        for match in re.finditer(pattern, document, re.IGNORECASE):
            _add(pii_type, match)

    # Names (only if they look like proper names, not common words)
    for match in NAME_PATTERN.finditer(document):
        _add(PIIType.NAME, match)

    # Addresses
    for match in ADDRESS_PATTERN.finditer(document):
        _add(PIIType.ADDRESS, match)

    return entities


# ── LLM Enhancement (optional, for better scores on hard tasks) ──────────────

LLM_DETECTION_PROMPT = """You are a PII detection expert. Analyze the document and detect ALL PII entities.

For each PII found, return a JSON object with:
- "pii_type": One of: EMAIL, PHONE, SSN, CREDIT_CARD, DATE_OF_BIRTH, NAME, AGE, ADDRESS, LOCATION, IP_ADDRESS, EMPLOYEE_ID, MEDICAL_CONDITION, MEDICATION, ORGANIZATION, SALARY, BANK_ACCOUNT, PASSPORT, LICENSE_NUMBER, USERNAME, PASSWORD
- "value": The exact text as it appears
- "start": Character offset (0-indexed)
- "end": Character offset end

Detect ALL instances including obfuscated, partial, contextual, and indirect PII.

Return ONLY a valid JSON array. No explanation, no markdown.

Document:
\"\"\"
{document}
\"\"\"
"""


def detect_pii_llm(document: str) -> list[PIIEntity]:
    """Enhance detection with LLM. Returns empty list on failure."""
    try:
        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[{"role": "user", "content": LLM_DETECTION_PROMPT.format(document=document)}],
            temperature=0.1,
            max_tokens=2048,
            timeout=LLM_TIMEOUT,
        )
        text = response.choices[0].message.content.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            lines = [l for l in lines if not l.strip().startswith("```")]
            text = "\n".join(lines)
        raw_data = json.loads(text)
        entities = []
        for item in raw_data:
            try:
                entities.append(PIIEntity(
                    pii_type=PIIType(item.get("pii_type", "NAME")),
                    value=item.get("value", ""),
                    start=item.get("start", 0),
                    end=item.get("end", 0),
                ))
            except (ValueError, KeyError):
                continue
        return entities
    except Exception as exc:
        print(f"  [WARN] LLM detection failed: {exc}", file=sys.stderr)
        return []


def merge_entities(regex_entities: list[PIIEntity], llm_entities: list[PIIEntity]) -> list[PIIEntity]:
    """Merge regex and LLM entities, deduplicating by value."""
    seen = {(e.pii_type.value, e.value.lower()) for e in regex_entities}
    merged = list(regex_entities)
    for e in llm_entities:
        key = (e.pii_type.value, e.value.lower())
        if key not in seen:
            merged.append(e)
            seen.add(key)
    return merged


# ── Redaction & Compliance (local, no LLM needed) ───────────────────────────

def redact_document(document: str, entities: list[PIIEntity]) -> str:
    """Redact PII by replacing with [TYPE] tags."""
    sorted_entities = sorted(entities, key=lambda e: e.start, reverse=True)
    result = document
    for entity in sorted_entities:
        result = result[:entity.start] + f"[{entity.pii_type.value}]" + result[entity.end:]
    return result


RISK_MAP = {
    PIIType.SSN: RiskLevel.CRITICAL,
    PIIType.PASSPORT: RiskLevel.CRITICAL,
    PIIType.CREDIT_CARD: RiskLevel.HIGH,
    PIIType.BANK_ACCOUNT: RiskLevel.HIGH,
    PIIType.MEDICAL_CONDITION: RiskLevel.HIGH,
    PIIType.MEDICATION: RiskLevel.HIGH,
    PIIType.PASSWORD: RiskLevel.HIGH,
    PIIType.SALARY: RiskLevel.HIGH,
    PIIType.NAME: RiskLevel.MEDIUM,
    PIIType.EMAIL: RiskLevel.MEDIUM,
    PIIType.PHONE: RiskLevel.MEDIUM,
    PIIType.ADDRESS: RiskLevel.MEDIUM,
    PIIType.DATE_OF_BIRTH: RiskLevel.MEDIUM,
    PIIType.AGE: RiskLevel.MEDIUM,
    PIIType.IP_ADDRESS: RiskLevel.MEDIUM,
    PIIType.EMPLOYEE_ID: RiskLevel.MEDIUM,
    PIIType.LICENSE_NUMBER: RiskLevel.MEDIUM,
    PIIType.USERNAME: RiskLevel.MEDIUM,
    PIIType.LOCATION: RiskLevel.LOW,
    PIIType.ORGANIZATION: RiskLevel.LOW,
}

REGULATION_MAP = {
    PIIType.SSN: "DPDP Section 9(1), GDPR Art.9",
    PIIType.MEDICAL_CONDITION: "HIPAA §164.502, GDPR Art.9",
    PIIType.MEDICATION: "HIPAA §164.502",
    PIIType.CREDIT_CARD: "PCI-DSS Req.3, DPDP Section 4",
    PIIType.BANK_ACCOUNT: "DPDP Section 4, GDPR Art.6",
}


def build_compliance_report(entities: list[PIIEntity]) -> ComplianceReport:
    """Build compliance report from detected entities (no LLM needed)."""
    findings = []
    for e in entities:
        findings.append(ComplianceFinding(
            value=e.value,
            pii_type=e.pii_type,
            risk_level=RISK_MAP.get(e.pii_type, RiskLevel.MEDIUM),
            regulation=REGULATION_MAP.get(e.pii_type, "GDPR Art.6, DPDP Section 4"),
            recommended_action=f"Redact or anonymize {e.pii_type.value} data",
        ))

    critical_count = sum(1 for f in findings if f.risk_level == RiskLevel.CRITICAL)
    summary = f"Found {len(findings)} PII entities."
    if critical_count:
        summary += f" {critical_count} critical items require immediate remediation."
    else:
        summary += " Review and redact all detected items per applicable regulations."

    return ComplianceReport(findings=findings, summary=summary)


# ── Episode Runner ───────────────────────────────────────────────────────────


async def run_episode(env: PIIScannerEnv, task_type: str) -> float:
    """Run a single episode. Emits [START], [STEP]*, [END] to stdout."""
    is_hard = task_type in ("hard_audit", "hard_adversarial")
    use_llm = task_type != "easy"  # LLM enhancement for non-easy tasks

    result = await env.reset(task_type=task_type)

    log_start(task=task_type, env=BENCHMARK, model=MODEL_NAME)

    step_num = 0
    rewards: List[float] = []
    success = False
    score = 0.0

    try:
        while not result.done:
            step_num += 1
            obs = result.observation
            document = obs.document
            error = None

            try:
                # Fast regex detection (always runs, ~instant)
                entities = detect_pii_regex(document)

                # Optional LLM enhancement for non-easy tasks
                if use_llm:
                    llm_entities = detect_pii_llm(document)
                    entities = merge_entities(entities, llm_entities)

                # For hard tasks, generate redaction + compliance locally
                redacted_text = None
                compliance_report = None
                if is_hard:
                    redacted_text = redact_document(document, entities)
                    compliance_report = build_compliance_report(entities)

                action = PIIAction(
                    detected_pii=entities,
                    redacted_text=redacted_text,
                    compliance_report=compliance_report,
                )

                result = await env.step(action)

                reward = result.reward or 0.0
                rewards.append(reward)

                action_desc = f"detect({len(entities)}_entities)"
                if is_hard:
                    action_desc += "+redact+comply"

            except Exception as exc:
                error = str(exc).replace("\n", " ")
                reward = 0.0
                rewards.append(reward)
                action_desc = "error"

            log_step(
                step=step_num,
                action=action_desc,
                reward=reward,
                done=result.done,
                error=error,
            )

        score = sum(rewards) / len(rewards) if rewards else 0.0
        score = min(max(score, 0.0), 1.0)
        success = score >= SUCCESS_THRESHOLD

    except Exception as exc:
        print(f"[WARN] Episode failed: {exc}", file=sys.stderr)
        score = sum(rewards) / len(rewards) if rewards else 0.0
        score = min(max(score, 0.0), 1.0)

    finally:
        log_end(success=success, steps=step_num, score=score, rewards=rewards)

    return score


# ── Main ─────────────────────────────────────────────────────────────────────


async def main() -> None:
    print("=" * 60, file=sys.stderr)
    print("PII Scanner — Inference", file=sys.stderr)
    print(f"Model: {MODEL_NAME}", file=sys.stderr)
    print(f"API: {API_BASE_URL}", file=sys.stderr)
    print(f"Image: {IMAGE_NAME}", file=sys.stderr)
    print("=" * 60, file=sys.stderr)

    # PORT=8000 so the container listens on the port the SDK expects
    env = await PIIScannerEnv.from_docker_image(IMAGE_NAME, env_vars={"PORT": "8000"})
    results = {}

    try:
        for task_type in TASK_TYPES:
            print(f"\n--- Running {task_type.upper()} ---", file=sys.stderr)
            score = await run_episode(env, task_type)
            results[task_type] = score
            print(f"  Score: {score:.2%}", file=sys.stderr)
    finally:
        try:
            await env.close()
        except Exception as e:
            print(f"[DEBUG] env.close() error: {e}", file=sys.stderr)

    avg_score = sum(results.values()) / len(results) if results else 0.0
    print(f"\n{'=' * 60}", file=sys.stderr)
    print("FINAL RESULTS:", file=sys.stderr)
    for task_type, s in results.items():
        print(f"  {task_type:25s}: {s:.2%}", file=sys.stderr)
    print(f"  {'AVERAGE':25s}: {avg_score:.2%}", file=sys.stderr)
    print(f"{'=' * 60}", file=sys.stderr)


if __name__ == "__main__":
    asyncio.run(main())
