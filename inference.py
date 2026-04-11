"""
PII Scanner — Inference Script
===================================
MANDATORY
- Before submitting, ensure the following variables are defined in your environment configuration:
    API_BASE_URL   The API endpoint for the LLM.
    MODEL_NAME     The model identifier to use for inference.
    HF_TOKEN       Your Hugging Face / API key.

- The inference script must be named `inference.py` and placed in the root directory of the project
- Participants must use OpenAI Client for all LLM calls using above variables

STDOUT FORMAT
- The script must emit exactly three line types to stdout, in this order:

    [START] task=<task_name> env=<benchmark> model=<model_name>
    [STEP]  step=<n> action=<action_str> reward=<0.00> done=<true|false> error=<msg|null>
    [END]   success=<true|false> steps=<n> score=<score> rewards=<r1,r2,...,rn>

  Rules:
    - One [START] line at episode begin.
    - One [STEP] line per step, immediately after env.step() returns.
    - One [END] line after env.close(), always emitted (even on exception).
    - reward and rewards are formatted to 2 decimal places.
    - done and success are lowercase booleans: true or false.
    - error is the raw last_action_error string, or null if none.
    - All fields on a single line with no newlines within a line.
    - Each tasks should return score in [0, 1]
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import List, Optional

from openai import OpenAI

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from models import (
    ComplianceFinding,
    ComplianceReport,
    PIIAction,
    PIIEntity,
    PIIObservation,
    PIIType,
    RiskLevel,
    TaskDifficulty,
)
from server.environment import PIIScannerEnvironment

# ── Configuration ─────────────────────────────────────────────────────────────

API_BASE_URL = os.getenv("API_BASE_URL", "https://api.openai.com/v1")
MODEL_NAME = os.getenv("MODEL_NAME", "gpt-4o-mini")
HF_TOKEN = os.getenv("HF_TOKEN", "")
BENCHMARK = "pii_scanner"
SUCCESS_THRESHOLD = 0.1  # normalized score in [0, 1]

client = OpenAI(
    base_url=API_BASE_URL,
    api_key=HF_TOKEN or os.getenv("OPENAI_API_KEY", ""),
)

# ── Structured Logging (MANDATORY FORMAT) ─────────────────────────────────────

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


# ── Prompts ───────────────────────────────────────────────────────────────────

DETECTION_PROMPT = """You are a PII (Personally Identifiable Information) detection expert.

Analyze the following document and detect ALL PII entities.

For each PII found, return a JSON object with:
- "pii_type": One of: EMAIL, PHONE, SSN, CREDIT_CARD, DATE_OF_BIRTH, NAME, AGE, ADDRESS, LOCATION, IP_ADDRESS, EMPLOYEE_ID, MEDICAL_CONDITION, MEDICATION, ORGANIZATION, SALARY, BANK_ACCOUNT, PASSPORT, LICENSE_NUMBER, USERNAME, PASSWORD
- "value": The exact text of the PII as it appears in the document
- "start": Character offset where PII starts (0-indexed)
- "end": Character offset where PII ends

IMPORTANT rules:
- Use exact character positions from the document
- Detect ALL instances, even partial or obfuscated ones
- Spelled-out numbers (e.g., "four-zero-eight") count as PII if they represent phone numbers, IPs, etc.
- Partially masked values (e.g., "XXXX-XXXX-7834") are still PII
- Indirect references to age ("mid-fifties", "born in '94") count as AGE or DATE_OF_BIRTH
- Health-related terms linked to a person (e.g., "diabetic", "chemotherapy", "AA meetings") are MEDICAL_CONDITION
- Medications (e.g., "Metformin 500mg") are MEDICATION
- Salary hints ("45 LPA", "north of 20 lakhs") are SALARY

Return ONLY a valid JSON array. No explanation, no markdown.

Document:
\"\"\"
{document}
\"\"\"
"""

SECOND_PASS_PROMPT = """You are a PII detection specialist doing a SECOND PASS review.

A first-pass detector found these PII entities:
{first_pass}

Review the document again. Look SPECIFICALLY for PII that the first pass MISSED:
- Contextual PII: health conditions mentioned casually, indirect age references
- Obfuscated PII: spelled-out numbers, partially masked values, encoded emails ("name at domain dot com")
- Implicit PII: organization names that reveal identity, locations mentioned in passing
- Linked PII: names of family members, emergency contacts, supervisors

Return ONLY the ADDITIONAL PII entities not already found. If nothing was missed, return an empty array [].

Return ONLY a valid JSON array with: pii_type, value, start, end. No explanation.

Document:
\"\"\"
{document}
\"\"\"
"""

REDACTION_PROMPT = """You are a data privacy expert. Given the following document and list of detected PII, create a redacted version where each PII value is replaced with its type tag in brackets.

Example: "John at john@test.com" -> "[NAME] at [EMAIL]"

Rules:
- Replace EVERY detected PII value with its [TYPE] tag
- Keep all non-PII text exactly as-is
- Do not add or remove any other text

Document:
\"\"\"
{document}
\"\"\"

Detected PII:
{pii_list}

Return ONLY the redacted document text. No explanation.
"""

COMPLIANCE_PROMPT = """You are a Chief Privacy Officer conducting a compliance audit. Given the detected PII, generate a compliance report under the specified regulatory framework.

Document:
\"\"\"
{document}
\"\"\"

Detected PII:
{pii_list}

Applicable Frameworks: {framework}

For each PII entity, assess:
1. risk_level: "low", "medium", "high", or "critical"
   - critical: SSN, Aadhaar, biometrics, children's data
   - high: financial data, medical conditions, passwords
   - medium: names, DOB, addresses, contact info
   - low: organization names, general locations
2. regulation: Cite the specific regulation (e.g., "DPDP Section 9(1)", "HIPAA §164.502", "GDPR Art.6")
3. recommended_action: Specific actionable recommendation

Return a JSON object with:
- "findings": Array of objects with: value, pii_type, risk_level, regulation, recommended_action
- "summary": 2-3 sentence executive summary covering total PII count, highest risk items, and primary regulatory concern

Return ONLY valid JSON. No explanation, no markdown.
"""


# ── LLM Helper ────────────────────────────────────────────────────────────────

def call_llm(prompt: str) -> str:
    """Call the LLM and return the response text."""
    try:
        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            max_tokens=4096,
            timeout=90,
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        print(f"  [ERROR] LLM call failed: {e}", file=sys.stderr)
        raise


def parse_json_response(text: str) -> any:
    """Parse JSON from LLM response, handling markdown code blocks."""
    text = text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        lines = [line for line in lines if not line.strip().startswith("```")]
        text = "\n".join(lines)
    return json.loads(text)


# ── Agent Logic ───────────────────────────────────────────────────────────────

def _parse_entities(raw_data: list) -> list[PIIEntity]:
    """Parse a list of raw dicts into PIIEntity objects."""
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


def detect_pii(document: str, task_type: str = "easy") -> list[PIIEntity]:
    """
    Use LLM to detect PII in a document.
    For medium/hard tasks, runs a second pass to catch contextual and obfuscated PII.
    """
    prompt = DETECTION_PROMPT.format(document=document)
    response = call_llm(prompt)

    try:
        first_pass_data = parse_json_response(response)
    except json.JSONDecodeError:
        print("  [WARN] Failed to parse first pass response", file=sys.stderr)
        return []

    entities = _parse_entities(first_pass_data)

    # Second pass for non-easy tasks
    if task_type != "easy":
        first_pass_summary = json.dumps(
            [{"pii_type": e.pii_type.value, "value": e.value} for e in entities],
            indent=2,
        )
        second_prompt = SECOND_PASS_PROMPT.format(
            first_pass=first_pass_summary,
            document=document,
        )
        try:
            second_response = call_llm(second_prompt)
            second_data = parse_json_response(second_response)
            additional = _parse_entities(second_data)

            existing_values = {(e.pii_type.value, e.value.lower()) for e in entities}
            for new_entity in additional:
                key = (new_entity.pii_type.value, new_entity.value.lower())
                if key not in existing_values:
                    entities.append(new_entity)
                    existing_values.add(key)
        except (json.JSONDecodeError, Exception) as exc:
            print(f"  [WARN] Second pass failed: {exc}", file=sys.stderr)

    return entities


def generate_redaction(document: str, entities: list[PIIEntity]) -> str:
    """Use LLM to generate redacted version of the document."""
    pii_list = json.dumps([e.model_dump() for e in entities], indent=2, default=str)
    prompt = REDACTION_PROMPT.format(document=document, pii_list=pii_list)
    return call_llm(prompt)


def generate_compliance_report(
    document: str, entities: list[PIIEntity], framework: str
) -> ComplianceReport:
    """Use LLM to generate a compliance report."""
    pii_list = json.dumps([e.model_dump() for e in entities], indent=2, default=str)
    prompt = COMPLIANCE_PROMPT.format(
        document=document, pii_list=pii_list, framework=framework
    )
    response = call_llm(prompt)

    try:
        cr_data = parse_json_response(response)
    except json.JSONDecodeError:
        return ComplianceReport(findings=[], summary="Failed to generate report.")

    findings = []
    for f in cr_data.get("findings", []):
        try:
            findings.append(ComplianceFinding(
                value=f.get("value", ""),
                pii_type=PIIType(f.get("pii_type", "NAME")),
                risk_level=RiskLevel(f.get("risk_level", "medium")),
                regulation=f.get("regulation", ""),
                recommended_action=f.get("recommended_action", ""),
            ))
        except (ValueError, KeyError):
            continue

    return ComplianceReport(
        findings=findings,
        summary=cr_data.get("summary", ""),
    )


# ── Episode Runner ────────────────────────────────────────────────────────────

def run_episode(env: PIIScannerEnvironment, task_type: str) -> float:
    """
    Run a single episode for the given task type.
    Emits [START], [STEP]*, [END] to stdout in the required format.
    """
    is_hard = task_type in ("hard_audit", "hard_adversarial")

    obs = env.reset(task_type=task_type)
    state = env.state

    log_start(task=task_type, env=BENCHMARK, model=MODEL_NAME)

    step_num = 0
    rewards: List[float] = []
    success = False

    try:
        while not obs.done:
            step_num += 1
            document = obs.document
            error = None

            try:
                # Step 1: Detect PII (multi-pass for non-easy)
                entities = detect_pii(document, task_type)

                # Step 2: For hard tasks, generate redaction and compliance report
                redacted_text = None
                compliance_report = None
                if is_hard:
                    redacted_text = generate_redaction(document, entities)
                    compliance_report = generate_compliance_report(
                        document, entities, "DPDP Act 2023 (India), GDPR, HIPAA"
                    )

                # Build action
                action = PIIAction(
                    detected_pii=entities,
                    redacted_text=redacted_text,
                    compliance_report=compliance_report,
                )

                # Submit
                obs = env.step(action)

                reward = obs.reward if obs.reward is not None else 0.0
                rewards.append(reward)

                # Build compact action description for log
                action_desc = f"detect({len(entities)}_entities)"
                if is_hard:
                    action_desc = f"detect({len(entities)}_entities)+redact+comply"

            except Exception as exc:
                error = str(exc).replace("\n", " ")
                reward = 0.0
                rewards.append(reward)
                action_desc = "error"

            log_step(
                step=step_num,
                action=action_desc,
                reward=reward,
                done=obs.done,
                error=error,
            )

        # Compute final score (average reward, clamped to [0, 1])
        score = sum(rewards) / len(rewards) if rewards else 0.0
        score = min(max(score, 0.0), 1.0)
        success = score >= SUCCESS_THRESHOLD

    except Exception as exc:
        print(f"[WARN] Episode failed: {exc}", file=sys.stderr)
        score = sum(rewards) / len(rewards) if rewards else 0.0
        score = min(max(score, 0.0), 1.0)
        success = False

    finally:
        log_end(success=success, steps=step_num, score=score, rewards=rewards)

    return score


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    """Run baseline inference across all 6 difficulty levels."""
    print("=" * 60, file=sys.stderr)
    print("PII Scanner — Baseline Inference", file=sys.stderr)
    print(f"Model: {MODEL_NAME}", file=sys.stderr)
    print(f"API: {API_BASE_URL}", file=sys.stderr)
    print("=" * 60, file=sys.stderr)

    env = PIIScannerEnvironment()
    results = {}

    task_types = [
        "easy",
        "medium_contextual",
        "medium_obfuscated",
        "medium_crossref",
        "hard_audit",
        "hard_adversarial",
    ]

    try:
        for task_type in task_types:
            print(f"\n--- Running {task_type.upper()} tasks ---", file=sys.stderr)
            start_time = time.time()

            score = run_episode(env, task_type)
            elapsed = time.time() - start_time

            results[task_type] = score
            print(f"  Score: {score:.2%} ({elapsed:.1f}s)", file=sys.stderr)
    finally:
        env.close()

    # Final summary to stderr (not stdout — stdout is reserved for [START]/[STEP]/[END])
    avg_score = sum(results.values()) / len(results)
    print(f"\n{'=' * 60}", file=sys.stderr)
    print("FINAL RESULTS:", file=sys.stderr)
    for task_type, score in results.items():
        print(f"  {task_type:25s}: {score:.2%}", file=sys.stderr)
    print(f"  {'AVERAGE':25s}: {avg_score:.2%}", file=sys.stderr)
    print(f"{'=' * 60}", file=sys.stderr)


if __name__ == "__main__":
    main()
