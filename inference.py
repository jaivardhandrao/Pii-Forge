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

import asyncio
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor
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
LLM_TIMEOUT = 30

TASK_TYPES = [
    "easy",
    "medium_contextual",
    "medium_obfuscated",
    "medium_crossref",
    "hard_audit",
    "hard_adversarial",
]

client = OpenAI(base_url=API_BASE_URL, api_key=API_KEY)
executor = ThreadPoolExecutor(max_workers=3)

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


# ── Prompts ──────────────────────────────────────────────────────────────────

DETECTION_PROMPT = """You are a PII detection expert. Analyze the document and detect ALL PII entities.

For each PII found, return a JSON object with:
- "pii_type": One of: EMAIL, PHONE, SSN, CREDIT_CARD, DATE_OF_BIRTH, NAME, AGE, ADDRESS, LOCATION, IP_ADDRESS, EMPLOYEE_ID, MEDICAL_CONDITION, MEDICATION, ORGANIZATION, SALARY, BANK_ACCOUNT, PASSPORT, LICENSE_NUMBER, USERNAME, PASSWORD
- "value": The exact text of the PII as it appears
- "start": Character offset where PII starts (0-indexed)
- "end": Character offset where PII ends

IMPORTANT:
- Detect ALL instances, even partial or obfuscated ones
- Spelled-out numbers count as PII if they represent phone numbers, IPs, etc.
- Partially masked values (e.g., "XXXX-XXXX-7834") are still PII
- Indirect age references ("mid-fifties", "born in '94") count as AGE or DATE_OF_BIRTH
- Health terms linked to a person are MEDICAL_CONDITION
- Medications are MEDICATION
- Salary hints ("45 LPA") are SALARY

Return ONLY a valid JSON array. No explanation, no markdown.

Document:
\"\"\"
{document}
\"\"\"
"""

REDACTION_PROMPT = """You are a data privacy expert. Replace each detected PII with its [TYPE] tag.

Example: "John at john@test.com" -> "[NAME] at [EMAIL]"

Rules:
- Replace EVERY detected PII value with its [TYPE] tag
- Keep all non-PII text exactly as-is

Document:
\"\"\"
{document}
\"\"\"

Detected PII:
{pii_list}

Return ONLY the redacted document text. No explanation.
"""

COMPLIANCE_PROMPT = """You are a Chief Privacy Officer. Given detected PII, generate a compliance report.

Detected PII:
{pii_list}

Frameworks: {framework}

For each PII, assess:
- risk_level: "low", "medium", "high", or "critical"
- regulation: Cite specific regulation
- recommended_action: Specific recommendation

Return JSON with:
- "findings": Array of {{value, pii_type, risk_level, regulation, recommended_action}}
- "summary": 2-3 sentence summary

Return ONLY valid JSON.
"""


# ── LLM Helper ───────────────────────────────────────────────────────────────


def call_llm(prompt: str, max_tokens: int = 2048) -> str:
    """Call the LLM and return the response text."""
    response = client.chat.completions.create(
        model=MODEL_NAME,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.1,
        max_tokens=max_tokens,
        timeout=LLM_TIMEOUT,
    )
    return response.choices[0].message.content.strip()


def parse_json_response(text: str):
    """Parse JSON from LLM response, handling markdown code blocks."""
    text = text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        lines = [line for line in lines if not line.strip().startswith("```")]
        text = "\n".join(lines)
    return json.loads(text)


# ── Agent Logic ──────────────────────────────────────────────────────────────


def _parse_entities(raw_data: list) -> list[PIIEntity]:
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


def detect_pii(document: str) -> list[PIIEntity]:
    """Use LLM to detect PII in a document."""
    prompt = DETECTION_PROMPT.format(document=document)
    response = call_llm(prompt)
    try:
        data = parse_json_response(response)
    except json.JSONDecodeError:
        return []
    return _parse_entities(data)


def generate_redaction(document: str, entities: list[PIIEntity]) -> str:
    pii_list = json.dumps([e.model_dump() for e in entities], indent=2, default=str)
    prompt = REDACTION_PROMPT.format(document=document, pii_list=pii_list)
    return call_llm(prompt)


def generate_compliance_report(
    document: str, entities: list[PIIEntity], framework: str
) -> ComplianceReport:
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
    return ComplianceReport(findings=findings, summary=cr_data.get("summary", ""))


# ── Episode Runner ───────────────────────────────────────────────────────────


async def run_episode(env: PIIScannerEnv, task_type: str) -> float:
    """Run a single episode. Emits [START], [STEP]*, [END] to stdout."""
    is_hard = task_type in ("hard_audit", "hard_adversarial")

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
                # Detect PII
                entities = detect_pii(document)

                # For hard tasks, run redaction + compliance in parallel
                redacted_text = None
                compliance_report = None
                if is_hard:
                    redact_future = executor.submit(generate_redaction, document, entities)
                    comply_future = executor.submit(
                        generate_compliance_report,
                        document, entities, "DPDP Act 2023 (India), GDPR, HIPAA",
                    )
                    try:
                        redacted_text = redact_future.result(timeout=LLM_TIMEOUT + 5)
                    except Exception:
                        pass
                    try:
                        compliance_report = comply_future.result(timeout=LLM_TIMEOUT + 5)
                    except Exception:
                        pass

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

    env = await PIIScannerEnv.from_docker_image(IMAGE_NAME)
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
    for task_type, score in results.items():
        print(f"  {task_type:25s}: {score:.2%}", file=sys.stderr)
    print(f"  {'AVERAGE':25s}: {avg_score:.2%}", file=sys.stderr)
    print(f"{'=' * 60}", file=sys.stderr)


if __name__ == "__main__":
    asyncio.run(main())
