"""
PII Scanner Grader — F1 Score based evaluation engine.

Grades agent submissions against ground truth PII annotations.
Supports three scoring modes:
  - Easy/Medium: PII detection F1 score
  - Hard: Weighted composite (detection + redaction + compliance)

Enhanced with:
  - Position-aware matching (overlap-based span matching)
  - Sequence-based fuzzy matching (handles obfuscated PII)
  - Partial credit for near-misses
"""

from __future__ import annotations

from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional, Tuple

from models import (
    ComplianceFinding,
    ComplianceReport,
    PIIEntity,
    PIIType,
    RiskLevel,
    TaskDifficulty,
)


# ── Value matching ──────────────────────────────────────────────────────────

def _normalize_value(value: str) -> str:
    """Normalize a PII value for fuzzy comparison."""
    return value.strip().lower().replace("  ", " ")


def _values_overlap(pred_val: str, truth_val: str, threshold: float = 0.6) -> bool:
    """
    Check if two PII values overlap sufficiently.

    Uses multiple strategies:
      1. Exact match (after normalization)
      2. Containment check
      3. Sequence-based similarity (handles obfuscated PII like spelled-out numbers)
      4. Character-level overlap (fallback)
    """
    pred_norm = _normalize_value(pred_val)
    truth_norm = _normalize_value(truth_val)

    # Exact match
    if pred_norm == truth_norm:
        return True

    # Containment check
    if pred_norm in truth_norm or truth_norm in pred_norm:
        return True

    # Sequence-based similarity (SequenceMatcher handles transpositions, insertions)
    seq_ratio = SequenceMatcher(None, pred_norm, truth_norm).ratio()
    if seq_ratio >= threshold:
        return True

    # Character-level overlap (fallback for heavily obfuscated values)
    pred_set = set(pred_norm)
    truth_set = set(truth_norm)
    if not truth_set:
        return False
    overlap = len(pred_set & truth_set) / len(truth_set)
    return overlap >= threshold


def _spans_overlap(
    pred_start: int, pred_end: int,
    truth_start: int, truth_end: int,
    threshold: float = 0.5,
) -> bool:
    """
    Check if two character spans overlap by at least `threshold` of the ground truth span.
    """
    overlap_start = max(pred_start, truth_start)
    overlap_end = min(pred_end, truth_end)
    overlap_len = max(0, overlap_end - overlap_start)

    truth_len = truth_end - truth_start
    if truth_len <= 0:
        return False

    return (overlap_len / truth_len) >= threshold


# ── Entity matching ─────────────────────────────────────────────────────────

def _match_entities(
    predictions: List[PIIEntity],
    ground_truth: List[Dict[str, Any]],
) -> Tuple[int, int, int, List[str], List[str]]:
    """
    Match predicted PII entities against ground truth.

    Uses a two-pass approach:
      Pass 1: Match by type + value overlap (primary)
      Pass 2: Match by type + span overlap (catches position-accurate but value-different detections)

    Returns: (true_positives, false_positives, false_negatives, hits, misses)
    """
    matched_truth = set()
    matched_pred = set()
    hits = []

    # Pass 1: Type + value matching
    for pi, pred in enumerate(predictions):
        if pi in matched_pred:
            continue
        for ti, gt in enumerate(ground_truth):
            if ti in matched_truth:
                continue
            # Type must match
            gt_type = gt["pii_type"]
            if isinstance(gt_type, str):
                try:
                    gt_type = PIIType(gt_type)
                except ValueError:
                    pass
            if pred.pii_type != gt_type and pred.pii_type.value != gt.get("pii_type"):
                continue
            # Value must overlap
            if _values_overlap(pred.value, gt["value"]):
                matched_truth.add(ti)
                matched_pred.add(pi)
                hits.append(
                    f'✅ {pred.pii_type.value}: "{pred.value}" matched "{gt["value"]}"'
                )
                break

    # Pass 2: Type + span overlap (for remaining unmatched)
    for pi, pred in enumerate(predictions):
        if pi in matched_pred:
            continue
        for ti, gt in enumerate(ground_truth):
            if ti in matched_truth:
                continue
            gt_type = gt["pii_type"]
            if isinstance(gt_type, str):
                try:
                    gt_type = PIIType(gt_type)
                except ValueError:
                    pass
            if pred.pii_type != gt_type and pred.pii_type.value != gt.get("pii_type"):
                continue
            # Check span overlap
            gt_start = gt.get("start", -1)
            gt_end = gt.get("end", -1)
            if gt_start >= 0 and gt_end > gt_start:
                if _spans_overlap(pred.start, pred.end, gt_start, gt_end):
                    matched_truth.add(ti)
                    matched_pred.add(pi)
                    hits.append(
                        f'✅ {pred.pii_type.value}: "{pred.value}" matched "{gt["value"]}" (by position)'
                    )
                    break

    # False positives
    false_pos_details = []
    for pi, pred in enumerate(predictions):
        if pi not in matched_pred:
            false_pos_details.append(
                f'❌ False positive: {pred.pii_type.value}: "{pred.value}"'
            )

    # Misses
    misses = []
    for ti, gt in enumerate(ground_truth):
        if ti not in matched_truth:
            misses.append(f'❌ Missed: {gt["pii_type"]}: "{gt["value"]}"')

    tp = len(matched_truth)
    fp = len(predictions) - tp
    fn = len(ground_truth) - tp

    return tp, fp, fn, hits + false_pos_details, misses


# ── F1 computation ──────────────────────────────────────────────────────────

def compute_f1(tp: int, fp: int, fn: int) -> Tuple[float, float, float]:
    """Compute precision, recall, and F1 score."""
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )
    return precision, recall, f1


# ── Redaction grading ───────────────────────────────────────────────────────

def grade_redaction(
    predicted_redacted: Optional[str],
    expected_redacted: str,
    ground_truth: List[Dict[str, Any]],
) -> Tuple[float, str]:
    """
    Grade redaction quality.
    Checks that all PII values have been replaced with [TYPE] tags.

    Returns: (score 0.0-1.0, feedback string)
    """
    if not predicted_redacted:
        return 0.0, "No redacted text provided."

    total_checks = len(ground_truth)
    passed = 0
    feedback_parts = []

    for gt in ground_truth:
        original_value = gt["value"]
        # Check that the original PII value is NOT in the redacted text
        if original_value.lower() not in predicted_redacted.lower():
            passed += 1
        else:
            feedback_parts.append(
                f'❌ PII not redacted: "{original_value}" still present'
            )

    # Check for presence of [TYPE] replacement tags
    tag_count = predicted_redacted.count("[")
    if tag_count < total_checks * 0.5:
        feedback_parts.append(
            f"⚠️ Expected ~{total_checks} redaction tags, found {tag_count}"
        )

    # Bonus: check structural similarity with expected redaction
    structural_bonus = 0.0
    if expected_redacted:
        sim = SequenceMatcher(None, predicted_redacted.lower(), expected_redacted.lower()).ratio()
        if sim >= 0.8:
            structural_bonus = 0.1  # 10% bonus for close structural match

    score = passed / total_checks if total_checks > 0 else 0.0
    score = min(score + structural_bonus, 1.0)

    feedback = (
        "\n".join(feedback_parts) if feedback_parts else "✅ All PII properly redacted."
    )
    return score, feedback


# ── Compliance grading ──────────────────────────────────────────────────────

def grade_compliance(
    predicted_report: Optional[ComplianceReport],
    expected_findings: List[Dict[str, Any]],
) -> Tuple[float, str]:
    """
    Grade compliance report quality.
    Checks for: risk level accuracy, regulation citation, and action recommendation.

    Returns: (score 0.0-1.0, feedback string)
    """
    if not predicted_report or not predicted_report.findings:
        return 0.0, "No compliance report provided."

    total_score = 0.0
    max_score = len(expected_findings) * 3  # 3 points per finding: risk, regulation, action
    feedback_parts = []

    for expected in expected_findings:
        exp_value = expected["value"]
        exp_type = expected["pii_type"]

        # Find matching finding in predicted report
        matched = None
        for pred_finding in predicted_report.findings:
            pred_type_val = (
                pred_finding.pii_type.value
                if isinstance(pred_finding.pii_type, PIIType)
                else pred_finding.pii_type
            )
            if _values_overlap(pred_finding.value, exp_value) or pred_type_val == exp_type:
                matched = pred_finding
                break

        if not matched:
            feedback_parts.append(
                f'❌ Missing compliance finding for: {exp_type} "{exp_value}"'
            )
            continue

        # Check risk level
        matched_risk = (
            matched.risk_level.value
            if isinstance(matched.risk_level, RiskLevel)
            else matched.risk_level
        )
        if matched_risk == expected["risk_level"]:
            total_score += 1.0
        else:
            total_score += 0.5  # partial credit
            feedback_parts.append(
                f'⚠️ Risk level for "{exp_value}": expected {expected["risk_level"]}, got {matched_risk}'
            )

        # Check regulation citation (keyword match)
        exp_reg_keywords = expected["regulation"].lower().split()
        pred_reg = matched.regulation.lower()
        reg_match = sum(1 for kw in exp_reg_keywords if kw in pred_reg)
        reg_score = min(reg_match / max(len(exp_reg_keywords) * 0.3, 1), 1.0)
        total_score += reg_score

        # Check recommended action (non-empty and relevant)
        if matched.recommended_action and len(matched.recommended_action) > 10:
            total_score += 1.0
        elif matched.recommended_action:
            total_score += 0.5
            feedback_parts.append(
                f'⚠️ Action for "{exp_value}" is too brief'
            )
        else:
            feedback_parts.append(
                f'❌ No recommended action for "{exp_value}"'
            )

    # Check summary
    if predicted_report.summary and len(predicted_report.summary) > 20:
        total_score += 1.0
        max_score += 1.0
    else:
        max_score += 1.0

    score = total_score / max_score if max_score > 0 else 0.0
    score = min(score, 1.0)

    feedback = (
        "\n".join(feedback_parts) if feedback_parts else "✅ Compliance report is comprehensive."
    )
    return score, feedback


# ── Main grading entry point ────────────────────────────────────────────────

def grade_submission(
    predictions: List[PIIEntity],
    ground_truth: List[Dict[str, Any]],
    task_difficulty: TaskDifficulty,
    predicted_redacted: Optional[str] = None,
    expected_redacted: Optional[str] = None,
    predicted_report: Optional[ComplianceReport] = None,
    expected_findings: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Grade a full submission.

    Easy/Medium: 100% detection F1
    Hard: 40% detection + 30% redaction + 30% compliance

    Returns dict with: reward, precision, recall, f1, feedback, breakdown
    """
    tp, fp, fn, hit_details, miss_details = _match_entities(predictions, ground_truth)
    precision, recall, f1 = compute_f1(tp, fp, fn)

    feedback_lines = hit_details + miss_details
    breakdown = {
        "detection": {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
        },
    }

    hard_tasks = (
        TaskDifficulty.HARD,
        TaskDifficulty.HARD_AUDIT,
        TaskDifficulty.HARD_ADVERSARIAL,
    )

    if task_difficulty not in hard_tasks:
        reward = f1
        feedback_lines.insert(
            0,
            f"📊 Detection F1: {f1:.2%} (P: {precision:.2%}, R: {recall:.2%})"
        )
    else:
        # Hard task: weighted composite
        redaction_score, redaction_feedback = grade_redaction(
            predicted_redacted, expected_redacted or "", ground_truth
        )
        compliance_score, compliance_feedback = grade_compliance(
            predicted_report, expected_findings or []
        )

        reward = 0.4 * f1 + 0.3 * redaction_score + 0.3 * compliance_score
        breakdown["redaction"] = round(redaction_score, 4)
        breakdown["compliance"] = round(compliance_score, 4)

        feedback_lines.insert(
            0,
            f"📊 Overall: {reward:.2%} (Detection: {f1:.2%}, Redaction: {redaction_score:.2%}, Compliance: {compliance_score:.2%})"
        )
        feedback_lines.append(f"\n📝 Redaction: {redaction_feedback}")
        feedback_lines.append(f"📋 Compliance: {compliance_feedback}")

    return {
        "reward": round(min(max(reward, 0.0), 1.0), 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "feedback": "\n".join(feedback_lines),
        "breakdown": breakdown,
    }
