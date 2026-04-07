"""
PII Scanner — Enhanced Gradio Frontend.

Interactive UI for testing the PII Scanner environment with:
- Color-coded PII highlighting in documents
- Side-by-side redaction diff view
- Risk heatmap visualization
- Score dashboard with per-task breakdown
- Custom document scanning mode
"""

from __future__ import annotations

import html as html_lib
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import gradio as gr

sys.path.insert(0, str(Path(__file__).parent.parent))

from models import (
    ComplianceFinding,
    ComplianceReport,
    PIIAction,
    PIIEntity,
    PIIObservation,
    PIIState,
    PIIType,
    RiskLevel,
    TaskDifficulty,
)
from server.environment import PIIScannerEnvironment

# ── PII type color map ──────────────────────────────────────────────────────

PII_COLORS = {
    "NAME": "#FF6B6B",
    "EMAIL": "#4ECDC4",
    "PHONE": "#45B7D1",
    "SSN": "#F7DC6F",
    "CREDIT_CARD": "#BB8FCE",
    "DATE_OF_BIRTH": "#85C1E9",
    "AGE": "#82E0AA",
    "ADDRESS": "#F0B27A",
    "LOCATION": "#D7BDE2",
    "IP_ADDRESS": "#AED6F1",
    "EMPLOYEE_ID": "#F9E79F",
    "MEDICAL_CONDITION": "#E74C3C",
    "MEDICATION": "#CD6155",
    "ORGANIZATION": "#5DADE2",
    "SALARY": "#48C9B0",
    "BANK_ACCOUNT": "#EB984E",
    "PASSPORT": "#AF7AC5",
    "LICENSE_NUMBER": "#73C6B6",
    "USERNAME": "#F1948A",
    "PASSWORD": "#C0392B",
}

RISK_COLORS = {
    "low": "#27AE60",
    "medium": "#F39C12",
    "high": "#E74C3C",
    "critical": "#8E44AD",
}

def _new_session_state() -> Dict[str, Any]:
    """Create a fresh per-user session state."""
    return {
        "env": PIIScannerEnvironment(),
        "current_obs": None,
        "history": [],
        "last_submitted_pii": [],
    }


# ── Utility functions ───────────────────────────────────────────────────────

def highlight_pii_in_document(document: str, pii_entities: List[Dict[str, Any]]) -> str:
    """Generate HTML with color-coded PII highlights."""
    if not pii_entities or not document:
        safe_doc = html_lib.escape(document or "")
        return f"<div style='font-family:monospace;white-space:pre-wrap;padding:12px;background:#1a1a2e;color:#e0e0e0;border-radius:8px;line-height:1.8;'>{safe_doc}</div>"

    # Sort by start position descending so we can insert tags without shifting offsets
    sorted_pii = sorted(pii_entities, key=lambda x: x.get("start", 0), reverse=True)

    result = html_lib.escape(document)
    for entity in sorted_pii:
        start = entity.get("start", 0)
        end = entity.get("end", 0)
        pii_type = entity.get("pii_type", "NAME")
        color = PII_COLORS.get(pii_type, "#AAAAAA")

        tag_open = (
            f'<span style="background:{color}33;border:1px solid {color};'
            f'border-radius:3px;padding:1px 4px;position:relative;">'
            f'<span style="font-size:9px;color:{color};position:absolute;top:-14px;'
            f'left:0;white-space:nowrap;font-weight:bold;">{pii_type}</span>'
        )
        tag_close = '</span>'

        if 0 <= start < end <= len(result):
            result = result[:start] + tag_open + result[start:end] + tag_close + result[end:]

    return (
        f"<div style='font-family:monospace;white-space:pre-wrap;padding:16px 12px 12px;"
        f"background:#1a1a2e;color:#e0e0e0;border-radius:8px;line-height:2.4;'>"
        f"{result}</div>"
    )


def build_redaction_diff(original: str, redacted: str) -> str:
    """Generate side-by-side diff HTML for original vs redacted document."""
    if not redacted:
        return "<p style='color:#999;'>No redacted text submitted yet.</p>"

    original = html_lib.escape(original)
    redacted = html_lib.escape(redacted)

    # Highlight [TYPE] tags in the redacted version
    highlighted_redacted = re.sub(
        r'\[([A-Z_]+)\]',
        lambda m: (
            f'<span style="background:{PII_COLORS.get(m.group(1), "#AAAAAA")}44;'
            f'border:1px solid {PII_COLORS.get(m.group(1), "#AAAAAA")};'
            f'border-radius:3px;padding:1px 4px;font-weight:bold;'
            f'color:{PII_COLORS.get(m.group(1), "#AAAAAA")};">[{m.group(1)}]</span>'
        ),
        redacted,
    )

    return f"""
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
        <div>
            <div style="font-weight:bold;color:#E74C3C;margin-bottom:6px;font-size:13px;">
                ORIGINAL (with PII)
            </div>
            <div style="font-family:monospace;white-space:pre-wrap;padding:12px;
                        background:#2d1b1b;color:#e0e0e0;border-radius:8px;
                        border:1px solid #E74C3C44;font-size:13px;line-height:1.6;">
                {original}
            </div>
        </div>
        <div>
            <div style="font-weight:bold;color:#27AE60;margin-bottom:6px;font-size:13px;">
                REDACTED (PII removed)
            </div>
            <div style="font-family:monospace;white-space:pre-wrap;padding:12px;
                        background:#1b2d1b;color:#e0e0e0;border-radius:8px;
                        border:1px solid #27AE6044;font-size:13px;line-height:1.6;">
                {highlighted_redacted}
            </div>
        </div>
    </div>
    """


def build_risk_heatmap(pii_entities: List[Dict[str, Any]], feedback: str) -> str:
    """Build a visual risk heatmap showing PII density and types."""
    if not pii_entities:
        return "<p style='color:#999;'>Submit PII detections to see the risk analysis.</p>"

    # Count by type
    type_counts: Dict[str, int] = {}
    for e in pii_entities:
        t = e.get("pii_type", "UNKNOWN")
        type_counts[t] = type_counts.get(t, 0) + 1

    # Assign risk levels to PII types
    HIGH_RISK = {"SSN", "CREDIT_CARD", "BANK_ACCOUNT", "PASSPORT", "PASSWORD", "MEDICAL_CONDITION", "MEDICATION"}
    MEDIUM_RISK = {"NAME", "DATE_OF_BIRTH", "ADDRESS", "SALARY", "LICENSE_NUMBER", "AGE"}
    LOW_RISK = {"EMAIL", "PHONE", "IP_ADDRESS", "EMPLOYEE_ID", "LOCATION", "ORGANIZATION", "USERNAME"}

    total = len(pii_entities)
    high_count = sum(v for k, v in type_counts.items() if k in HIGH_RISK)
    med_count = sum(v for k, v in type_counts.items() if k in MEDIUM_RISK)
    low_count = sum(v for k, v in type_counts.items() if k in LOW_RISK)

    # Overall risk
    if high_count >= 2:
        overall_risk = "CRITICAL"
        overall_color = RISK_COLORS["critical"]
    elif high_count >= 1:
        overall_risk = "HIGH"
        overall_color = RISK_COLORS["high"]
    elif med_count >= 2:
        overall_risk = "MEDIUM"
        overall_color = RISK_COLORS["medium"]
    else:
        overall_risk = "LOW"
        overall_color = RISK_COLORS["low"]

    # Build bars
    bars_html = ""
    for pii_type, count in sorted(type_counts.items(), key=lambda x: -x[1]):
        color = PII_COLORS.get(pii_type, "#AAAAAA")
        if pii_type in HIGH_RISK:
            risk_label = "HIGH"
        elif pii_type in MEDIUM_RISK:
            risk_label = "MED"
        else:
            risk_label = "LOW"
        bar_width = min(count / max(type_counts.values()) * 100, 100)
        bars_html += f"""
        <div style="display:flex;align-items:center;margin:4px 0;gap:8px;">
            <div style="width:140px;font-size:12px;color:{color};font-weight:bold;text-align:right;">
                {pii_type}
            </div>
            <div style="flex:1;background:#222;border-radius:4px;height:22px;overflow:hidden;">
                <div style="width:{bar_width}%;background:{color}88;height:100%;
                            border-radius:4px;display:flex;align-items:center;
                            padding-left:8px;font-size:11px;color:#fff;font-weight:bold;">
                    {count}x
                </div>
            </div>
            <div style="font-size:10px;color:#999;width:36px;">{risk_label}</div>
        </div>
        """

    return f"""
    <div style="background:#111;border-radius:10px;padding:16px;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;">
            <div style="font-size:16px;font-weight:bold;color:#e0e0e0;">
                Risk Analysis
            </div>
            <div style="background:{overall_color}33;border:2px solid {overall_color};
                        border-radius:6px;padding:4px 14px;font-weight:bold;
                        color:{overall_color};font-size:14px;">
                {overall_risk} RISK
            </div>
        </div>
        <div style="display:flex;gap:16px;margin-bottom:14px;">
            <div style="text-align:center;flex:1;background:#1a1a2e;border-radius:8px;padding:10px;">
                <div style="font-size:28px;font-weight:bold;color:#e0e0e0;">{total}</div>
                <div style="font-size:11px;color:#999;">TOTAL PII</div>
            </div>
            <div style="text-align:center;flex:1;background:#2d1b1b;border-radius:8px;padding:10px;">
                <div style="font-size:28px;font-weight:bold;color:{RISK_COLORS['high']};">{high_count}</div>
                <div style="font-size:11px;color:#999;">HIGH RISK</div>
            </div>
            <div style="text-align:center;flex:1;background:#2d2b1b;border-radius:8px;padding:10px;">
                <div style="font-size:28px;font-weight:bold;color:{RISK_COLORS['medium']};">{med_count}</div>
                <div style="font-size:11px;color:#999;">MEDIUM</div>
            </div>
            <div style="text-align:center;flex:1;background:#1b2d1b;border-radius:8px;padding:10px;">
                <div style="font-size:28px;font-weight:bold;color:{RISK_COLORS['low']};">{low_count}</div>
                <div style="font-size:11px;color:#999;">LOW RISK</div>
            </div>
        </div>
        {bars_html}
    </div>
    """


def build_score_dashboard(scores: List[float], task_type: str, total_tasks: int = 0) -> str:
    """Build a visual score dashboard."""
    if not scores:
        return "<p style='color:#999;'>No scores yet. Start scanning!</p>"

    avg = sum(scores) / len(scores)

    # Color based on average
    if avg >= 0.9:
        avg_color = "#27AE60"
    elif avg >= 0.7:
        avg_color = "#F39C12"
    else:
        avg_color = "#E74C3C"

    bars = ""
    for i, score in enumerate(scores):
        s_color = "#27AE60" if score >= 0.9 else "#F39C12" if score >= 0.7 else "#E74C3C"
        width = score * 100
        bars += f"""
        <div style="display:flex;align-items:center;gap:8px;margin:3px 0;">
            <div style="width:60px;font-size:12px;color:#999;text-align:right;">Doc {i+1}</div>
            <div style="flex:1;background:#222;border-radius:4px;height:20px;overflow:hidden;">
                <div style="width:{width}%;background:{s_color};height:100%;border-radius:4px;
                            display:flex;align-items:center;justify-content:flex-end;
                            padding-right:6px;font-size:11px;color:#fff;font-weight:bold;">
                    {score:.0%}
                </div>
            </div>
        </div>
        """

    return f"""
    <div style="background:#111;border-radius:10px;padding:16px;">
        <div style="display:flex;align-items:baseline;gap:12px;margin-bottom:12px;">
            <div style="font-size:36px;font-weight:bold;color:{avg_color};">{avg:.0%}</div>
            <div style="font-size:13px;color:#999;">
                Average F1 &middot; {len(scores)}/{total_tasks} tasks &middot;
                <span style="text-transform:uppercase;color:#5DADE2;">{task_type}</span>
            </div>
        </div>
        {bars}
    </div>
    """


def build_pii_legend() -> str:
    """Build the color legend for PII types."""
    items = ""
    for pii_type, color in PII_COLORS.items():
        items += (
            f'<span style="display:inline-block;margin:2px 4px;padding:2px 8px;'
            f'background:{color}33;border:1px solid {color};border-radius:4px;'
            f'font-size:11px;color:{color};font-weight:bold;">{pii_type}</span>'
        )
    return f"<div style='padding:8px;background:#111;border-radius:8px;'>{items}</div>"


# ── Environment handlers ────────────────────────────────────────────────────

def reset_environment(difficulty: str, session: Dict[str, Any]):
    """Reset the environment with a new difficulty."""
    session["history"] = []
    session["last_submitted_pii"] = []

    env = session["env"]
    obs = env.reset(task_type=difficulty.lower())
    session["current_obs"] = obs

    progress = f"Task {obs.current_task_number} / {obs.total_tasks}"

    return (
        obs.document,                                               # doc_raw
        obs.instructions,                                           # instructions
        progress,                                                   # progress
        "<p style='color:#999;'>No scores yet. Start scanning!</p>",# score_dashboard
        "",                                                         # feedback
        "<p style='color:#999;'>Submit detections to see highlighted PII.</p>",  # highlighted_doc
        "<p style='color:#999;'>Submit PII detections to see the risk analysis.</p>",  # risk_heatmap
        "<p style='color:#999;'>Redaction diff available in Hard mode.</p>",  # redaction_diff
        build_pii_legend(),                                         # pii_legend
        session,                                                    # updated session state
    )


def submit_detection(pii_json_text: str, redacted_text: str, compliance_json_text: str, session: Dict[str, Any]):
    """Submit PII detection results to the environment."""
    current_obs = session.get("current_obs")

    if current_obs is None or current_obs.done:
        err = "Episode ended. Reset to start again."
        return (err, "", "", "", "", "", "", "", session)

    current_document = current_obs.document

    # Parse PII entities from JSON
    entities = []
    pii_dicts = []
    try:
        pii_data = json.loads(pii_json_text) if pii_json_text.strip() else []
        for item in pii_data:
            entities.append(PIIEntity(
                pii_type=PIIType(item.get("pii_type", item.get("type", "NAME"))),
                value=item.get("value", ""),
                start=item.get("start", 0),
                end=item.get("end", 0),
            ))
            pii_dicts.append({
                "pii_type": item.get("pii_type", item.get("type", "NAME")),
                "value": item.get("value", ""),
                "start": item.get("start", 0),
                "end": item.get("end", 0),
            })
    except (json.JSONDecodeError, ValueError) as e:
        err = f"Error parsing PII JSON: {e}"
        return (err, "", "", "", "", "", "", "", session)

    session["last_submitted_pii"] = pii_dicts

    # Parse compliance report
    compliance = None
    if compliance_json_text and compliance_json_text.strip():
        try:
            cr_data = json.loads(compliance_json_text)
            findings = []
            for f in cr_data.get("findings", []):
                findings.append(ComplianceFinding(
                    value=f.get("value", ""),
                    pii_type=PIIType(f.get("pii_type", "NAME")),
                    risk_level=RiskLevel(f.get("risk_level", "medium")),
                    regulation=f.get("regulation", ""),
                    recommended_action=f.get("recommended_action", ""),
                ))
            compliance = ComplianceReport(
                findings=findings,
                summary=cr_data.get("summary", ""),
            )
        except (json.JSONDecodeError, ValueError) as e:
            err = f"Error parsing compliance JSON: {e}"
            return (err, "", "", "", "", "", "", "", session)

    action = PIIAction(
        detected_pii=entities,
        redacted_text=redacted_text if redacted_text and redacted_text.strip() else None,
        compliance_report=compliance,
    )

    env = session["env"]
    obs = env.step(action)
    session["current_obs"] = obs
    state = env.state

    progress = f"Task {obs.current_task_number} / {obs.total_tasks}"
    if obs.done:
        progress = f"COMPLETE - All {obs.total_tasks} tasks done!"

    session["history"].append({
        "task": obs.task_id,
        "reward": obs.reward,
        "entities_submitted": len(entities),
    })

    # Build visual outputs
    highlighted = highlight_pii_in_document(current_document, pii_dicts)
    risk = build_risk_heatmap(pii_dicts, obs.feedback or "")
    score_dash = build_score_dashboard(state.scores, state.task_type.value, state.total_tasks)

    # Redaction diff
    diff_html = build_redaction_diff(current_document, redacted_text) if redacted_text else (
        "<p style='color:#999;'>No redacted text submitted (only needed for Hard mode).</p>"
    )

    next_doc = obs.document if not obs.done else "All tasks complete! See your scores below."
    feedback = obs.feedback or "No feedback"

    return (
        feedback,       # feedback
        next_doc,       # doc_raw
        progress,       # progress
        score_dash,     # score_dashboard
        highlighted,    # highlighted_doc
        risk,           # risk_heatmap
        diff_html,      # redaction_diff
        json.dumps(obs.metadata, indent=2, default=str) if obs.metadata else "",  # metadata
        session,        # updated session state
    )


def scan_custom_document(custom_text: str, pii_json_text: str) -> Tuple[str, str]:
    """Scan a custom user-provided document (demo mode, no grading)."""
    if not custom_text.strip():
        return (
            "<p style='color:#999;'>Paste a document above to scan.</p>",
            "<p style='color:#999;'>No PII detected yet.</p>",
        )

    pii_dicts = []
    try:
        pii_data = json.loads(pii_json_text) if pii_json_text.strip() else []
        for item in pii_data:
            pii_dicts.append({
                "pii_type": item.get("pii_type", item.get("type", "NAME")),
                "value": item.get("value", ""),
                "start": item.get("start", 0),
                "end": item.get("end", 0),
            })
    except (json.JSONDecodeError, ValueError):
        return (
            "<p style='color:#E74C3C;'>Invalid JSON. Check your PII detection format.</p>",
            "<p style='color:#999;'>Fix JSON to see risk analysis.</p>",
        )

    highlighted = highlight_pii_in_document(custom_text, pii_dicts)
    risk = build_risk_heatmap(pii_dicts, "")
    return highlighted, risk


# ── Gradio App ──────────────────────────────────────────────────────────────

CUSTOM_CSS = """
.gradio-container { max-width: 1400px !important; }
.score-box textarea { font-family: monospace !important; }
.feedback-box textarea { font-family: monospace !important; }
.dark { background: #0a0a0a !important; }
"""

def create_gradio_app() -> gr.Blocks:
    """Create the enhanced Gradio interface."""
    with gr.Blocks(
        title="PII Scanner Environment",
    ) as demo:

        # ── Header ──────────────────────────────────────────────────────
        gr.HTML("""
        <div style="text-align:center;padding:20px 0 10px;">
            <h1 style="font-size:32px;margin:0;color:#e0e0e0;">
                PII Scanner Environment
            </h1>
            <p style="color:#888;font-size:15px;margin:6px 0 0;">
                Detect, Classify &amp; Redact Personally Identifiable Information
                &middot; GDPR &middot; HIPAA &middot; DPDP Act 2023
            </p>
        </div>
        """)

        # ── Main Environment Tab ────────────────────────────────────────
        with gr.Tabs():
            with gr.TabItem("Environment"):
                with gr.Row():
                    # Left panel — controls
                    with gr.Column(scale=1):
                        gr.Markdown("### Controls")
                        difficulty = gr.Dropdown(
                            choices=[
                                "easy",
                                "medium_contextual",
                                "medium_obfuscated",
                                "medium_crossref",
                                "hard_audit",
                                "hard_adversarial",
                            ],
                            value="easy",
                            label="Difficulty Level",
                        )
                        reset_btn = gr.Button("Reset Environment", variant="primary")
                        progress = gr.Textbox(label="Progress", interactive=False)

                        gr.Markdown("### Score Dashboard")
                        score_dashboard = gr.HTML(
                            value="<p style='color:#999;'>No scores yet.</p>"
                        )

                        gr.Markdown("### PII Types Legend")
                        pii_legend = gr.HTML(value=build_pii_legend())

                    # Right panel — document & instructions
                    with gr.Column(scale=2):
                        gr.Markdown("### Document to Scan")
                        doc_raw = gr.Textbox(
                            label="Raw Document",
                            interactive=False,
                            lines=6,
                        )
                        instructions = gr.Textbox(
                            label="Instructions",
                            interactive=False,
                            lines=3,
                        )

                gr.Markdown("---")
                gr.Markdown("### Your Submission")

                with gr.Row():
                    with gr.Column():
                        pii_json = gr.Textbox(
                            label="Detected PII (JSON array)",
                            placeholder='[{"pii_type": "EMAIL", "value": "user@test.com", "start": 10, "end": 23}]',
                            lines=8,
                        )
                    with gr.Column():
                        redacted = gr.Textbox(
                            label="Redacted Text (Hard mode only)",
                            placeholder="Replace PII with [TYPE] tags, e.g.: Contact [NAME] at [EMAIL]...",
                            lines=8,
                        )

                compliance_json = gr.Textbox(
                    label="Compliance Report JSON (Hard mode only)",
                    placeholder='{"findings": [{"value":"...","pii_type":"EMAIL","risk_level":"medium","regulation":"GDPR Art.6","recommended_action":"..."}], "summary": "..."}',
                    lines=4,
                )

                submit_btn = gr.Button("Submit Detection", variant="primary", size="lg")

                gr.Markdown("---")
                gr.Markdown("### Results & Visualization")

                with gr.Row():
                    with gr.Column():
                        gr.Markdown("#### Grading Feedback")
                        feedback = gr.Textbox(
                            label="Feedback",
                            interactive=False,
                            lines=10,
                            elem_classes="feedback-box",
                        )
                        metadata = gr.Textbox(
                            label="Score Breakdown (JSON)",
                            interactive=False,
                            lines=6,
                        )
                    with gr.Column():
                        gr.Markdown("#### PII Highlighted Document")
                        highlighted_doc = gr.HTML(
                            value="<p style='color:#999;'>Submit detections to see highlighted PII.</p>"
                        )

                with gr.Row():
                    with gr.Column():
                        gr.Markdown("#### Risk Heatmap")
                        risk_heatmap = gr.HTML(
                            value="<p style='color:#999;'>Submit PII detections to see risk analysis.</p>"
                        )
                    with gr.Column():
                        gr.Markdown("#### Redaction Diff (Hard Mode)")
                        redaction_diff = gr.HTML(
                            value="<p style='color:#999;'>Redaction diff available in Hard mode.</p>"
                        )

            # ── Try Your Own Tab ────────────────────────────────────────
            with gr.TabItem("Try Your Own Document"):
                gr.HTML("""
                <div style="padding:12px;background:#1a1a2e;border-radius:8px;margin-bottom:12px;">
                    <p style="color:#e0e0e0;margin:0;">
                        <strong>Demo Mode:</strong> Paste any document and your PII detections
                        to visualize the highlighting and risk analysis.
                        This mode is ungraded — use it to explore or demo the scanner.
                    </p>
                </div>
                """)

                with gr.Row():
                    with gr.Column():
                        custom_text = gr.Textbox(
                            label="Paste Your Document",
                            placeholder="Paste any text containing PII here...",
                            lines=10,
                        )
                        custom_pii_json = gr.Textbox(
                            label="Your PII Detections (JSON array)",
                            placeholder='[{"pii_type": "NAME", "value": "John Doe", "start": 0, "end": 8}]',
                            lines=8,
                        )
                        custom_scan_btn = gr.Button("Visualize PII", variant="primary")

                    with gr.Column():
                        gr.Markdown("#### Highlighted Document")
                        custom_highlighted = gr.HTML(
                            value="<p style='color:#999;'>Paste a document and detections to visualize.</p>"
                        )
                        gr.Markdown("#### Risk Analysis")
                        custom_risk = gr.HTML(
                            value="<p style='color:#999;'>No PII detected yet.</p>"
                        )

            # ── About Tab ───────────────────────────────────────────────
            with gr.TabItem("About"):
                gr.Markdown("""
                ## PII Scanner Environment

                An **OpenEnv-compatible** environment where AI agents learn to detect,
                classify, and redact Personally Identifiable Information (PII)
                from real-world documents.

                ### 6 Difficulty Levels

                | # | Level | Task | Scoring |
                |---|-------|------|---------|
                | 1 | **Easy** | Detect structured PII (emails, phones, SSNs) | F1 Score |
                | 2 | **Medium Contextual** | PII in natural language (health, indirect age) | F1 Score |
                | 3 | **Medium Obfuscated** | Spelled-out numbers, encoded emails, masked IDs | F1 Score |
                | 4 | **Medium Cross-Ref** | Quasi-identifiers that re-identify when combined | F1 Score |
                | 5 | **Hard Audit** | Full audit: detect + redact + compliance report | 40/30/30 Weighted |
                | 6 | **Hard Adversarial** | Find PII leaks in poorly-redacted documents | 40/30/30 Weighted |

                ### Supported PII Types (20)

                `EMAIL`, `PHONE`, `SSN`, `CREDIT_CARD`, `DATE_OF_BIRTH`, `NAME`, `AGE`,
                `ADDRESS`, `LOCATION`, `IP_ADDRESS`, `EMPLOYEE_ID`, `MEDICAL_CONDITION`,
                `MEDICATION`, `ORGANIZATION`, `SALARY`, `BANK_ACCOUNT`, `PASSPORT`,
                `LICENSE_NUMBER`, `USERNAME`, `PASSWORD`

                ### Compliance Frameworks

                - **DPDP Act 2023** (India)
                - **GDPR** (EU)
                - **HIPAA** (US)
                - **POSH Act 2013** (India)
                - **Aadhaar Act** (India)

                ### API Endpoints

                | Endpoint | Method | Description |
                |----------|--------|-------------|
                | `/health` | GET | Health check |
                | `/reset` | POST | Start new episode |
                | `/step` | POST | Submit PII detection |
                | `/state/{session_id}` | GET | Get progress |
                | `/ws` | WebSocket | Real-time agent connection |
                | `/docs` | GET | Swagger API docs |
                """)

        # ── Per-user session state ──────────────────────────────────────
        session_state = gr.State(value=_new_session_state)

        # ── Wire up events ──────────────────────────────────────────────

        reset_btn.click(
            fn=reset_environment,
            inputs=[difficulty, session_state],
            outputs=[
                doc_raw, instructions, progress, score_dashboard,
                feedback, highlighted_doc, risk_heatmap, redaction_diff,
                pii_legend, session_state,
            ],
        )

        submit_btn.click(
            fn=submit_detection,
            inputs=[pii_json, redacted, compliance_json, session_state],
            outputs=[
                feedback, doc_raw, progress, score_dashboard,
                highlighted_doc, risk_heatmap, redaction_diff, metadata,
                session_state,
            ],
        )

        custom_scan_btn.click(
            fn=scan_custom_document,
            inputs=[custom_text, custom_pii_json],
            outputs=[custom_highlighted, custom_risk],
        )

    return demo


# ── Standalone launch ───────────────────────────────────────────────────────

if __name__ == "__main__":
    demo = create_gradio_app()
    demo.launch(
        server_name="0.0.0.0",
        server_port=7860,
        theme=gr.themes.Base(
            primary_hue=gr.themes.colors.cyan,
            secondary_hue=gr.themes.colors.red,
            neutral_hue=gr.themes.colors.gray,
            font=gr.themes.GoogleFont("Inter"),
        ),
        css=CUSTOM_CSS,
    )
