"""
PII-Forge — Simplified Gradio Frontend.

A clean, easy-to-use UI where users paste text and get instant PII
detection + redaction powered by Microsoft Presidio + Aho-Corasick.
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

from server.pii_detector import get_detector
from server.tasks_graded import TASKS

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

RISK_LEVELS = {
    "SSN": "critical", "CREDIT_CARD": "critical", "BANK_ACCOUNT": "critical",
    "PASSPORT": "critical", "PASSWORD": "critical", "MEDICAL_CONDITION": "high",
    "MEDICATION": "high", "NAME": "high", "DATE_OF_BIRTH": "medium",
    "ADDRESS": "medium", "SALARY": "medium", "LICENSE_NUMBER": "medium",
    "AGE": "medium", "EMAIL": "low", "PHONE": "low", "IP_ADDRESS": "low",
    "EMPLOYEE_ID": "low", "LOCATION": "low", "ORGANIZATION": "low",
    "USERNAME": "low",
}

RISK_COLORS = {
    "low": "#27AE60",
    "medium": "#F39C12",
    "high": "#E74C3C",
    "critical": "#8E44AD",
}


# ── Visualization helpers ────────────────────────────────────────────────────

def highlight_pii(text: str, entities: List[Dict[str, Any]]) -> str:
    """Generate HTML with color-coded PII highlights."""
    if not entities or not text:
        return f"<div style='font-family:monospace;white-space:pre-wrap;padding:16px;background:#1e1e2e;color:#cdd6f4;border-radius:8px;line-height:1.8;min-height:120px;'>{html_lib.escape(text or 'No text provided.')}</div>"

    sorted_entities = sorted(entities, key=lambda x: x["start"], reverse=True)
    result = list(text)

    for entity in sorted_entities:
        start = entity["start"]
        end = entity["end"]
        pii_type = entity["pii_type"]
        color = PII_COLORS.get(pii_type, "#AAAAAA")

        tag = (
            f'<mark style="background:{color}30;border:1px solid {color};'
            f'border-radius:3px;padding:1px 4px;">'
            f'<span style="font-size:9px;color:{color};font-weight:700;'
            f'vertical-align:super;">{pii_type}</span> '
        )
        tag_close = '</mark>'

        if 0 <= start < end <= len(text):
            chunk = html_lib.escape(text[start:end])
            replacement = tag + chunk + tag_close
            result[start:end] = [replacement]

    final = "".join(result)
    return (
        f"<div style='font-family:monospace;white-space:pre-wrap;padding:16px;"
        f"background:#1e1e2e;color:#cdd6f4;border-radius:8px;line-height:2.2;"
        f"min-height:120px;'>{final}</div>"
    )


def build_stats_html(entities: List[Dict[str, Any]]) -> str:
    """Build a compact stats panel."""
    if not entities:
        return "<p style='color:#6c7086;text-align:center;padding:24px;'>No PII detected.</p>"

    type_counts: Dict[str, int] = {}
    for e in entities:
        t = e["pii_type"]
        type_counts[t] = type_counts.get(t, 0) + 1

    # Risk breakdown
    risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for pii_type, count in type_counts.items():
        risk = RISK_LEVELS.get(pii_type, "low")
        risk_counts[risk] += count

    # Overall risk
    if risk_counts["critical"] > 0:
        overall = "CRITICAL"
        overall_color = RISK_COLORS["critical"]
    elif risk_counts["high"] > 0:
        overall = "HIGH"
        overall_color = RISK_COLORS["high"]
    elif risk_counts["medium"] > 0:
        overall = "MEDIUM"
        overall_color = RISK_COLORS["medium"]
    else:
        overall = "LOW"
        overall_color = RISK_COLORS["low"]

    # Summary cards
    cards = f"""
    <div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;">
        <div style="flex:1;min-width:80px;text-align:center;background:#1e1e2e;border-radius:8px;padding:10px;">
            <div style="font-size:24px;font-weight:700;color:#cdd6f4;">{len(entities)}</div>
            <div style="font-size:10px;color:#6c7086;text-transform:uppercase;">Total PII</div>
        </div>
        <div style="flex:1;min-width:80px;text-align:center;background:#1e1e2e;border-radius:8px;padding:10px;">
            <div style="font-size:24px;font-weight:700;color:{overall_color};">{overall}</div>
            <div style="font-size:10px;color:#6c7086;text-transform:uppercase;">Risk Level</div>
        </div>
        <div style="flex:1;min-width:80px;text-align:center;background:#1e1e2e;border-radius:8px;padding:10px;">
            <div style="font-size:24px;font-weight:700;color:#cdd6f4;">{len(type_counts)}</div>
            <div style="font-size:10px;color:#6c7086;text-transform:uppercase;">PII Types</div>
        </div>
    </div>
    """

    # Type bars
    bars = ""
    for pii_type, count in sorted(type_counts.items(), key=lambda x: -x[1]):
        color = PII_COLORS.get(pii_type, "#AAAAAA")
        risk = RISK_LEVELS.get(pii_type, "low")
        risk_color = RISK_COLORS[risk]
        bar_width = min(count / max(type_counts.values()) * 100, 100)
        bars += f"""
        <div style="display:flex;align-items:center;gap:6px;margin:3px 0;">
            <div style="width:130px;font-size:11px;color:{color};font-weight:600;text-align:right;font-family:monospace;">{pii_type}</div>
            <div style="flex:1;background:#313244;border-radius:4px;height:18px;overflow:hidden;">
                <div style="width:{bar_width}%;background:{color}80;height:100%;border-radius:4px;
                            display:flex;align-items:center;padding-left:6px;
                            font-size:10px;color:#fff;font-weight:600;">{count}</div>
            </div>
            <div style="width:50px;font-size:9px;color:{risk_color};font-weight:600;text-transform:uppercase;">{risk}</div>
        </div>
        """

    return f"""
    <div style="background:#11111b;border-radius:10px;padding:14px;">
        {cards}
        {bars}
    </div>
    """


def format_entities_table(entities: List[Dict[str, Any]]) -> str:
    """Format entities as a readable markdown table."""
    if not entities:
        return "No PII detected."

    lines = ["| # | Type | Value | Position | Confidence | Source |",
             "|---|------|-------|----------|------------|--------|"]
    for i, e in enumerate(entities, 1):
        value = e["value"]
        if len(value) > 40:
            value = value[:37] + "..."
        score = e.get("score", 0)
        source = e.get("source", "unknown")
        lines.append(
            f"| {i} | `{e['pii_type']}` | {value} | {e['start']}-{e['end']} | {score:.0%} | {source} |"
        )
    return "\n".join(lines)


# ── Core scan function ───────────────────────────────────────────────────────

SAMPLE_TEXT = """CONFIDENTIAL — TERMINATION NOTICE

To: Amit Verma
Employee ID: EMP-29471
Department: Engineering
Date: March 15, 2026

Dear Amit,

This letter confirms the termination of your employment effective March 31, 2026. Your final salary of ₹18,50,000 will be credited to your HDFC Bank account ending in 4829. Your performance review scores of 2.1/5 for the last two quarters were below the minimum threshold.

Your manager, Rajesh Kumar, and HR representative Sneha Patel (sneha.patel@company.com) have documented the performance improvement plan discussions. Please return your laptop and ID badge to the Whitefield office, Bangalore.

Your health insurance (Policy #MED-88421) covering your pre-existing asthma condition will remain active until April 30, 2026. Continuation details will be sent to your registered address at 42 Brigade Road, Bangalore 560025.

For questions, contact Sneha directly at 080-4555-0192.

Sincerely,
VP Human Resources
"""


def _build_curl_command(redacted_text: str) -> str:
    """Build a ready-to-paste curl command with properly escaped JSON."""
    # Escape for JSON string: newlines → \\n, quotes → \\"
    escaped = redacted_text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return (
        f'curl -X POST http://localhost:80/api/grade \\\n'
        f'  -H "Content-Type: application/json" \\\n'
        f'  -d \'{{"task_id": "REPLACE_WITH_TASK_ID", "result": "{escaped}"}}\''
    )


def scan_document(text: str) -> Tuple[str, str, str, str, str]:
    """Run PII detection and return all UI outputs."""
    if not text or not text.strip():
        empty = "<p style='color:#6c7086;text-align:center;padding:24px;'>Paste a document above and click Scan.</p>"
        return empty, "", "", empty, "No PII detected."

    detector = get_detector()
    result = detector.detect_and_redact(text)

    entities = result["entities"]
    redacted = result["redacted_text"]

    highlighted_html = highlight_pii(text, entities)
    stats_html = build_stats_html(entities)
    entities_table = format_entities_table(entities)
    curl_cmd = _build_curl_command(redacted)

    return highlighted_html, redacted, curl_cmd, stats_html, entities_table


# ── Tasks HTML builder ───────────────────────────────────────────────────────

DIFFICULTY_COLORS = {"easy": "#27AE60", "medium": "#F39C12", "hard": "#E74C3C"}


def _build_tasks_html() -> str:
    """Build HTML cards for each graded task with curl copy buttons."""
    cards = ""
    for i, task in enumerate(TASKS, 1):
        color = DIFFICULTY_COLORS.get(task["difficulty"], "#888")
        tid = task["task_id"]
        # Escape document for HTML display
        doc_preview = html_lib.escape(task["document"][:300])
        if len(task["document"]) > 300:
            doc_preview += "..."

        curl_cmd = (
            f'curl -X POST http://localhost:80/api/grade '
            f'-H "Content-Type: application/json" '
            f"""-d '{{"task_id": "{tid}", "result": "YOUR_REDACTED_TEXT_HERE"}}'"""
        )
        curl_escaped = html_lib.escape(curl_cmd)

        # JS to copy the curl command; uses a unique ID per task
        copy_id = f"curl-{i}"

        cards += f"""
        <div style="background:#1e1e2e;border:1px solid #313244;border-radius:10px;padding:16px;margin-bottom:14px;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                <div>
                    <span style="font-size:18px;font-weight:700;color:#cdd6f4;">Task {i}: {html_lib.escape(task["title"])}</span>
                    <span style="background:{color}30;border:1px solid {color};color:{color};font-size:11px;
                                font-weight:600;padding:2px 8px;border-radius:4px;margin-left:8px;
                                text-transform:uppercase;">{task["difficulty"]}</span>
                </div>
                <span style="font-size:12px;color:#6c7086;">{len(task["pii"])} PII items</span>
            </div>

            <div style="font-size:11px;color:#6c7086;margin-bottom:6px;font-family:monospace;">
                Task ID: <code style="color:#89b4fa;background:#313244;padding:1px 6px;border-radius:3px;user-select:all;">{tid}</code>
            </div>

            <details style="margin-top:8px;">
                <summary style="cursor:pointer;color:#89b4fa;font-size:13px;font-weight:600;">
                    Show Document
                </summary>
                <pre style="background:#11111b;color:#cdd6f4;padding:12px;border-radius:6px;margin-top:6px;
                            font-size:12px;white-space:pre-wrap;max-height:250px;overflow-y:auto;
                            border:1px solid #313244;">{html_lib.escape(task["document"])}</pre>
            </details>

            <details style="margin-top:6px;">
                <summary style="cursor:pointer;color:#89b4fa;font-size:13px;font-weight:600;">
                    Show curl command
                </summary>
                <div style="position:relative;margin-top:6px;">
                    <pre id="{copy_id}" style="background:#11111b;color:#a6e3a1;padding:12px;border-radius:6px;
                                font-size:11px;white-space:pre-wrap;word-break:break-all;
                                border:1px solid #313244;user-select:all;">{curl_escaped}</pre>
                </div>
            </details>

            <div style="margin-top:8px;">
                <span style="font-size:11px;color:#6c7086;">PII to redact: </span>
                {"".join(
                    f'<span style="display:inline-block;margin:2px;padding:1px 6px;background:{PII_COLORS.get(p["type"], "#888")}25;'
                    f'border:1px solid {PII_COLORS.get(p["type"], "#888")};border-radius:3px;font-size:10px;'
                    f'color:{PII_COLORS.get(p["type"], "#888")};font-weight:600;">{p["type"]}</span>'
                    for p in task["pii"]
                )}
            </div>
        </div>
        """

    return f"""
    <div style="max-width:900px;">
        {cards}
        <div style="background:#1e1e2e;border:1px solid #313244;border-radius:10px;padding:14px;margin-top:10px;">
            <div style="font-size:13px;font-weight:600;color:#cdd6f4;margin-bottom:6px;">Quick API Reference</div>
            <div style="font-size:12px;color:#6c7086;font-family:monospace;line-height:1.8;">
                <code style="color:#89b4fa;">GET /api/tasks</code> — List all tasks<br>
                <code style="color:#89b4fa;">GET /api/tasks/{{task_id}}</code> — Get a specific task<br>
                <code style="color:#89b4fa;">POST /api/grade</code> — Grade your submission<br>
            </div>
        </div>
    </div>
    """


# ── Gradio App ───────────────────────────────────────────────────────────────

CUSTOM_CSS = """
.gradio-container { max-width: 1200px !important; margin: auto; }
textarea { font-family: 'JetBrains Mono', 'Fira Code', monospace !important; }
"""

def create_gradio_app() -> gr.Blocks:
    """Create the simplified Gradio interface."""
    with gr.Blocks(
        title="PII-Forge: Detect & Redact PII",
    ) as demo:

        # Header
        gr.Markdown("""
# PII-Forge
**Detect & Redact Personally Identifiable Information**

Powered by **Microsoft Presidio** (NER-based detection) + **Aho-Corasick** algorithm (fast keyword matching).
        """)

        with gr.Tabs():
            # ── Tab 1: Scanner ──────────────────────────────────────────
            with gr.TabItem("Scanner"):
                gr.Markdown("Paste any document below and click **Scan** to find and redact PII instantly.")

                with gr.Row():
                    with gr.Column(scale=1):
                        input_text = gr.Textbox(
                            label="Paste your document",
                            placeholder="Paste any text containing PII here...",
                            lines=14,
                            max_lines=30,
                        )
                        with gr.Row():
                            scan_btn = gr.Button("Scan & Redact", variant="primary", size="lg")
                            sample_btn = gr.Button("Load Sample", variant="secondary", size="lg")
                            clear_btn = gr.Button("Clear", size="lg")

                    with gr.Column(scale=1):
                        with gr.Tabs():
                            with gr.TabItem("Highlighted"):
                                highlighted_output = gr.HTML(
                                    value="<p style='color:#6c7086;text-align:center;padding:24px;'>Results will appear here.</p>",
                                    label="Detected PII",
                                )
                            with gr.TabItem("Redacted — Copy"):
                                redacted_output = gr.Textbox(
                                    label="Redacted text (Ctrl+A, Ctrl+C to copy)",
                                    lines=10,
                                    max_lines=20,
                                    interactive=False,
                                )
                            with gr.TabItem("Redacted — Curl"):
                                curl_output = gr.Textbox(
                                    label="Curl command (Ctrl+A, Ctrl+C — paste directly in terminal)",
                                    lines=10,
                                    max_lines=20,
                                    interactive=False,
                                )

                gr.Markdown("---")

                with gr.Row():
                    with gr.Column(scale=1):
                        gr.Markdown("### Risk Analysis")
                        stats_output = gr.HTML(
                            value="<p style='color:#6c7086;text-align:center;padding:24px;'>Scan a document to see risk analysis.</p>"
                        )
                    with gr.Column(scale=1):
                        gr.Markdown("### Detected Entities")
                        entities_output = gr.Markdown("No PII detected yet.")

            # ── Tab 2: Graded Tasks ─────────────────────────────────────
            with gr.TabItem("Graded Tasks"):
                gr.Markdown("""
### Graded PII Redaction Tasks

Each task contains a document with known PII. Your job: **remove all PII** from the document
and submit the redacted version via the API. The grader checks each PII value and scores you
out of **1.0**.

**Anti-gaming**: You must preserve the non-PII content. Submitting blank text or gibberish
scores **0.0** because `final_score = pii_removal × content_preservation`.

**How to use**:
1. Pick a task below
2. Copy the `curl` command
3. Replace `YOUR_REDACTED_TEXT_HERE` with your redacted version
4. The API returns your score with per-PII breakdown
                """)

                tasks_html = _build_tasks_html()
                gr.HTML(value=tasks_html)

        # Footer
        gr.Markdown("""
---
**PII Types Detected**: NAME, EMAIL, PHONE, SSN, CREDIT_CARD, DATE_OF_BIRTH, AGE, ADDRESS, LOCATION,
IP_ADDRESS, EMPLOYEE_ID, MEDICAL_CONDITION, MEDICATION, ORGANIZATION, SALARY, BANK_ACCOUNT, PASSPORT,
LICENSE_NUMBER, USERNAME, PASSWORD

**Engines**: Microsoft Presidio (NLP/NER) + Aho-Corasick (fast pattern matching) + Custom regex patterns
        """)

        # Wire up events
        scan_btn.click(
            fn=scan_document,
            inputs=[input_text],
            outputs=[highlighted_output, redacted_output, curl_output, stats_output, entities_output],
        )

        sample_btn.click(
            fn=lambda: SAMPLE_TEXT,
            inputs=[],
            outputs=[input_text],
        )

        clear_btn.click(
            fn=lambda: (
                "",
                "<p style='color:#6c7086;text-align:center;padding:24px;'>Results will appear here.</p>",
                "",
                "",
                "<p style='color:#6c7086;text-align:center;padding:24px;'>Scan a document to see risk analysis.</p>",
                "No PII detected yet.",
            ),
            inputs=[],
            outputs=[input_text, highlighted_output, redacted_output, curl_output, stats_output, entities_output],
        )

    return demo


# ── Standalone launch ────────────────────────────────────────────────────────

if __name__ == "__main__":
    demo = create_gradio_app()
    demo.launch(server_name="0.0.0.0", server_port=7860, css=CUSTOM_CSS)
