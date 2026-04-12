"""
PII Scanner — FastAPI Application.

Uses OpenEnv SDK's create_app for standard /reset, /step, /ws endpoints.
Adds custom endpoints for scanning, graded tasks, and Gradio UI.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi.responses import JSONResponse
from pydantic import BaseModel

# Add parent to path so models can be imported
sys.path.insert(0, str(Path(__file__).parent.parent))

from openenv.core.env_server.http_server import create_app

from models import PIIAction, PIIObservation
from server.environment import PIIScannerEnvironment
from server.pii_detector import get_detector
from server.tasks_graded import TASKS, TASKS_BY_ID, grade_result

# ── Create app via OpenEnv SDK (handles /reset, /step, /ws, /state, /schema) ─

app = create_app(
    PIIScannerEnvironment,
    PIIAction,
    PIIObservation,
    env_name="pii_scanner",
    max_concurrent_envs=4,
)


# ── Simple Scan Endpoint (Presidio + Aho-Corasick) ──────────────────────────

class ScanRequest(BaseModel):
    text: str
    language: str = "en"


class ScanResponse(BaseModel):
    entities: List[Dict[str, Any]]
    redacted_text: str
    entity_count: int
    type_counts: Dict[str, int]


@app.post("/scan", response_model=ScanResponse)
async def scan_text(request: ScanRequest):
    """Scan text for PII using Presidio + Aho-Corasick and return detected entities + redacted text."""
    detector = get_detector()
    result = detector.detect_and_redact(request.text, request.language)
    return result


# ── Graded Tasks API ─────────────────────────────────────────────────────────

class GradeRequest(BaseModel):
    task_id: str
    result: Optional[str] = None


@app.get("/api/tasks")
async def list_tasks():
    """List all available graded tasks (documents with PII to redact)."""
    return [
        {
            "task_id": t["task_id"],
            "title": t["title"],
            "difficulty": t["difficulty"],
            "pii_count": len(t["pii"]),
            "document": t["document"],
        }
        for t in TASKS
    ]


@app.get("/api/tasks/{task_id}")
async def get_task(task_id: str):
    """Get a single task by ID — returns the document to redact."""
    task = TASKS_BY_ID.get(task_id)
    if not task:
        return JSONResponse(status_code=404, content={"error": f"Task '{task_id}' not found."})
    return {
        "task_id": task["task_id"],
        "title": task["title"],
        "difficulty": task["difficulty"],
        "pii_count": len(task["pii"]),
        "document": task["document"],
    }


@app.post("/api/grade")
async def grade_task(request: GradeRequest):
    """Grade a redacted paragraph against ground truth PII."""
    result = grade_result(request.task_id, request.result)
    if "error" in result:
        return JSONResponse(status_code=404, content=result)
    return result


# ── Mount Gradio UI ─────────────────────────────────────────────────────────

try:
    import gradio as gr
    from server.gradio_ui import create_gradio_app

    gradio_app = create_gradio_app()
    app = gr.mount_gradio_app(app, gradio_app, path="/")
except Exception:
    # Gradio UI is optional; server works without it
    pass


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=7860)


if __name__ == "__main__":
    main()
