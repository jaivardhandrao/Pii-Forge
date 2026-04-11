"""
PII Scanner — FastAPI Application.

Exposes the PII Scanner environment via REST + WebSocket endpoints.
Also provides a simple /scan endpoint using Presidio + Aho-Corasick.
Compatible with OpenEnv specification.
"""

from __future__ import annotations

import json
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# Add parent to path so models can be imported
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
from server.pii_detector import get_detector
from server.tasks_graded import TASKS, TASKS_BY_ID, grade_result

app = FastAPI(
    title="PII-Forge",
    description="PII detection and redaction powered by Microsoft Presidio + Aho-Corasick",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ── Session management ────────────────────────────────────────────────────────

SESSION_TTL = 1800  # 30 minutes

sessions: Dict[str, PIIScannerEnvironment] = {}
session_last_active: Dict[str, float] = {}


def _cleanup_expired_sessions():
    """Remove sessions older than SESSION_TTL."""
    now = time.time()
    expired = [sid for sid, ts in session_last_active.items() if now - ts > SESSION_TTL]
    for sid in expired:
        sessions.pop(sid, None)
        session_last_active.pop(sid, None)


def get_or_create_session(session_id: Optional[str] = None) -> tuple[str, PIIScannerEnvironment]:
    _cleanup_expired_sessions()
    if session_id and session_id in sessions:
        session_last_active[session_id] = time.time()
        return session_id, sessions[session_id]
    sid = session_id or str(uuid.uuid4())
    env = PIIScannerEnvironment()
    sessions[sid] = env
    session_last_active[sid] = time.time()
    return sid, env


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


# ── REST Endpoints (OpenEnv) ─────────────────────────────────────────────────

class ResetRequest(BaseModel):
    task_type: str = "easy"
    session_id: Optional[str] = None


class StepRequest(BaseModel):
    session_id: str
    detected_pii: list = []
    redacted_text: Optional[str] = None
    compliance_report: Optional[dict] = None


@app.get("/health")
async def health():
    return {"status": "healthy", "environment": "pii_scanner", "version": "2.0.0"}


@app.post("/reset")
async def reset(request: ResetRequest):
    sid, env = get_or_create_session(request.session_id)
    obs = env.reset(task_type=request.task_type)
    return {
        "session_id": sid,
        "observation": obs.model_dump(),
    }


@app.post("/step")
async def step(request: StepRequest):
    _cleanup_expired_sessions()
    if request.session_id not in sessions:
        return JSONResponse(
            status_code=404,
            content={"error": f"Session {request.session_id} not found. Call /reset first."},
        )
    env = sessions[request.session_id]
    session_last_active[request.session_id] = time.time()

    # Parse detected PII
    entities = []
    for item in request.detected_pii:
        try:
            entities.append(PIIEntity(
                pii_type=PIIType(item.get("pii_type", item.get("type", "NAME"))),
                value=item.get("value", ""),
                start=item.get("start", 0),
                end=item.get("end", 0),
            ))
        except (ValueError, KeyError):
            continue

    # Parse compliance report if provided
    compliance = None
    if request.compliance_report:
        findings = []
        for f in request.compliance_report.get("findings", []):
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
        compliance = ComplianceReport(
            findings=findings,
            summary=request.compliance_report.get("summary", ""),
        )

    action = PIIAction(
        detected_pii=entities,
        redacted_text=request.redacted_text,
        compliance_report=compliance,
    )

    obs = env.step(action)
    return {
        "session_id": request.session_id,
        "observation": obs.model_dump(),
    }


@app.get("/state/{session_id}")
async def get_state(session_id: str):
    if session_id not in sessions:
        return JSONResponse(
            status_code=404,
            content={"error": f"Session {session_id} not found."},
        )
    env = sessions[session_id]
    return {"session_id": session_id, "state": env.state.model_dump()}


@app.get("/state")
async def get_state_default():
    return {"error": "Provide session_id: GET /state/{session_id}"}


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
    """
    Grade a redacted paragraph against ground truth PII.

    Body: {"task_id": "uuid", "result": "redacted paragraph text"}

    If "result" is missing or empty, returns the original document with score 0.0.

    Scoring:
      - pii_removal_score: fraction of PII values removed (0.0 – 1.0)
      - content_preservation: fraction of non-PII words preserved (0.0 – 1.0)
      - final score = pii_removal_score * content_preservation

    This prevents gaming by submitting empty/blank text.
    """
    result = grade_result(request.task_id, request.result)
    if "error" in result:
        return JSONResponse(status_code=404, content=result)
    return result


# ── WebSocket Endpoint ────────────────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    sid = str(uuid.uuid4())
    env = PIIScannerEnvironment()
    sessions[sid] = env

    try:
        await websocket.send_json({"type": "connected", "session_id": sid})

        while True:
            data = await websocket.receive_json()
            msg_type = data.get("type", "")

            if msg_type == "reset":
                task_type = data.get("data", {}).get("task_type", "easy")
                obs = env.reset(task_type=task_type)
                await websocket.send_json({
                    "type": "observation",
                    "data": obs.model_dump(),
                })

            elif msg_type == "step":
                step_data = data.get("data", {})
                entities = []
                for item in step_data.get("detected_pii", []):
                    try:
                        entities.append(PIIEntity(
                            pii_type=PIIType(item.get("pii_type", "NAME")),
                            value=item.get("value", ""),
                            start=item.get("start", 0),
                            end=item.get("end", 0),
                        ))
                    except (ValueError, KeyError):
                        continue

                compliance = None
                cr_data = step_data.get("compliance_report")
                if cr_data:
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
                    compliance = ComplianceReport(
                        findings=findings,
                        summary=cr_data.get("summary", ""),
                    )

                action = PIIAction(
                    detected_pii=entities,
                    redacted_text=step_data.get("redacted_text"),
                    compliance_report=compliance,
                )
                obs = env.step(action)
                await websocket.send_json({
                    "type": "observation",
                    "data": obs.model_dump(),
                })

            elif msg_type == "state":
                await websocket.send_json({
                    "type": "state",
                    "data": env.state.model_dump(),
                })

            elif msg_type == "close":
                break

            else:
                await websocket.send_json({
                    "type": "error",
                    "data": {"message": f"Unknown message type: {msg_type}"},
                })

    except WebSocketDisconnect:
        pass
    finally:
        sessions.pop(sid, None)


# ── Mount Gradio UI at root ──────────────────────────────────────────────────

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
