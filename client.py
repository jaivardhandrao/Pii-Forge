"""
PII Scanner — WebSocket Client.

Provides both async and sync interfaces for interacting
with the PII Scanner environment server.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List, Optional

import websockets

from models import (
    ComplianceReport,
    PIIAction,
    PIIEntity,
    PIIObservation,
    PIIState,
    TaskDifficulty,
)


class PIIScannerClient:
    """
    WebSocket client for the PII Scanner environment.

    Usage (async):
        async with PIIScannerClient("ws://localhost:8000/ws") as client:
            obs = await client.reset(task_type="easy")
            while not obs.done:
                action = PIIAction(detected_pii=[...])
                obs = await client.step(action)

    Usage (sync):
        client = PIIScannerClient.sync_connect("ws://localhost:8000/ws")
        obs = client.sync_reset(task_type="easy")
    """

    def __init__(self, base_url: str = "ws://localhost:8000/ws"):
        self.base_url = base_url
        self._ws = None
        self._session_id = None

    async def connect(self):
        self._ws = await websockets.connect(self.base_url)
        response = await self._ws.recv()
        data = json.loads(response)
        self._session_id = data.get("session_id")
        return self

    async def close(self):
        if self._ws:
            await self._ws.send(json.dumps({"type": "close"}))
            await self._ws.close()

    async def __aenter__(self):
        return await self.connect()

    async def __aexit__(self, *args):
        await self.close()

    async def reset(self, task_type: str = "easy") -> PIIObservation:
        await self._ws.send(json.dumps({
            "type": "reset",
            "data": {"task_type": task_type},
        }))
        response = json.loads(await self._ws.recv())
        return PIIObservation(**response["data"])

    async def step(self, action: PIIAction) -> PIIObservation:
        payload = {
            "type": "step",
            "data": {
                "detected_pii": [e.model_dump() for e in action.detected_pii],
                "redacted_text": action.redacted_text,
                "compliance_report": (
                    action.compliance_report.model_dump()
                    if action.compliance_report
                    else None
                ),
            },
        }
        await self._ws.send(json.dumps(payload, default=str))
        response = json.loads(await self._ws.recv())
        return PIIObservation(**response["data"])

    async def state(self) -> PIIState:
        await self._ws.send(json.dumps({"type": "state"}))
        response = json.loads(await self._ws.recv())
        return PIIState(**response["data"])

    # ── Sync convenience methods ──────────────────────────────────────────

    @classmethod
    def sync_connect(cls, base_url: str = "ws://localhost:8000/ws") -> "PIIScannerSyncClient":
        return PIIScannerSyncClient(base_url)


class PIIScannerSyncClient:
    """Synchronous wrapper around the async client."""

    def __init__(self, base_url: str = "ws://localhost:8000/ws"):
        self._async_client = PIIScannerClient(base_url)
        self._loop = asyncio.new_event_loop()

    def connect(self):
        self._loop.run_until_complete(self._async_client.connect())
        return self

    def close(self):
        self._loop.run_until_complete(self._async_client.close())

    def reset(self, task_type: str = "easy") -> PIIObservation:
        return self._loop.run_until_complete(self._async_client.reset(task_type))

    def step(self, action: PIIAction) -> PIIObservation:
        return self._loop.run_until_complete(self._async_client.step(action))

    def state(self) -> PIIState:
        return self._loop.run_until_complete(self._async_client.state())

    def __enter__(self):
        return self.connect()

    def __exit__(self, *args):
        self.close()
