"""Real-time SaaS API Bridge for Crucible (v0.7.0).

Provides a REST API for the Next.js dashboard to consume scan data,
findings, and interdiction status.
"""

import json
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="Crucible Sovereign API")

# Enable CORS for the Next.js dashboard
# Restrict origins in production to secure domains, or allow specific origins via environment variables.
allowed_origins_env = os.getenv("CRUCIBLE_ALLOWED_ORIGINS")
if allowed_origins_env:
    allowed_origins = [
        origin.strip() for origin in allowed_origins_env.split(",") if origin.strip()
    ]
else:
    # Standard local dashboard ports (Next.js, Vite, etc.)
    allowed_origins = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:3001",
        "http://127.0.0.1:3001",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]

# If allowed_origins contains "*", allow_credentials must be False
allow_credentials = "*" not in allowed_origins

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=allow_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)

REPORT_DIR = Path("~/.crucible/reports").expanduser()


class SystemStatus(BaseModel):
    version: str
    status: str
    active_scans: int
    hive_mind_size: int


@app.get("/")
async def root() -> dict[str, str]:
    return {"message": "Crucible Sovereign Engine API Active"}


@app.get("/status", response_model=SystemStatus)
async def get_status() -> dict[str, str | int]:
    # Mock status for demo
    return {
        "version": "0.7.0",
        "status": "SOVEREIGN",
        "active_scans": 0,
        "hive_mind_size": 128,
    }


@app.get("/findings")
async def get_findings() -> list[dict[str, Any]]:
    """Return all findings from recent reports."""
    all_findings = []
    if REPORT_DIR.exists():
        for report_file in REPORT_DIR.glob("*.json"):
            try:
                with open(report_file, encoding="utf-8") as f:
                    data = json.load(f)
                    # Extract failed findings
                    for module in data.get("modules", []):
                        for finding in module.get("findings", []):
                            if not finding.get("passed"):
                                all_findings.append(finding)
            except Exception:
                continue
    return all_findings[:50]  # Limit to latest 50


@app.get("/topology")
async def get_topology() -> dict[str, list[dict[str, Any]]]:
    """Return agent topology for the React Flow map."""
    # This would be generated from the swarm discovery logic
    return {
        "nodes": [
            {"id": "1", "data": {"label": "Gateway", "role": "Entry"}},
            {"id": "2", "data": {"label": "Auth", "role": "Internal"}},
            {"id": "3", "data": {"label": "Data", "role": "Internal"}},
        ],
        "edges": [
            {"id": "e1-2", "source": "1", "target": "2"},
            {"id": "e1-3", "source": "1", "target": "3"},
        ],
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
