"""
Dashboard API — FastAPI backend for centralized scan management.
Features:
  - Multi-target scan management
  - Real-time findings via WebSocket
  - RBAC (Admin, Researcher, Viewer)
  - Integration webhooks (Jira, Slack, Teams)
"""
from fastapi import FastAPI, HTTPException, WebSocket, Depends, status
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
from typing import List, Optional
import asyncio, json
from core.engine import GhostHunterEngine
import yaml

app = FastAPI(title="GhostHunter Dashboard", version="2.0")

# RBAC
API_KEY = APIKeyHeader(name="X-API-Key")
USERS = {
    "admin_key": {"role": "admin", "permissions": ["scan", "view", "manage"]},
    "researcher_key": {"role": "researcher", "permissions": ["scan", "view"]},
    "viewer_key": {"role": "viewer", "permissions": ["view"]}
}

async def auth(api_key: str = Depends(API_KEY)):
    if api_key not in USERS:
        raise HTTPException(status_code=403, detail="Invalid API Key")
    return USERS[api_key]

def require_permission(perm: str):
    def checker(user: dict = Depends(auth)):
        if perm not in user["permissions"]:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user
    return checker

# Models
class ScanRequest(BaseModel):
    target: str
    intensity: str = "aggressive"
    ai_enabled: bool = True

class FindingResponse(BaseModel):
    id: str
    title: str
    severity: str
    confidence: float
    endpoint: str

# In-memory store (use PostgreSQL in prod)
scans = {}
findings = {}

@app.post("/scans", dependencies=[Depends(require_permission("scan"))])
async def start_scan(req: ScanRequest):
    scan_id = f"scan_{len(scans)+1}"
    scans[scan_id] = {"target": req.target, "status": "running", "findings": []}
    
    # Run scan in background
    asyncio.create_task(_run_scan(scan_id, req))
    return {"scan_id": scan_id, "status": "started"}

async def _run_scan(scan_id: str, req: ScanRequest):
    config = yaml.safe_load(open("config.yaml"))
    config["target"]["domain"] = req.target
    config["scanning"]["active_intensity"] = req.intensity
    config["ai"]["enabled"] = req.ai_enabled
    
    engine = GhostHunterEngine(config)
    await engine.run(req.target)
    
    findings[scan_id] = engine.findings
    scans[scan_id]["status"] = "completed"

@app.get("/scans", dependencies=[Depends(auth)])
async def list_scans():
    return scans

@app.get("/scans/{scan_id}/findings", dependencies=[Depends(auth)])
async def get_findings(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    return findings.get(scan_id, [])

@app.websocket("/ws/findings")
async def ws_findings(websocket: WebSocket):
    """Real-time findings stream."""
    await websocket.accept()
    while True:
        for scan_id, finding_list in findings.items():
            for f in finding_list:
                await websocket.send_text(json.dumps({
                    "scan_id": scan_id,
                    "title": f.title,
                    "severity": f.severity
                }))
        await asyncio.sleep(5)

@app.post("/integrations/jira/{finding_id}", dependencies=[Depends(require_permission("manage"))])
async def create_jira_issue(finding_id: str):
    """Create Jira issue from finding."""
    # Implementation would use Jira API
    return {"status": "Jira issue created", "finding_id": finding_id}
