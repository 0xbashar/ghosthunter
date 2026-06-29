# enterprise/dashboard.py
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Depends, status, Request
from fastapi.security import APIKeyHeader
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import List, Optional, Dict
import asyncio, json, yaml, os, uuid
from pathlib import Path
from core.engine import GhostHunterEngine
from core.logger import Logger

log = Logger.get_logger("dashboard")
app = FastAPI(title="GhostHunter Command Center", version="3.0")

# --- Configuration & State ---
API_KEY = APIKeyHeader(name="X-API-Key")
USERS = {
    "gh-admin": {"role": "admin", "permissions": ["scan", "view", "manage", "terminate"]},
    "gh-hunter": {"role": "hunter", "permissions": ["scan", "view"]},
    "gh-viewer": {"role": "viewer", "permissions": ["view"]}
}

async def auth(api_key: str = Depends(API_KEY)):
    if api_key not in USERS:
        raise HTTPException(status_code=403, detail="Invalid API Key")
    return USERS[api_key]

# In-memory state (Replace with Redis/PostgreSQL in production)
active_scans: Dict[str, dict] = {}
findings_db: List[dict] = []
system_stats = {"workers_active": 4, "queue_size": 0, "tor_circuits": 12}

# --- Models ---
class ScanRequest(BaseModel):
    target: str
    intensity: str = "ninja"
    ai_enabled: bool = True
    tor_enabled: bool = True
    distributed: bool = False

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_text(json.dumps(message))
            except:
                pass

manager = ConnectionManager()

# --- Background Task Simulator (Replace with actual Celery/Engine calls) ---
async def mock_scan_runner(scan_id: str, req: ScanRequest):
    import random
    await manager.broadcast({"type": "scan_start", "scan_id": scan_id, "target": req.target})
    
    for i in range(10):
        await asyncio.sleep(random.uniform(1.0, 3.5))
        progress = (i + 1) * 10
        await manager.broadcast({"type": "scan_progress", "scan_id": scan_id, "progress": progress})
        
        # Simulate finding
        if random.random() > 0.6:
            sev = random.choice(["Critical", "High", "Medium", "Low"])
            finding = {
                "id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "title": f"Vulnerability found in {req.target}",
                "severity": sev,
                "confidence": round(random.uniform(0.75, 0.99), 2),
                "endpoint": f"https://{req.target}/api/v1/resource?id={random.randint(1,100)}",
                "payload": "<script>alert(1)</script>" if sev == "High" else "' OR 1=1--",
                "timestamp": str(__import__("datetime").datetime.now())
            }
            findings_db.append(finding)
            await manager.broadcast({"type": "new_finding", "data": finding})

    active_scans[scan_id]["status"] = "completed"
    await manager.broadcast({"type": "scan_complete", "scan_id": scan_id})

# --- API Endpoints ---
@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    return FileResponse("enterprise/static/index.html")

@app.post("/api/scans")
async def start_scan(req: ScanRequest, user: dict = Depends(auth)):
    if "scan" not in user["permissions"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    scan_id = f"scan_{str(uuid.uuid4())[:8]}"
    active_scans[scan_id] = {"target": req.target, "status": "running", "config": req.dict()}
    
    # In production: await scan_target.delay(req.target) or asyncio.create_task(engine.run())
    asyncio.create_task(mock_scan_runner(scan_id, req))
    
    return {"scan_id": scan_id, "status": "initiated"}

@app.get("/api/scans")
async def list_scans(user: dict = Depends(auth)):
    return list(active_scans.values())

@app.get("/api/findings")
async def get_findings(severity: Optional[str] = None, user: dict = Depends(auth)):
    if severity:
        return [f for f in findings_db if f["severity"].lower() == severity.lower()]
    return findings_db

@app.get("/api/stats")
async def get_stats(user: dict = Depends(auth)):
    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings_db:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
    
    return {
        "total_scans": len(active_scans),
        "active_scans": sum(1 for s in active_scans.values() if s["status"] == "running"),
        "total_findings": len(findings_db),
        "severity_breakdown": sev_counts,
        "system": system_stats
    }

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await asyncio.sleep(1) # Keep connection alive
    except WebSocketDisconnect:
        manager.disconnect(websocket)
