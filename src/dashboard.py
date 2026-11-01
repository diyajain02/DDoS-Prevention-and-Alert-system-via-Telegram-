"""Light-SOC Web Dashboard - FastAPI Backend"""
import asyncio
import json
import logging
import os
import secrets
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Depends, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field
from starlette.websockets import WebSocketState

# Import Light-SOC modules
import sys
sys.path.insert(0, '/opt/data/light-soc')

from src.config_loader import get_config, load_config
from src.models import IncidentReport, BlockedIP, LogEntry, Severity
from src.blocker import get_blocker
from src.report_generator import get_report_generator
from src.fim import get_fim_monitor
from src.vulnerability_detector import get_vuln_detector
from src.sca import get_sca_scanner
from src.threat_intel import get_threat_intel_manager
from src.agent import get_agent_manager, AgentStatus
from src.main import LightSOC

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Security
SECRET_KEY = os.environ.get("LIGHT_SOC_SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer(auto_error=False)

# Global state
light_soc: Optional[LightSOC] = None
connected_websockets: Set[WebSocket] = set()
dashboard_config: Dict[str, Any] = {}

# Pydantic models
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class LoginRequest(BaseModel):
    username: str
    password: str

class IncidentResponse(BaseModel):
    id: str
    incident_type: str
    severity: str
    attacker_ip: str
    targeted_usernames: List[str]
    timeline: List[Dict[str, Any]]
    total_attempts: int
    successful: bool
    recommended_mitigation: List[str]
    confidence: float
    created_at: str
    raw_logs: List[str] = []

class BlockedIPResponse(BaseModel):
    ip: str
    reason: str
    blocked_at: str
    expires_at: Optional[str]
    active: bool
    rule_handle: Optional[str]

class AgentResponse(BaseModel):
    agent_id: str
    name: str
    ip: str
    platform: str
    version: str
    status: str
    registered_at: str
    last_heartbeat: Optional[str]
    tags: List[str]

class ScanStatusResponse(BaseModel):
    fim: Dict[str, Any]
    vulnerability: Dict[str, Any]
    sca: Dict[str, Any]
    threat_intel: Dict[str, Any]

class SystemStatusResponse(BaseModel):
    running: bool
    blocked_ips: int
    total_incidents: int
    ollama_healthy: bool
    modules: Dict[str, bool]
    fim_baseline_files: int = 0
    fim_alerts: int = 0
    vuln_total_packages: int = 0
    vuln_vulnerable_packages: int = 0
    vuln_total_cves: int = 0
    sca_total_checks: int = 0
    sca_passed: int = 0
    sca_failed: int = 0
    threat_intel_indicators: int = 0
    threat_intel_feeds: int = 0

class BlockIPRequest(BaseModel):
    ip: str
    reason: str = "Manual block from dashboard"
    duration: int = 3600

class UnblockIPRequest(BaseModel):
    ip: str

# Auth functions
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# WebSocket manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                if connection.client_state == WebSocketState.CONNECTED:
                    await connection.send_json(message)
            except Exception:
                pass

manager = ConnectionManager()

# Background task for real-time updates
async def background_updates():
    while True:
        try:
            if light_soc:
                status_data = light_soc.get_status()
                await manager.broadcast({
                    "type": "status_update",
                    "data": status_data,
                    "timestamp": datetime.utcnow().isoformat()
                })
        except Exception as e:
            logger.error(f"Background update error: {e}")
        await asyncio.sleep(5)  # Update every 5 seconds

# Lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    global light_soc, dashboard_config
    
    # Load config
    config_path = os.environ.get("LIGHT_SOC_CONFIG", "/opt/data/light-soc/config/config.yaml")
    load_config(config_path)
    dashboard_config = get_config()
    
    # Initialize Light-SOC
    light_soc = LightSOC(config_path)
    
    # Start background task
    task = asyncio.create_task(background_updates())
    
    yield
    
    # Cleanup
    task.cancel()
    if light_soc:
        light_soc.stop()

# Create FastAPI app
app = FastAPI(
    title="Light-SOC Dashboard",
    description="Lightweight SOC with NGFW capabilities - Web Dashboard",
    version="0.1.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files (frontend will be served from /static)
static_dir = Path(__file__).parent / "static"
static_dir.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=static_dir), name="static")

# Health check
@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

# Auth endpoints
@app.post("/api/auth/login", response_model=Token)
async def login(request: LoginRequest):
    # Default admin credentials (change in production!)
    default_username = dashboard_config.get("dashboard", {}).get("username", "admin")
    default_password_hash = dashboard_config.get("dashboard", {}).get("password_hash", "")
    
    if request.username == default_username:
        if default_password_hash and verify_password(request.password, default_password_hash):
            pass
        elif not default_password_hash and request.password == "light-soc-admin":
            pass  # Default password for first login
        else:
            raise HTTPException(status_code=401, detail="Invalid credentials")
    else:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    access_token = create_access_token(data={"sub": request.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/api/auth/me")
async def get_me(current_user: str = Depends(get_current_user)):
    return {"username": current_user}

# Incident endpoints
@app.get("/api/incidents", response_model=List[IncidentResponse])
async def get_incidents(
    limit: int = 50,
    offset: int = 0,
    severity: Optional[str] = None,
    current_user: str = Depends(get_current_user)
):
    if not light_soc:
        raise HTTPException(status_code=503, detail="Light-SOC not initialized")
    
    incidents = light_soc.list_incidents()
    
    # Filter by severity
    if severity:
        incidents = [i for i in incidents if i.severity == severity.upper()]
    
    # Sort by created_at desc
    incidents.sort(key=lambda x: x.created_at, reverse=True)
    
    # Paginate
    incidents = incidents[offset:offset+limit]
    
    return [
        IncidentResponse(
            id=f"inc_{idx}",
            incident_type=inc.incident_type,
            severity=inc.severity,
            attacker_ip=inc.attacker_ip,
            targeted_usernames=inc.targeted_usernames,
            timeline=[{"timestamp": t.timestamp, "event": t.event, "details": t.details} for t in inc.timeline],
            total_attempts=inc.total_attempts,
            successful=inc.successful,
            recommended_mitigation=inc.recommended_mitigation,
            confidence=inc.confidence,
            created_at=inc.created_at.isoformat(),
            raw_logs=inc.raw_logs
        )
        for idx, inc in enumerate(incidents)
    ]

@app.get("/api/incidents/{incident_id}", response_model=IncidentResponse)
async def get_incident(incident_id: str, current_user: str = Depends(get_current_user)):
    if not light_soc:
        raise HTTPException(status_code=503, detail="Light-SOC not initialized")
    
    incidents = light_soc.list_incidents()
    idx = int(incident_id.replace("inc_", "")) if incident_id.startswith("inc_") else 0
    
    if idx >= len(incidents):
        raise HTTPException(status_code=404, detail="Incident not found")
    
    inc = incidents[idx]
    return IncidentResponse(
        id=incident_id,
        incident_type=inc.incident_type,
        severity=inc.severity,
        attacker_ip=inc.attacker_ip,
        targeted_usernames=inc.targeted_usernames,
        timeline=[{"timestamp": t.timestamp, "event": t.event, "details": t.details} for t in inc.timeline],
        total_attempts=inc.total_attempts,
        successful=inc.successful,
        recommended_mitigation=inc.recommended_mitigation,
        confidence=inc.confidence,
        created_at=inc.created_at.isoformat(),
        raw_logs=inc.raw_logs
    )

# Blocked IPs endpoints
@app.get("/api/blocked-ips", response_model=List[BlockedIPResponse])
async def get_blocked_ips(current_user: str = Depends(get_current_user)):
    if not light_soc or not light_soc.blocker:
        return []
    
    blocked = light_soc.blocker.get_all_blocks()
    return [
        BlockedIPResponse(
            ip=b.ip,
            reason=b.reason,
            blocked_at=b.blocked_at.isoformat(),
            expires_at=b.expires_at.isoformat() if b.expires_at else None,
            active=b.active,
            rule_handle=b.rule_handle
        )
        for b in blocked
    ]

@app.post("/api/blocked-ips")
async def block_ip(request: BlockIPRequest, current_user: str = Depends(get_current_user)):
    if not light_soc or not light_soc.blocker:
        raise HTTPException(status_code=503, detail="Blocker not available")
    
    success = light_soc.blocker.block_ip(request.ip, request.reason, request.duration)
    if not success:
        raise HTTPException(status_code=400, detail="Failed to block IP (may be whitelisted)")
    
    # Broadcast update
    await manager.broadcast({"type": "blocked_ip_added", "ip": request.ip})
    
    return {"success": True, "message": f"Blocked {request.ip}"}

@app.delete("/api/blocked-ips/{ip}")
async def unblock_ip(ip: str, current_user: str = Depends(get_current_user)):
    if not light_soc or not light_soc.blocker:
        raise HTTPException(status_code=503, detail="Blocker not available")
    
    success = light_soc.blocker.unblock_ip(ip)
    if not success:
        raise HTTPException(status_code=404, detail="IP not found or already unblocked")
    
    await manager.broadcast({"type": "blocked_ip_removed", "ip": ip})
    
    return {"success": True, "message": f"Unblocked {ip}"}

# Agent endpoints
@app.get("/api/agents", response_model=List[AgentResponse])
async def get_agents(current_user: str = Depends(get_current_user)):
    if not light_soc:
        raise HTTPException(status_code=503, detail="Light-SOC not initialized")
    
    try:
        agent_manager = get_agent_manager()
        agents = agent_manager.get_agents()
        return [
            AgentResponse(
                agent_id=a.agent_id,
                name=a.name,
                ip=a.ip,
                platform=a.platform,
                version=a.version,
                status=a.status.value,
                registered_at=a.registered_at.isoformat(),
                last_heartbeat=a.last_heartbeat.isoformat() if a.last_heartbeat else None,
                tags=a.tags
            )
            for a in agents
        ]
    except Exception as e:
        logger.error(f"Error getting agents: {e}")
        return []

@app.post("/api/agents/{agent_id}/command")
async def send_agent_command(
    agent_id: str,
    command: str,
    args: Dict[str, Any] = {},
    current_user: str = Depends(get_current_user)
):
    try:
        agent_manager = get_agent_manager()
        success = agent_manager.send_command(agent_id, command, args)
        return {"success": success}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Scan endpoints
@app.get("/api/scans/status", response_model=ScanStatusResponse)
async def get_scan_status(current_user: str = Depends(get_current_user)):
    if not light_soc:
        raise HTTPException(status_code=503, detail="Light-SOC not initialized")
    
    fim_status = {}
    vuln_status = {}
    sca_status = {}
    ti_status = {}
    
    if light_soc.fim_monitor:
        first_baseline = None
        if light_soc.fim_monitor.baselines:
            first_key = list(light_soc.fim_monitor.baselines.keys())[0]
            first_baseline = light_soc.fim_monitor.baselines[first_key]
        fim_status = {
            "enabled": True,
            "baseline_files": len(light_soc.fim_monitor.baselines),
            "alerts": len(light_soc.fim_monitor.alerts),
            "last_scan": first_baseline.last_checked.isoformat() if first_baseline and first_baseline.last_checked else None
        }
    
    if light_soc.vuln_detector:
        last_scan = light_soc.vuln_detector.get_last_scan()
        if last_scan:
            vuln_status = {
                "enabled": True,
                "total_packages": last_scan.total_packages,
                "vulnerable_packages": last_scan.vulnerable_packages,
                "total_cves": last_scan.total_cves,
                "critical": last_scan.critical_count,
                "high": last_scan.high_count,
                "medium": last_scan.medium_count,
                "low": last_scan.low_count,
                "last_scan": last_scan.timestamp.isoformat()
            }
    
    if light_soc.sca_scanner:
        last_scan = light_soc.sca_scanner.get_last_scan()
        if last_scan:
            sca_status = {
                "enabled": True,
                "total_checks": last_scan.total_checks,
                "passed": last_scan.passed,
                "failed": last_scan.failed,
                "critical_failures": last_scan.critical_failures,
                "high_failures": last_scan.high_failures,
                "last_scan": last_scan.timestamp.isoformat()
            }
    
    if light_soc.threat_intel:
        ti_status = {
            "enabled": True,
            "indicators": light_soc.threat_intel.stats.get("total_indicators", 0),
            "feeds_active": light_soc.threat_intel.stats.get("feeds_active", 0),
            "last_update": light_soc.threat_intel.stats.get("last_update")
        }
    
    return ScanStatusResponse(
        fim=fim_status,
        vulnerability=vuln_status,
        sca=sca_status,
        threat_intel=ti_status
    )

@app.post("/api/scans/fim")
async def run_fim_scan(current_user: str = Depends(get_current_user)):
    if not light_soc or not light_soc.fim_monitor:
        raise HTTPException(status_code=503, detail="FIM not enabled")
    
    light_soc.fim_monitor.scan()
    alerts = light_soc.fim_monitor.get_alerts()
    return {"success": True, "alerts": len(alerts)}

@app.post("/api/scans/vulnerability")
async def run_vuln_scan(current_user: str = Depends(get_current_user)):
    if not light_soc or not light_soc.vuln_detector:
        raise HTTPException(status_code=503, detail="Vulnerability detection not enabled")
    
    result = light_soc.vuln_detector.scan()
    return {
        "success": True,
        "total_packages": result.total_packages,
        "vulnerable_packages": result.vulnerable_packages,
        "total_cves": result.total_cves,
        "critical": result.critical_count,
        "high": result.high_count,
        "medium": result.medium_count,
        "low": result.low_count
    }

@app.post("/api/scans/sca")
async def run_sca_scan(current_user: str = Depends(get_current_user)):
    if not light_soc or not light_soc.sca_scanner:
        raise HTTPException(status_code=503, detail="SCA not enabled")
    
    result = light_soc.sca_scanner.scan()
    return {
        "success": True,
        "total_checks": result.total_checks,
        "passed": result.passed,
        "failed": result.failed,
        "critical_failures": result.critical_failures,
        "high_failures": result.high_failures
    }

@app.post("/api/scans/threat-intel")
async def run_threat_intel_update(current_user: str = Depends(get_current_user)):
    if not light_soc or not light_soc.threat_intel:
        raise HTTPException(status_code=503, detail="Threat intelligence not enabled")
    
    light_soc.threat_intel.update_all_feeds()
    feeds = light_soc.threat_intel.get_feed_status()
    return {
        "success": True,
        "feeds_updated": len(feeds),
        "total_indicators": light_soc.threat_intel.stats.get("total_indicators", 0)
    }

# Threat Intel endpoints
@app.get("/api/threat-intel/feeds")
async def get_threat_intel_feeds(current_user: str = Depends(get_current_user)):
    if not light_soc or not light_soc.threat_intel:
        raise HTTPException(status_code=503, detail="Threat intelligence not enabled")
    
    return light_soc.threat_intel.get_feed_status()

@app.get("/api/threat-intel/check-ip/{ip}")
async def check_threat_intel_ip(ip: str, current_user: str = Depends(get_current_user)):
    if not light_soc or not light_soc.threat_intel:
        raise HTTPException(status_code=503, detail="Threat intelligence not enabled")
    
    matches = light_soc.threat_intel.check_ip(ip)
    return {
        "ip": ip,
        "matches": len(matches),
        "indicators": [
            {
                "type": m.indicator_type,
                "value": m.value,
                "confidence": m.confidence,
                "severity": m.severity,
                "source": m.source,
                "description": m.description
            }
            for m in matches
        ]
    }

@app.get("/api/threat-intel/check-domain/{domain}")
async def check_threat_intel_domain(domain: str, current_user: str = Depends(get_current_user)):
    if not light_soc or not light_soc.threat_intel:
        raise HTTPException(status_code=503, detail="Threat intelligence not enabled")
    
    matches = light_soc.threat_intel.check_domain(domain)
    return {
        "domain": domain,
        "matches": len(matches),
        "indicators": [
            {
                "type": m.indicator_type,
                "value": m.value,
                "confidence": m.confidence,
                "severity": m.severity,
                "source": m.source,
                "description": m.description
            }
            for m in matches
        ]
    }

# System status
@app.get("/api/system/status", response_model=SystemStatusResponse)
async def get_system_status(current_user: str = Depends(get_current_user)):
    if not light_soc:
        raise HTTPException(status_code=503, detail="Light-SOC not initialized")
    
    return SystemStatusResponse(**light_soc.get_status())

# WebSocket for real-time updates
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        # Send initial status
        if light_soc:
            await websocket.send_json({
                "type": "initial_status",
                "data": light_soc.get_status(),
                "timestamp": datetime.utcnow().isoformat()
            })
        
        while True:
            # Keep connection alive
            data = await websocket.receive_text()
            # Echo back for ping/pong
            await websocket.send_json({"type": "pong", "timestamp": datetime.utcnow().isoformat()})
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket)

# Serve frontend
@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    index_path = static_dir / "index.html"
    if index_path.exists():
        return FileResponse(index_path)
    return HTMLResponse("<h1>Light-SOC Dashboard</h1><p>Frontend not built yet. Visit <a href='/docs'>/docs</a> for API.</p>")

# Catch-all for SPA routing
@app.get("/{full_path:path}")
async def serve_spa(full_path: str):
    index_path = static_dir / "index.html"
    if index_path.exists():
        return FileResponse(index_path)
    raise HTTPException(status_code=404, detail="Not found")

if __name__ == "__main__":
    import uvicorn
    import os
    port = int(os.environ.get("DASHBOARD_PORT", "8080"))
    uvicorn.run(app, host="0.0.0.0", port=port)