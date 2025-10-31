# File: api/server.py

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Optional
import uvicorn
import asyncio
import os
import logging

from db.database import Database
from core.packet_capture import PacketCapture
from ml.anomaly_detector import AnomalyDetector
from core.signature_ids import SignatureIDS
from core.threat_analyzer import ThreatAnalyzer

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(title="Sentinel AI Threat Detector", version="2.0.0")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global instances
DATABASE_URL = os.getenv(
    'DATABASE_URL',
    'postgresql://sentinel:sentinel_secure_pass@localhost:5432/sentinel_threats'
)

db = Database(DATABASE_URL)
packet_capture = None
anomaly_detector = AnomalyDetector()
signature_ids = SignatureIDS()
threat_analyzer = ThreatAnalyzer()
processing_active = False

# Pydantic models
class ThreatResponse(BaseModel):
    id: str
    timestamp: str
    source_ip: str
    destination_ip: str
    threat_score: float
    severity: str
    indicators: List[str]

class CaptureRequest(BaseModel):
    interface: str = Field(default="eth0", description="Network interface to capture")

class SignatureRuleRequest(BaseModel):
    name: str
    pattern: str
    severity: str
    description: str

@app.on_event("startup")
async def startup():
    """Initialize database connection"""
    await db.connect()
    logger.info("Application started")

@app.on_event("shutdown")
async def shutdown():
    """Cleanup on shutdown"""
    if packet_capture and packet_capture.is_running:
        packet_capture.stop()
    await db.disconnect()
    logger.info("Application shutdown")

async def process_packet(packet: Dict):
    """Process captured packet through detection pipeline"""
    try:
        # ML Anomaly Detection
        anomaly_result = anomaly_detector.detect_anomaly(packet)
        
        # Signature Detection
        signature_matches = signature_ids.check_packet(packet)
        
        # Threat Analysis
        threat = threat_analyzer.analyze_packet(
            packet,
            anomaly_result,
            signature_matches
        )
        
        # Save threat to database
        if threat:
            await db.save_threat(threat)
            logger.warning(f"THREAT: {threat['severity']} from {threat['source_ip']}")
    
    except Exception as e:
        logger.error(f"Error processing packet: {e}")

def packet_callback(packet: Dict):
    """Callback for captured packets"""
    # Create new event loop for async operations in thread
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(process_packet(packet))
    except Exception as e:
        logger.error(f"Callback error: {e}")

@app.post("/api/capture/start")
async def start_capture(request: CaptureRequest):
    """Start network packet capture"""
    global packet_capture, processing_active
    
    try:
        if packet_capture and packet_capture.is_running:
            raise HTTPException(status_code=400, detail="Capture already running")
        
        # Create new capture instance
        packet_capture = PacketCapture(interface=request.interface)
        
        # Create database session
        session_id = await db.create_capture_session(request.interface)
        packet_capture.session_id = session_id
        
        # Start capture
        success = packet_capture.start(packet_callback)
        
        if not success:
            raise HTTPException(status_code=500, detail="Failed to start capture")
        
        processing_active = True
        
        logger.info(f"Capture started on {request.interface}")
        return {
            "status": "started",
            "interface": request.interface,
            "session_id": session_id
        }
    
    except Exception as e:
        logger.error(f"Error starting capture: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/capture/stop")
async def stop_capture():
    """Stop network packet capture"""
    global packet_capture, processing_active
    
    try:
        if not packet_capture or not packet_capture.is_running:
            raise HTTPException(status_code=400, detail="Capture not running")
        
        # Stop capture
        packet_capture.stop()
        processing_active = False
        
        # Update database session
        if packet_capture.session_id:
            await db.close_capture_session(packet_capture.session_id)
        
        stats = packet_capture.get_stats()
        
        logger.info("Capture stopped")
        return {
            "status": "stopped",
            "packets_captured": stats['packet_count']
        }
    
    except Exception as e:
        logger.error(f"Error stopping capture: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/threats")
async def get_threats(severity: Optional[str] = None, limit: int = 100):
    """Get detected threats from database"""
    try:
        threats = await db.get_threats(limit=limit, severity=severity)
        return threats
    except Exception as e:
        logger.error(f"Error fetching threats: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/stats")
async def get_stats():
    """Get real-time statistics"""
    try:
        stats = await db.get_statistics()
        
        # Add current capture stats if running
        if packet_capture and packet_capture.is_running:
            capture_stats = packet_capture.get_stats()
            stats['total_packets'] = capture_stats['packet_count']
        
        return stats
    except Exception as e:
        logger.error(f"Error fetching stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/capture/status")
async def get_capture_status():
    """Get current capture status"""
    if packet_capture:
        stats = packet_capture.get_stats()
        return stats
    return {"is_running": False, "packet_count": 0}

@app.post("/api/rules")
async def add_signature_rule(rule: SignatureRuleRequest):
    """Add custom signature rule"""
    try:
        new_rule = {
            'id': f"CUSTOM_{len(signature_ids.rules) + 1}",
            'name': rule.name,
            'pattern': rule.pattern,
            'severity': rule.severity,
            'description': rule.description
        }
        
        await db.add_signature_rule(new_rule)
        signature_ids.load_rules_from_db = True  # Reload rules
        
        return {"status": "created", "rule_id": new_rule['id']}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/rules")
async def get_signature_rules():
    """Get all signature rules"""
    try:
        rules = await db.get_signature_rules()
        return rules
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
