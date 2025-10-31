from collections import defaultdict, deque
from datetime import datetime, timedelta
import hashlib


class ThreatAnalyzer:
    """Correlate and analyze threats from multiple detection sources"""
    
    def __init__(self, time_window: int = 300):
        self.time_window = time_window  # seconds
        self.threat_cache = defaultdict(deque)
        self.ip_reputation = defaultdict(int)
        self.connection_tracker = defaultdict(int)
        
    def analyze_packet(self, packet: Dict, anomaly_result: Tuple[bool, float],
                      signature_matches: List[Dict]) -> Optional[Dict]:
        """
        Comprehensive threat analysis combining ML and signature results
        """
        threat = None
        threat_score = 0.0
        threat_indicators = []
        
        src_ip = packet.get('src_ip', 'unknown')
        
        # ML Anomaly Detection Score
        is_anomaly, anomaly_score = anomaly_result
        if is_anomaly:
            threat_score += anomaly_score * 50
            threat_indicators.append("ML anomaly detected")
        
        # Signature Matches
        if signature_matches:
            max_severity = max([
                {'low': 25, 'medium': 50, 'high': 75, 'critical': 100}[m['severity']]
                for m in signature_matches
            ])
            threat_score += max_severity
            threat_indicators.extend([m['rule_name'] for m in signature_matches])
        
        # IP Reputation Score
        self.ip_reputation[src_ip] += 1
        if self.ip_reputation[src_ip] > 10:
            threat_score += 20
            threat_indicators.append("High activity from source IP")
        
        # Connection Rate Analysis
        conn_key = f"{src_ip}:{packet.get('dst_port', 0)}"
        self.connection_tracker[conn_key] += 1
        if self.connection_tracker[conn_key] > 100:
            threat_score += 30
            threat_indicators.append("High connection rate")
        
        # Port Scan Detection
        if self._detect_port_scan(src_ip):
            threat_score += 40
            threat_indicators.append("Port scanning detected")
        
        # Generate threat if score exceeds threshold
        if threat_score >= 50:
            threat = {
                'id': self._generate_threat_id(packet),
                'timestamp': datetime.now().isoformat(),
                'source_ip': src_ip,
                'destination_ip': packet.get('dst_ip', 'unknown'),
                'threat_score': min(threat_score, 100),
                'severity': self._calculate_severity(threat_score),
                'indicators': threat_indicators,
                'signature_matches': signature_matches,
                'anomaly_score': anomaly_score,
                'packet_details': packet
            }
            
            # Cache threat for correlation
            self.threat_cache[src_ip].append({
                'time': datetime.now(),
                'threat': threat
            })
        
        return threat
    
    def _detect_port_scan(self, src_ip: str) -> bool:
        """Detect port scanning behavior"""
        recent_threats = self.threat_cache.get(src_ip, [])
        if len(recent_threats) < 5:
            return False
        
        # Check if multiple different ports accessed in short time
        recent_ports = set()
        cutoff_time = datetime.now() - timedelta(seconds=60)
        
        for entry in recent_threats:
            if entry['time'] > cutoff_time:
                port = entry['threat']['packet_details'].get('dst_port')
                if port:
                    recent_ports.add(port)
        
        return len(recent_ports) >= 5
    
    def _calculate_severity(self, score: float) -> str:
        """Calculate threat severity level"""
        if score >= 90:
            return "critical"
        elif score >= 70:
            return "high"
        elif score >= 50:
            return "medium"
        else:
            return "low"
    
    def _generate_threat_id(self, packet: Dict) -> str:
        """Generate unique threat ID"""
        data = f"{packet.get('src_ip')}{packet.get('dst_ip')}{datetime.now()}"
        return hashlib.md5(data.encode()).hexdigest()[:16]


# ============================================
# 5. REST API SERVER
# ============================================
# File: api/server.py

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from typing import List, Optional
import uvicorn


app = FastAPI(title="Sentinel AI Threat Detector API", version="1.0.0")

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()


# Pydantic Models
class ThreatResponse(BaseModel):
    id: str
    timestamp: str
    source_ip: str
    destination_ip: str
    threat_score: float
    severity: str
    indicators: List[str]
    
class PacketStats(BaseModel):
    total_packets: int
    threats_detected: int
    anomalies_detected: int
    signature_matches: int
    
class SignatureRuleRequest(BaseModel):
    name: str = Field(..., min_length=3, max_length=100)
    pattern: str = Field(..., min_length=1)
    severity: str = Field(..., regex="^(low|medium|high|critical)$")
    description: str
    enabled: bool = True


# Global instances (in production, use dependency injection)
packet_capture = PacketCapture()
anomaly_detector = AnomalyDetector()
signature_ids = SignatureIDS()
threat_analyzer = ThreatAnalyzer()
threat_history = []


@app.get("/")
async def root():
    return {
        "service": "Sentinel AI Threat Detector",
        "version": "1.0.0",
        "status": "operational"
    }


@app.post("/api/capture/start")
async def start_capture(interface: str = "eth0"):
    """Start network packet capture"""
    try:
        import threading
        capture_thread = threading.Thread(
            target=packet_capture.start_capture,
            daemon=True
        )
        capture_thread.start()
        return {"status": "started", "interface": interface}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/capture/stop")
async def stop_capture():
    """Stop network packet capture"""
    packet_capture.stop_capture()
    return {"status": "stopped", "packets_captured": packet_capture.packet_count}


@app.get("/api/threats", response_model=List[ThreatResponse])
async def get_threats(
    severity: Optional[str] = None,
    limit: int = 100
):
    """Retrieve detected threats"""
    filtered_threats = threat_history
    
    if severity:
        filtered_threats = [
            t for t in filtered_threats
            if t['severity'] == severity
        ]
    
    return filtered_threats[:limit]


@app.get("/api/stats", response_model=PacketStats)
async def get_stats():
    """Get real-time statistics"""
    return {
        "total_packets": packet_capture.packet_count,
        "threats_detected": len(threat_history),
        "anomalies_detected": sum(1 for t in threat_history if t.get('anomaly_score', 0) > 0.5),
        "signature_matches": sum(len(t.get('signature_matches', [])) for t in threat_history)
    }


@app.post("/api/rules")
async def add_signature_rule(rule: SignatureRuleRequest):
    """Add custom signature rule"""
    new_rule = SignatureRule(
        id=f"CUSTOM_{len(signature_ids.rules) + 1}",
        name=rule.name,
        pattern=rule.pattern,
        severity=rule.severity,
        description=rule.description,
        enabled=rule.enabled
    )
    signature_ids.add_rule(new_rule)
    return {"status": "created", "rule_id": new_rule.id}


@app.get("/api/rules")
async def get_signature_rules():
    """Get all signature rules"""
    return [
        {
            "id": rule.id,
            "name": rule.name,
            "severity": rule.severity,
            "enabled": rule.enabled
        }
        for rule in signature_ids.rules
    ]


@app.post("/api/model/train")
async def train_model(packets_count: int = 1000):
    """Train anomaly detection model"""
    # In production, load from database or file
    training_data = []  # Placeholder
    anomaly_detector.train(training_data)
    return {"status": "trained", "packets_used": len(training_data)}
