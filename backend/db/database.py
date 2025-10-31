# File: db/database.py

import asyncpg
import json
from typing import List, Dict, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class Database:
    """PostgreSQL database connection and operations"""
    
    def __init__(self, database_url: str):
        self.database_url = database_url
        self.pool = None
    
    async def connect(self):
        """Create database connection pool"""
        try:
            self.pool = await asyncpg.create_pool(
                self.database_url,
                min_size=5,
                max_size=20
            )
            logger.info("Database connection pool created")
        except Exception as e:
            logger.error(f"Failed to connect to database: {e}")
            raise
    
    async def disconnect(self):
        """Close database connection pool"""
        if self.pool:
            await self.pool.close()
            logger.info("Database connection pool closed")
    
    async def save_threat(self, threat: Dict):
        """Save detected threat to database"""
        async with self.pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO threats (
                    id, timestamp, source_ip, destination_ip, 
                    threat_score, severity, indicators, 
                    anomaly_score, packet_details
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                ON CONFLICT (id) DO UPDATE SET
                    threat_score = EXCLUDED.threat_score,
                    updated_at = CURRENT_TIMESTAMP
            """,
                threat['id'],
                datetime.fromisoformat(threat['timestamp']),
                threat['source_ip'],
                threat['destination_ip'],
                threat['threat_score'],
                threat['severity'],
                threat['indicators'],
                threat.get('anomaly_score', 0.0),
                json.dumps(threat.get('packet_details', {}))
            )
    
    async def get_threats(self, limit: int = 100, severity: Optional[str] = None) -> List[Dict]:
        """Retrieve threats from database"""
        async with self.pool.acquire() as conn:
            query = "SELECT * FROM threats"
            params = []
            
            if severity:
                query += " WHERE severity = $1"
                params.append(severity)
            
            query += " ORDER BY timestamp DESC LIMIT $" + str(len(params) + 1)
            params.append(limit)
            
            rows = await conn.fetch(query, *params)
            return [dict(row) for row in rows]
    
    async def get_statistics(self) -> Dict:
        """Get real-time statistics"""
        async with self.pool.acquire() as conn:
            stats = await conn.fetchrow("""
                SELECT 
                    COUNT(*) as total_threats,
                    COUNT(*) FILTER (WHERE anomaly_score > 0.5) as anomalies,
                    SUM(array_length(indicators, 1)) as signature_matches
                FROM threats
                WHERE timestamp > NOW() - INTERVAL '1 hour'
            """)
            
            # Get total packets from latest session
            session = await conn.fetchrow("""
                SELECT packets_captured 
                FROM capture_sessions 
                WHERE status = 'active'
                ORDER BY started_at DESC 
                LIMIT 1
            """)
            
            return {
                'total_packets': session['packets_captured'] if session else 0,
                'threats_detected': stats['total_threats'] or 0,
                'anomalies_detected': stats['anomalies'] or 0,
                'signature_matches': stats['signature_matches'] or 0
            }
    
    async def create_capture_session(self, interface: str) -> int:
        """Create new capture session"""
        async with self.pool.acquire() as conn:
            session_id = await conn.fetchval("""
                INSERT INTO capture_sessions (interface, started_at)
                VALUES ($1, NOW())
                RETURNING id
            """, interface)
            return session_id
    
    async def update_capture_session(self, session_id: int, packets_captured: int):
        """Update capture session packet count"""
        async with self.pool.acquire() as conn:
            await conn.execute("""
                UPDATE capture_sessions 
                SET packets_captured = $1
                WHERE id = $2
            """, packets_captured, session_id)
    
    async def close_capture_session(self, session_id: int):
        """Close capture session"""
        async with self.pool.acquire() as conn:
            await conn.execute("""
                UPDATE capture_sessions 
                SET stopped_at = NOW(), status = 'stopped'
                WHERE id = $1
            """, session_id)
    
    async def get_signature_rules(self) -> List[Dict]:
        """Get all signature rules"""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT * FROM signature_rules 
                WHERE enabled = TRUE
                ORDER BY created_at DESC
            """)
            return [dict(row) for row in rows]
    
    async def add_signature_rule(self, rule: Dict):
        """Add new signature rule"""
        async with self.pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO signature_rules (id, name, pattern, severity, description)
                VALUES ($1, $2, $3, $4, $5)
            """,
                rule['id'],
                rule['name'],
                rule['pattern'],
                rule['severity'],
                rule['description']
            )
