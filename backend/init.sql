cat > backend/init.sql << 'EOF'
-- Database initialization script
CREATE TABLE IF NOT EXISTS threats (
    id VARCHAR(50) PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    destination_ip VARCHAR(45) NOT NULL,
    threat_score FLOAT NOT NULL,
    severity VARCHAR(20) NOT NULL,
    indicators TEXT[],
    anomaly_score FLOAT,
    packet_details JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS signature_rules (
    id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    pattern TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL,
    description TEXT,
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_threats_timestamp ON threats(timestamp DESC);
CREATE INDEX idx_threats_severity ON threats(severity);
EOF