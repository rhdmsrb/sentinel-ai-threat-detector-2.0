cat > backend/setup.sh << 'EOF'
#!/bin/bash
echo "Setting up Sentinel AI Threat Detector..."

# Install system dependencies
sudo apt-get update
sudo apt-get install -y python3-pip libpcap-dev postgresql

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python packages
pip install -r requirements.txt

# Setup database
sudo -u postgres createdb sentinel_threats
sudo -u postgres createuser sentinel
sudo -u postgres psql -c "ALTER USER sentinel WITH PASSWORD 'sentinel_secure_pass';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE sentinel_threats TO sentinel;"

# Initialize schema
PGPASSWORD=sentinel_secure_pass psql -U sentinel -d sentinel_threats -f init.sql

echo "Setup complete!"
EOF

chmod +x backend/setup.sh
