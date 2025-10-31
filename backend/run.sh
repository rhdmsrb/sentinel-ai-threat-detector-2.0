cat > backend/run.sh << 'EOF'
#!/bin/bash
source venv/bin/activate
sudo python -m uvicorn api.server:app --host 0.0.0.0 --port 8000 --reload
EOF

chmod +x backend/run.sh
