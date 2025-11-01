#!/bin/bash
source venv/bin/activate
sudo -E env PATH=$PATH python -m uvicorn api.server:app --host 0.0.0.0 --port 8000 --reload
