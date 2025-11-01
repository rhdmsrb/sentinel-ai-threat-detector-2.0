#!/bin/bash
echo "Setting up Sentinel AI..."
sudo apt-get update
sudo apt-get install -y python3-pip python3-venv libpcap-dev postgresql
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
echo "Setup complete!"
