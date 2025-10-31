# Create comprehensive README
cat > README.md << 'EOF'
# 🛡️ Sentinel AI Threat Detector

AI-enhanced cybersecurity threat detection system with real-time network monitoring, ML-based anomaly detection, and signature-based IDS.

![Demo](docs/demo.gif)

## ✨ Features

- 🔍 **Real-time Packet Capture** - Live network traffic analysis
- 🤖 **ML Anomaly Detection** - Isolation Forest algorithm
- 🛡️ **Signature-based IDS** - Pattern matching with custom rules
- 📊 **Live Dashboard** - Real-time charts and statistics
- 🔔 **Alert Notifications** - Instant threat alerts
- 📥 **Export Data** - CSV and JSON export
- 🎯 **Severity Filtering** - Filter by threat level
- 🐳 **Docker Support** - Easy deployment

## 🏗️ Architecture
```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│   Network   │────▶│   Packet     │────▶│     ML      │
│   Traffic   │     │   Capture    │     │  Detection  │
└─────────────┘     └──────────────┘     └─────────────┘
                            │                     │
                            ▼                     ▼
                    ┌──────────────┐     ┌─────────────┐
                    │  Signature   │────▶│   Threat    │
                    │     IDS      │     │  Analyzer   │
                    └──────────────┘     └─────────────┘
                                                │
                                                ▼
                                        ┌─────────────┐
                                        │  Dashboard  │
                                        │   + API     │
                                        └─────────────┘
```

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Node.js 16+
- PostgreSQL 12+
- Linux system (for packet capture)

### Installation

#### 1. Clone Repository
```bash
git clone https://github.com/rhdmsrb/sentinel-ai-threat-detector.git
cd sentinel-ai-threat-detector
```

#### 2. Setup Backend
```bash
cd backend
sudo ./setup.sh
```

#### 3. Setup Frontend
```bash
cd frontend
npm install
```

#### 4. Start Services

**Terminal 1 - Backend:**
```bash
cd backend
sudo ./run.sh
```

**Terminal 2 - Frontend:**
```bash
cd frontend
npm run dev
```

#### 5. Access Dashboard
Open http://localhost:3000

## 🐳 Docker Deployment
```bash
cd backend
docker-compose up -d
```

## 📖 Usage

### Start Packet Capture
```bash
curl -X POST "http://localhost:8000/api/capture/start" \
  -H "Content-Type: application/json" \
  -d '{"interface": "eth0"}'
```

### View Threats
```bash
curl "http://localhost:8000/api/threats"
```

### Get Statistics
```bash
curl "http://localhost:8000/api/stats"
```

### Add Custom Rule
```bash
curl -X POST "http://localhost:8000/api/rules" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Custom Detection",
    "pattern": "suspicious_pattern",
    "severity": "high",
    "description": "Custom rule description"
  }'
```

## 🎯 API Documentation

Once running, visit: http://localhost:8000/docs

## 🔧 Configuration

Edit `backend/.env`:
```env
DATABASE_URL=postgresql://sentinel:password@localhost:5432/sentinel_threats
CAPTURE_INTERFACE=eth0
ALERT_THRESHOLD=70
```

## 📊 Dashboard Features

- Real-time packet statistics
- Threat severity distribution
- Timeline charts
- Alert notifications
- Export to CSV/JSON
- Severity filtering

## 🛠️ Tech Stack

### Frontend
- React 18
- TypeScript
- Recharts
- Tailwind CSS
- Vite

### Backend
- Python 3.11
- FastAPI
- Scapy
- scikit-learn
- PostgreSQL
- Docker

## 📸 Screenshots

### Dashboard
![Dashboard](docs/dashboard.png)

### Threat Detection
![Threats](docs/threats.png)

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open Pull Request

## 📝 License

MIT License - see [LICENSE](LICENSE) file

## 👨‍💻 Author

**rhdmsrb**
- GitHub: [@rhdmsrb](https://github.com/rhdmsrb)

## 🙏 Acknowledgments

- Scapy for packet capture
- scikit-learn for ML algorithms
- FastAPI for API framework
- Recharts for visualizations

## ⚠️ Security Note

This tool requires root privileges for packet capture. Use responsibly and only on networks you have permission to monitor.

## 📞 Support

For issues and questions, please open an issue on GitHub.

---

Made with ❤️ for cybersecurity
EOF
