# 🛡️ Traffic Intelligence — AI-Powered Network Intrusion Detection System

[![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)](https://python.org)
[![Node.js](https://img.shields.io/badge/Node.js-18+-green?logo=nodedotjs)](https://nodejs.org)
[![React](https://img.shields.io/badge/React-19-61DAFB?logo=react)](https://reactjs.org)
[![MongoDB](https://img.shields.io/badge/MongoDB-Atlas-green?logo=mongodb)](https://mongodb.com)
[![ML Model](https://img.shields.io/badge/Model-Isolation%20Forest-orange)](https://scikit-learn.org)
[![Dataset](https://img.shields.io/badge/Dataset-NSL--KDD-purple)](https://www.unb.ca/cic/datasets/nsl.html)

A **real-time network traffic monitoring and intrusion detection system** that combines **Deep Packet Inspection (DPI)**, **unsupervised Machine Learning** (Isolation Forest trained on the NSL-KDD benchmark dataset), and a **live React dashboard** to identify and visualize suspicious network behavior.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Traffic Intelligence                         │
│                                                                  │
│  ┌──────────────────┐     HTTP POST      ┌──────────────────┐   │
│  │  Python Analyzer │ ─────────────────► │  Node.js Backend │   │
│  │                  │                    │  (Express + REST) │   │
│  │  • Scapy Sniffer │                    │                  │   │
│  │  • DPI (L7 data) │                    │  • Flow Routes   │   │
│  │  • Isolation     │                    │  • Alert Routes  │   │
│  │    Forest (ML)   │                    │  • MongoDB Store │   │
│  │  • Geo-IP Lookup │                    └────────┬─────────┘   │
│  │  • Blacklist     │                             │ HTTP GET     │
│  │    Matching      │                    ┌────────▼─────────┐   │
│  └──────────────────┘                    │   React Frontend  │   │
│                                          │                   │   │
│                                          │  • KPI Cards      │   │
│                                          │  • Live Charts    │   │
│                                          │  • Threat Table   │   │
│                                          │  • Toast Alerts   │   │
│                                          │  • CSV Export     │   │
│                                          │  • Terminal Feed  │   │
│                                          └───────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 📡 **Real-Time Packet Capture** | Live network sniffing via Scapy — no external tools required |
| 🧠 **ML Anomaly Detection** | Isolation Forest trained on the NSL-KDD intrusion benchmark dataset |
| 🔍 **Deep Packet Inspection** | Extracts DNS queries, HTTP Host headers, and TLS SNI from Layer 7 |
| 🌍 **Geo-IP Intelligence** | Resolves IPs to countries with flag emojis in real time |
| 🚨 **Live Toast Alerts** | Browser popup notifications for Critical and High severity threats |
| 📊 **Interactive Dashboard** | Donut chart, area chart, health bars, and KPI cards |
| 🔐 **Domain Blacklisting** | Cross-references domains against a threat intelligence blacklist |
| ⬇️ **CSV Export** | Download full flow log as a timestamped CSV report |
| 💻 **Live Terminal Feed** | Scrolling packet log with colour-coded INFO / WARN / ALERT tags |

---

## 🚀 Setup & Running

### Prerequisites
- Python 3.10+
- Node.js 18+
- MongoDB (local or Atlas)
- **Windows:** Run analyzer as Administrator (Scapy requires raw socket access)

### 1. Clone & Install

```bash
git clone https://github.com/shreeyanshi25/Network-Inspection.git
cd Network-Inspection
```

### 2. Backend

```bash
cd backend
npm install
# Create a .env file with your MongoDB URI:
# MONGO_URI=mongodb://localhost:27017/traffic_intel
node server.js
```

### 3. Frontend

```bash
cd backend/frontend
npm install
npm start
# Opens at http://localhost:3000
```

### 4. Python Analyzer (Run as Administrator)

```bash
cd analyzer
python -m venv venv
.\venv\Scripts\activate        # Windows
pip install -r requirements.txt

# (Optional) Retrain the ML model on NSL-KDD:
python train_model.py

# Start live monitoring:
python packet_capture.py
```

### Python Requirements

```
scapy
scikit-learn
joblib
numpy
pandas
requests
```

---

## 🧠 Machine Learning Details

| Property | Value |
|----------|-------|
| **Algorithm** | Isolation Forest (unsupervised anomaly detection) |
| **Training Dataset** | [NSL-KDD](https://www.unb.ca/cic/datasets/nsl.html) — 67,343 real network flow records |
| **Training Strategy** | Trained on **normal flows only** — anomalies are flagged as statistical outliers |
| **Features Used** | `packet_count`, `total_bytes`, `avg_packet_size`, `duration`, `byte_rate`, `packet_rate` |
| **Contamination** | 5% (expected anomaly rate) |
| **n_estimators** | 300 trees |

---

## 📁 Project Structure

```
Traffic-Intelligence/
├── analyzer/
│   ├── packet_capture.py    # Main sniffer + ML inference + Geo-IP
│   ├── train_model.py       # NSL-KDD download + Isolation Forest training
│   ├── blacklist.py         # Domain threat intelligence
│   ├── anomaly_model.pkl    # Trained Isolation Forest model
│   └── scaler.pkl           # StandardScaler for feature normalization
│
├── backend/
│   ├── server.js            # Express app entry point
│   ├── config/db.js         # MongoDB connection
│   ├── models/
│   │   ├── Flow.js          # Flow schema (with Geo-IP fields)
│   │   └── Alert.js         # Alert schema
│   ├── routes/
│   │   └── flowRoutes.js    # GET /flows, POST /flows, GET /alerts
│   └── frontend/            # React dashboard
│       └── src/
│           ├── App.js       # Main dashboard component
│           ├── App.css      # Component styles (light theme)
│           └── index.css    # Global styles & CSS variables
│
└── README.md
```

---

## 📄 License

MIT License — free to use for educational and portfolio purposes.

---

*Built as a final-year Computer Science project demonstrating real-world integration of cybersecurity, machine learning, and full-stack web development.*
