🚀 AI Network Threat Detection Platform

An AI-powered Real-Time Network Threat Detection & Deep Packet Inspection (DPI) Platform that monitors live traffic, detects anomalies using Machine Learning, performs application-layer inspection (DNS, HTTP, TLS), and generates automated security alerts with a SOC-style dashboard.
This is not just a project — it is a mini Security Intelligence Platform.

📌 Project Overview

This system:
Captures live network packets using Scapy
Aggregates traffic into flows
Extracts application-layer metadata (DNS, HTTP Host, TLS SNI)
Detects anomalous behavior using ML (Isolation Forest)
Assigns threat scores & levels
Stores data in MongoDB
Generates alerts for High/Critical threats
Displays real-time analytics in a React dashboard

🏗 Architecture
            ┌────────────────────┐
            │   Network Traffic  │
            └─────────┬──────────┘
                      │
                Scapy Packet Capture
                      │
              Feature Engineering
                      │
            ML Anomaly Detection
                      │
          Threat Score + Threat Level
                      │
          ┌───────────┴───────────┐
          │                       │
     MongoDB Storage          Alert Engine
          │                       │
          └───────────┬───────────┘
                      │
              React Dashboard

🔥 Core Features
✅ Real-Time Packet Capture
Captures live traffic
Flow-based aggregation (src → dst)

✅ Deep Packet Inspection (DPI)
DNS Query Extraction
HTTP Host Extraction
TLS SNI Extraction

✅ Machine Learning Detection
Isolation Forest anomaly detection
Feature scaling (StandardScaler)
6-feature vector:
Packet Count
Total Bytes
Avg Packet Size
Duration
Byte Rate
Packet Rate

✅ Threat Scoring Engine
Converts anomaly score → 0–100 threat score
Auto-classifies:
Low
Medium
High
Critical

✅ Alert System
Automatically creates alert for:
High Threat
Critical Threat
Stores alert metadata (IP, domain, score)

✅ Security Dashboard
Threat Distribution Pie Chart
Bytes per Flow Bar Graph
Real-Time Flow Table
Threat Level Highlighting

🛠 Tech Stack
Backend
Node.js
Express.js
MongoDB
Mongoose
Frontend
React.js
Recharts

ML & Network Layer
Python
Scapy
Scikit-learn
Joblib

⚙️ How To Run
1️⃣ Backend
cd backend
npm install
npm start

2️⃣ Frontend
cd frontend
npm install
npm start

3️⃣ Packet Capture (ML Engine)

Activate virtual environment:

Windows:
venv\Scripts\activate
Then:
python packet_capture.py

📊 Example Dashboard
Real-time threat monitoring
Flow-based anomaly detection
SOC-style visualization
Alert generation for suspicious traffic

🚀 Future Enhancements
Email alerts
Sound notification system
Auto IP blocking (iptables)
GeoIP attack map
Threat timeline analytics
Model retraining automation
Deployment using Docker
