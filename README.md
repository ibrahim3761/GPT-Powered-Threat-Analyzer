# 🛡️ GPT-Powered Threat Analyzer

> **University Capstone Project — Tier S**  
> A production-grade Intrusion Detection System that captures live network packets, applies heuristic triage rules, and uses GPT OSS 120B to classify and explain threats in natural language.

---

## 📋 Table of Contents

- [Architecture](#architecture)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [API Documentation](#api-documentation)
- [Module Breakdown](#module-breakdown)
- [Comparison vs Traditional IDS](#comparison-vs-traditional-ids)
- [Limitations & Future Work](#limitations--future-work)

---

## 🏗️ Architecture

```
┌─────────────┐     ┌──────────────┐     ┌───────────────┐     ┌──────────────┐
│   Network   │────▶│    Scapy     │────▶│   Heuristic   │────▶│ GPT OSS 120B │
│  Interface  │     │  AsyncSniffer│     │   Triage      │     │  Analyzer    │
│   (Wi-Fi)   │     │  (Producer)  │     │  (Consumer)   │     │  (Async)     │
└─────────────┘     └──────────────┘     └───────────────┘     └──────────────┘
                           │                     │                      │
                     Thread-Safe            Sliding Window          Retry Logic
                       Queue                 Tracking              JSON Parsing
                                                │                      │
                                                ▼                      ▼
                                        ┌──────────────┐      ┌──────────────┐
                                        │   SQLite DB  │◀─────│  RAG Engine  │
                                        │   (Alerts)   │      │  (ChromaDB)  │
                                        └──────────────┘      └──────────────┘
                                                │
                                                ▼
                                  ┌────────────────────────┐
                                  │   FastAPI REST API     │
                                  │   (Port 8000)          │
                                  └────────────────────────┘
                                                │
                                                ▼
                                  ┌────────────────────────┐
                                  │  Streamlit Dashboard   │
                                  │  (Port 8501)           │
                                  └────────────────────────┘
```

### Concurrency Model

| Thread | Role | Pattern |
|---|---|---|
| Main (uvicorn) | FastAPI async request handling | Non-blocking |
| Sniffer Thread | Scapy `AsyncSniffer` packet capture | Producer |
| Triage Thread | Heuristic rule engine | Consumer |
| LLM Thread | GPT OSS 120B async calls | Dedicated event loop |

---

## ✨ Features

### Core
- **Live Packet Capture** — Scapy-based sniffing with BPF filter support
- **Feature Extraction** — IP, ports, protocol, TCP flags, payload hex, DNS queries
- **Heuristic Triage** — 10+ detection rules with sliding window tracking
- **AI-Powered Analysis** — GPT OSS 120B classifies threats with MITRE ATT&CK mapping
- **SQLite Persistence** — Full alert history with async database operations
- **REST API** — FastAPI with Swagger docs, pagination, filtering, WebSocket streaming

### Bonus
- **RAG Knowledge Base** — ChromaDB with 25+ MITRE ATT&CK techniques for context injection
- **Real-Time Dashboard** — Premium Streamlit SOC interface with Plotly charts
- **Manual Analysis** — Submit test packets directly via the dashboard or API

### Detection Rules
| Rule | Description |
|---|---|
| SYN Scan | TCP SYN without ACK, rapid succession |
| Port Sweep | Same source → many destination ports |
| ICMP Flood | High-rate ICMP from single source |
| NULL Scan | TCP packet with no flags |
| XMAS Scan | TCP FIN+PSH+URG flags |
| FIN Scan | TCP FIN only (stealth scan) |
| Suspicious Port | Destination on known-bad port list |
| DNS Tunneling | Oversized DNS packets |
| Large Payload | Unusual payload size on non-web ports |
| High Frequency | Excessive packet rate per source |

---

## 📦 Prerequisites

1. **Python 3.10+**
2. **Npcap** (Windows) — Required for Scapy packet capture
   - Download: https://npcap.com/#download
   - Install with **"WinPcap API-compatible Mode"** checked
3. **GPT OSS 120B API Key** — Set in `.env` file
4. **Administrator Privileges** — Required for raw packet capture

---

## 🚀 Installation

```bash
# 1. Clone or navigate to the project directory
cd "IS Project"

# 2. Create virtual environment
python -m venv venv
venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
# Edit .env file with your settings (API key is pre-configured)

# 5. Start the API server (Run as Administrator!)
python main.py

# 6. In a separate terminal, launch the dashboard
streamlit run dashboard/app.py
```

---

## 🖥️ Usage

### Starting the System
1. **Open PowerShell as Administrator**
2. Activate virtual environment: `venv\Scripts\activate`
3. Start API: `python main.py`
4. Open new terminal → `streamlit run dashboard/app.py`
5. Dashboard opens at `http://localhost:8501`

### Dashboard Controls
- **Start/Stop Sniffing** — Sidebar toggle button
- **Interface Selection** — Dropdown in sidebar
- **Manual Analysis** — Submit test packets in sidebar panel
- **Auto-Refresh** — Toggle in sidebar (default: 3 second interval)

### Generating Test Traffic
```bash
# Simple ping (ICMP)
ping -n 100 8.8.8.8

# Port scan with nmap (if installed)
nmap -sS 192.168.1.1

# High-frequency connections
for ($i=0; $i -lt 200; $i++) { Test-NetConnection -ComputerName 8.8.8.8 -Port 80 }
```

---

## 📡 API Documentation

Once the server is running, full Swagger docs are available at: `http://localhost:8000/docs`

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Welcome + endpoint listing |
| `GET` | `/status` | System health (all components) |
| `GET` | `/interfaces` | Available network interfaces |
| `GET` | `/alerts` | Paginated alerts with filters |
| `GET` | `/alerts/recent` | In-memory alert buffer (fast) |
| `GET` | `/alerts/{id}` | Single alert detail |
| `GET` | `/statistics` | Aggregated charts data |
| `POST` | `/toggle-sniffing` | Start/stop sniffer |
| `POST` | `/analyze-sample` | Manual packet analysis |
| `WS` | `/ws/alerts` | Real-time WebSocket stream |

---

## 🧩 Module Breakdown

### `modules/sniffer.py` — Packet Capture Engine
- Scapy `AsyncSniffer` in background thread
- Feature extraction: IP, ports, protocol, flags, payload
- `store=False` for memory efficiency
- Thread-safe queue output

### `modules/triage.py` — Heuristic Rule Engine
- Sliding window counters (`SlidingWindowTracker`, `PortTracker`)
- 10+ configurable detection rules
- Priority scoring system
- Auto-expiring entries for bounded memory

### `modules/llm_client.py` — GPT OSS 120B Integration
- Professional SOC Analyst system prompt
- Structured JSON response parsing with validation
- Exponential backoff retry (3 attempts)
- Dedicated asyncio event loop in background thread

### `modules/rag_engine.py` — RAG Knowledge Base
- ChromaDB embedded vector database
- 25+ MITRE ATT&CK technique descriptions
- Contextual query by triage flags
- Top-K results injected into LLM prompt

### `database.py` — SQLite Persistence
- Async operations via `aiosqlite`
- Full CRUD for alerts and sessions
- Aggregation queries for dashboard statistics

### `main.py` — FastAPI Orchestration
- Lifecycle management (startup/shutdown)
- All REST endpoints with Pydantic validation
- WebSocket real-time alert streaming
- CORS configured for dashboard

### `dashboard/app.py` — Streamlit SOC Dashboard
- Dark theme with cyan/teal accent palette
- Animated status indicators
- Plotly interactive charts
- Auto-refreshing alert feed
- Manual analysis panel

---

## ⚖️ Comparison vs Traditional IDS (Snort/Suricata)

| Criteria | This GPT-Powered Threat Analyzer | Snort/Suricata |
|---|---|---|
| **Detection Method** | Heuristic + AI classification | Signature-based rules |
| **Explainability** | Natural language explanations | Rule ID + CVE reference |
| **Zero-Day Detection** | Possible (behavioral analysis) | Limited (needs signature) |
| **Setup Complexity** | Moderate (Python + API key) | Complex (rule management) |
| **Performance** | ~100 packets/sec (LLM bottleneck) | 10Gbps+ wire speed |
| **False Positives** | Moderate (AI can reason about context) | Low (precise signatures) |
| **Customization** | Prompt engineering | Rule writing (Snort rules) |
| **Best For** | SOC augmentation, threat explanation | Production perimeter defense |

---

## ⚠️ Limitations & Future Work

### Current Limitations
- LLM analysis adds latency (1-3 seconds per packet via API)
- Requires Administrator/root for packet capture
- Single-interface capture (no multi-NIC aggregation)
- GPT OSS 120B API rate limits may throttle high-volume analysis

### Future Enhancements
- [ ] Voice-driven security assistant (speech-to-text queries)
- [ ] Multi-model comparison (GPT OSS 120B vs GPT-4 vs Claude)
- [ ] PCAP file import/replay for offline analysis
- [ ] Email/Slack alert notifications
- [ ] GeoIP mapping for source/destination visualization
- [ ] Integration with SIEM platforms (Splunk, ELK)
- [ ] Fine-tuned local model for offline operation

---

## 📄 License

This project is developed for educational purposes as a university capstone project.

---

## 👥 Credits

- **MITRE ATT&CK®** — Threat intelligence framework
- **GPT OSS 120B** — Large Language Model for threat analysis
- **Scapy** — Packet manipulation library
- **FastAPI** — Modern async web framework
- **Streamlit** — Dashboard framework
- **ChromaDB** — Vector database for RAG
