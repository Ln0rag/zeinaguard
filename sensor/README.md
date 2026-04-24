# ZeinaGuard Sensor — Wireless Intrusion Prevention System (WIPS)

> A professional, modular, real-time wireless intrusion prevention sensor built for deployment on Raspberry Pi as part of the **ZeinaGuard Pro** WIPS platform.

---

## Overview

Modern wireless networks are increasingly vulnerable to sophisticated attacks such as **Evil Twin access points**, **deauthentication floods**, and **signal spoofing**. Conventional network monitoring tools either lack real-time detection capability or fail to take active countermeasures when a threat is confirmed.

**ZeinaGuard Sensor** is the edge-deployed component of the ZeinaGuard Pro platform — a full-stack Wireless Intrusion Prevention System. This sensor runs on a Raspberry Pi equipped with a monitor-mode-capable wireless adapter and is responsible for:

- Passively scanning the RF environment for rogue access points
- Analyzing captured data against a trusted AP baseline
- Triggering active deauthentication countermeasures against confirmed threats
- Forwarding real-time threat intelligence to the ZeinaGuard central backend via REST API and WebSocket

The system targets a **threat detection-to-alert latency of under 500 milliseconds**, making it suitable for enterprise and campus network security deployments.

---

## Features

- **Real-time Packet Capture** — Continuous 802.11 frame sniffing across all 2.4 GHz channels using Scapy
- **Intelligent Channel Hopping** — Automatically cycles through channels 1–13, with the ability to lock onto a target channel during active containment
- **Evil Twin Detection** — Identifies rogue APs impersonating trusted networks by comparing BSSID, channel, and encryption parameters
- **Encryption Downgrade Detection** — Flags access points that mimic a trusted SSID/BSSID but broadcast with weaker or open encryption (e.g., WPA2 → OPEN downgrade attack)
- **Risk Scoring Engine** — Rule-based threat scoring system that classifies APs as `LEGIT`, `SUSPICIOUS`, or `ROGUE`
- **Active Containment (IPS Mode)** — Sends targeted 802.11 deauthentication frames to disconnect clients from confirmed rogue APs; falls back to broadcast deauth when no clients are yet associated
- **False Positive Mitigation** — A threat must be observed 3 or more times before triggering active response or alerting the dashboard
- **Dual-Queue Architecture** — Decoupled event bus separating containment actions from dashboard notifications, preventing race conditions
- **JWT-Authenticated Backend Communication** — Sensor authenticates with the Flask backend on startup and maintains a secure token
- **Real-time Dashboard Feed** — Confirmed threats are forwarded to the Next.js dashboard via WebSocket (`python-socketio`) with sub-500ms latency
- **Dynamic Trusted AP List** — Can pull the trusted AP whitelist from the backend database at runtime, rather than relying solely on a static config file
- **Graceful Shutdown** — Handles `SIGINT` (Ctrl+C) cleanly, closing socket connections and stopping daemon threads

---

## Architecture

The sensor is built on a clean, modular architecture where every component has a single responsibility and communicates via in-memory queues (the Event Bus). This prevents blocking and ensures concurrent operation across all subsystems.

```
┌─────────────────────────────────────────────────────────────┐
│                   Raspberry Pi Sensor                       │
│                                                             │
│  ┌──────────────┐    event_queue    ┌───────────────────┐  │
│  │   Sniffer    │ ────────────────► │  Threat Manager   │  │
│  │ (802.11 RF)  │                   │  + Risk Engine    │  │
│  └──────────────┘                   └────────┬──────────┘  │
│                                              │              │
│                          ┌───────────────────┤              │
│                          │                   │              │
│                  containment_queue    dashboard_queue        │
│                          │                   │              │
│                          ▼                   ▼              │
│               ┌──────────────────┐  ┌────────────────────┐ │
│               │ Response Engine  │  │    WS Client       │ │
│               │ (Deauth Attack)  │  │ (Socket.IO feed)   │ │
│               └──────────────────┘  └────────────────────┘ │
│                                              │              │
└──────────────────────────────────────────────┼─────────────┘
                                               │
                              ┌────────────────▼──────────────┐
                              │     ZeinaGuard Backend         │
                              │   Flask + PostgreSQL + Redis   │
                              └────────────────┬──────────────┘
                                               │
                              ┌────────────────▼──────────────┐
                              │   ZeinaGuard Dashboard         │
                              │       Next.js + TypeScript     │
                              └───────────────────────────────┘
```

### Component Responsibilities

| Component | Module | Responsibility |
|---|---|---|
| **Sniffer** | `monitoring/sniffer.py` | Captures raw 802.11 Beacon and Data frames; builds the client association map; pushes events to `event_queue` |
| **Channel Hopper** | `monitoring/sniffer.py` | Cycles through channels 1–13 in a daemon thread; locks to a specific channel during active containment |
| **Risk Engine** | `detection/risk_engine.py` | Scores each AP event using rule-based analysis; classifies as `LEGIT`, `SUSPICIOUS`, or `ROGUE` |
| **Threat Manager** | `detection/threat_manager.py` | Consumes `event_queue`; tracks per-BSSID observation history; confirms threats after 3 detections; fans out to both downstream queues |
| **Event Bus** | `core/event_bus.py` | Central in-memory message broker; hosts `event_queue`, `containment_queue`, and `dashboard_queue` |
| **Response Engine** | `prevention/response_engine.py` | Consumes `containment_queue`; spawns an isolated thread per containment action to avoid blocking |
| **Containment Engine** | `prevention/containment_engine.py` | Constructs and transmits 802.11 Deauth frames using Scapy; supports both targeted and broadcast deauth |
| **API Client** | `communication/api_client.py` | Handles sensor registration, JWT authentication, and fetching the trusted AP list from Flask |
| **WS Client** | `communication/ws_client.py` | Maintains a persistent Socket.IO connection to the backend; forwards confirmed threats from `dashboard_queue` in real time |
| **Utils** | `utils.py` | Parses raw 802.11 Information Elements to extract human-readable SSID and channel number |
| **Config** | `config.py` | Holds interface name, trusted AP whitelist, deauth parameters, and the active containment toggle |

---

## Project Structure

```
zeina-guard-sensor/
│
├── main.py                         # Entry point: initializes all components and threads
│
├── config.py                       # Global configuration: interface, trusted APs, deauth settings
│
├── utils.py                        # 802.11 IE parser helpers (SSID, channel extraction)
│
├── core/
│   ├── __init__.py
│   └── event_bus.py                # In-memory queues: event_queue, containment_queue, dashboard_queue
│
├── monitoring/
│   ├── __init__.py
│   └── sniffer.py                  # Packet capture, channel hopper, client association tracker
│
├── detection/
│   ├── __init__.py
│   ├── risk_engine.py              # Rule-based threat scoring and AP classification
│   └── threat_manager.py          # Threat confirmation logic and queue fan-out
│
├── prevention/
│   ├── __init__.py
│   ├── response_engine.py         # Threat consumer; dispatches containment threads
│   └── containment_engine.py      # 802.11 Deauth frame forging and transmission
│
└── communication/
    ├── __init__.py
    ├── api_client.py               # REST client: JWT auth, trusted AP sync
    └── ws_client.py                # WebSocket client: real-time threat forwarding to backend
```

---

## How It Works

### Full Detection and Response Flow

```
1. [Sniffer]           Captures 802.11 Beacon frames on all channels
                       ↓
2. [Sniffer]           Builds/updates the client-association map from Data frames
                       ↓
3. [Sniffer]           Pushes an event dict to event_queue
                       ↓
4. [Risk Engine]       Scores the event against trusted AP rules:
                         - Open network with clients          → +5
                         - Evil Twin (BSSID mismatch)         → +6
                         - Encryption downgrade attack        → +6
                         - Channel mismatch                   → +2
                         - Unknown / untrusted SSID           → +3
                         - Abnormally strong signal (>-30dBm) → +2
                       ↓
5. [Threat Manager]    Classifies: LEGIT / SUSPICIOUS / ROGUE
                       Increments per-BSSID observation counter
                       ↓
6. [Threat Manager]    If ROGUE and observed ≥ 3 times (first confirmation only):
                         → Puts threat into containment_queue  (for active response)
                         → Puts threat into dashboard_queue    (for UI notification)
                       ↓
         ┌─────────────────────────────────────────────┐
         │                                             │
7a. [Response Engine]                        7b. [WS Client]
    Reads containment_queue                      Reads dashboard_queue
    Spawns a new Thread →                        Emits 'new_threat' event →
    ContainmentEngine.contain()                  Flask Backend →
         ↓                                           Next.js Dashboard
8. [Containment]
    Locks channel hopper to target channel
    Sends Deauth frames (both directions) for 10s
    Releases channel lock after containment
```

---

## Technologies Used

### Sensor (Raspberry Pi)
- **Python 3** — Core language
- **Scapy** — Low-level 802.11 packet capture and frame injection
- **python-socketio** — WebSocket client for real-time backend communication
- **requests** — HTTP REST client for JWT authentication and trusted AP sync
- **threading** — Concurrent execution of all subsystems
- **Linux `iwconfig`** — Wireless interface channel management

### Backend (ZeinaGuard Pro Platform)
- **Python / Flask** — REST API and WebSocket server (Flask-SocketIO)
- **PostgreSQL + TimescaleDB** — Time-series event storage
- **Redis** — Caching and pub/sub messaging
- **JWT** — Sensor authentication and authorization

### Frontend (ZeinaGuard Pro Platform)
- **Next.js** — Dashboard framework
- **TypeScript** — Type-safe UI development

### Infrastructure
- **Local backend services** — Flask, PostgreSQL, and Redis running on the same machine or LAN
- **Raspberry Pi** — Edge sensor hardware
- **Monitor-mode USB WiFi adapter** (e.g., Alfa AWUS036ACH, TP-Link TL-WN722N v1)

---

## Installation

### Prerequisites

- Raspberry Pi running Raspberry Pi OS (64-bit recommended)
- A USB wireless adapter that supports **Monitor Mode** and **Packet Injection**
- Python 3.9 or later
- Root/sudo access (required for raw socket operations)

### 1. Clone the Repository

```bash
git clone https://github.com/Ln0rag/ZeinaGuard.git
cd ZeinaGuard/sensor
```

### 2. Install Python Dependencies

```bash
pip install scapy python-socketio websocket-client requests
```

> **Note:** Scapy requires root privileges to capture raw packets. Run all commands with `sudo`.

### 3. Enable Monitor Mode on Your Wireless Interface

```bash
# Replace wlx002e2dc0346b with your actual interface name
sudo ip link set wlx002e2dc0346b down
sudo iw dev wlx002e2dc0346b set type monitor
sudo ip link set wlx002e2dc0346b up

# Verify
iwconfig wlx002e2dc0346b
```

### 4. Configure the Sensor

Edit `config.py` to match your environment:

```python
# config.py

INTERFACE = "wlx002e2dc0346b"   # Your monitor-mode interface

TRUSTED_APS = {
    "YourNetworkSSID": {
        "bssid": "aa:bb:cc:dd:ee:ff",
        "channel": 6,
        "encryption": "SECURED"
    }
}

ENABLE_ACTIVE_CONTAINMENT = True   # Set to False for IDS-only (monitoring) mode
DEAUTH_COUNT = 40                  # Deauth frames per burst
DEAUTH_INTERVAL = 0.1              # Seconds between frames
```

Also update the backend URL in `communication/api_client.py` and `communication/ws_client.py`:

```python
backend_url = "http://<YOUR_BACKEND_IP>:5000"
```

---

## Usage

### Run the Sensor

```bash
sudo python main.py
```

### Expected Startup Output

```
ZeinaGuard Sensor Starting...

[API] Authenticating with http://192.168.1.100:5000/api/auth/login...
[API] Authentication Successful! Token received.
[WebSocket] Connected to ZeinaGuard Dashboard!
[WebSocket] Started listening for threats to broadcast...
 WIDPS System Started...
```

### Stopping the Sensor

Press `Ctrl+C` for a graceful shutdown:

```
^C
Shutting down ZeinaGuard Sensor...
```

### IDS-Only Mode (No Active Countermeasures)

To run the sensor in passive monitoring mode without sending deauth packets, set the following in `config.py`:

```python
ENABLE_ACTIVE_CONTAINMENT = False
```

---

## Example Workflow

### Scenario: Evil Twin Attack Detected

1. An attacker sets up a rogue access point with SSID `"CorpWiFi"` on channel 11, but uses their own MAC address. The legitimate `"CorpWiFi"` is on channel 1 with BSSID `aa:bb:cc:dd:ee:ff`.

2. The **Sniffer** captures a Beacon frame from the rogue AP on channel 11.

3. The **Risk Engine** evaluates the event:
   - SSID matches a trusted AP → checks BSSID → **mismatch** → `+6 (Evil Twin suspected)`
   - Channel mismatch (11 vs 1) → `+2`
   - Total score: `8` → classified as **`ROGUE`**

4. The **Threat Manager** increments the BSSID counter. After the 3rd detection, it confirms the threat and pushes it to both queues.

5. **Simultaneously:**
   - The **Response Engine** picks up the threat from `containment_queue`, locks the channel hopper to channel 11, and begins sending Deauth frames to all associated clients for 10 seconds.
   - The **WS Client** picks up the threat from `dashboard_queue` and emits a `new_threat` WebSocket event to the Flask backend, which forwards a real-time alert to the Next.js dashboard (≤500ms latency).

6. The dashboard operator sees a red alert notification with full threat details: SSID, BSSID, score, reasons, and connected clients.

---

## Security Use Case

| Attack Type | Detection Method | Response |
|---|---|---|
| **Evil Twin AP** | BSSID mismatch against trusted AP whitelist | Active deauth + dashboard alert |
| **Encryption Downgrade** | Encryption type change on known SSID/BSSID | Active deauth + dashboard alert |
| **Rogue Open AP with clients** | Open encryption + connected client count | Elevated risk score + alert |
| **Channel Interference / Spoofing** | Channel mismatch on trusted SSID | Contributes to risk score |
| **Abnormal Signal Strength** | Signal > -30 dBm heuristic | Contributes to risk score |

---

## Future Improvements

- **Dynamic Trusted AP Sync** — Fully replace static `config.py` whitelist with live pulls from the backend database on a scheduled interval
- **Deauth Attack Detection** — Passively detect 802.11 Deauth/Disassociation flood attacks targeting legitimate clients
- **5 GHz Band Support** — Extend channel hopping to cover 5 GHz channels (36–165) for dual-band monitoring
- **Sensor Fleet Management** — Support registration and heartbeat for multiple distributed sensors reporting to a single backend
- **Memory Management** — Implement periodic cleanup of `clients_map`, `history`, and `last_status` dictionaries to prevent long-running memory growth
- **Structured Logging** — Replace `print()` statements with `logging` module integration for log levels, file output, and log rotation
- **Prometheus Metrics** — Expose sensor health metrics (packets/sec, threats detected, uptime) for infrastructure monitoring
- **PMKID / Handshake Capture Detection** — Detect passive credential harvesting attempts against WPA2 networks
- **mDNS / Captive Portal Detection** — Identify rogue APs hosting captive portals designed to steal credentials

---

## Author

**Adham** — Sensor Module Developer, ZeinaGuard Pro  
Graduation Project — Wireless Intrusion Prevention System (WIPS)  
GitHub: [github.com/Ln0rag/ZeinaGuard](https://github.com/Ln0rag/ZeinaGuard)

---

## License

This project is developed as an academic graduation project. Please refer to the repository for licensing details.
