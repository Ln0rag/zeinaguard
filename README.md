![](screenshot.png)
# 🛡️ ZeinaGuard - Wireless Intrusion Detection & Prevention System

<div align="center">

![ZeinaGuard Logo](https://img.shields.io/badge/ZeinaGuard-WIDPS-blue?style=for-the-badge&logo=shield)
![Version](https://img.shields.io/badge/version-1.0.0-green?style=for-the-badge)
![License](https://img.shields.io/badge/license-MIT-blue?style=for-the-badge)
![Python](https://img.shields.io/badge/python-3.11+-blue?style=for-the-badge&logo=python)
![Node.js](https://img.shields.io/badge/node.js-20.x-green?style=for-the-badge&logo=node.js)

**Advanced Wireless Security Monitoring & Threat Prevention**

[⚡ Quick Start](#-quick-start) • [📖 Documentation](#-documentation) • [🔧 Configuration](#-configuration) • [🚀 Deployment](#-deployment)

</div>

---

## 🎯 Overview

**ZeinaGuard** is a comprehensive **Wireless Intrusion Detection & Prevention System (WIDPS)** that provides real-time monitoring, analysis, and protection against wireless security threats. Built with cutting-edge technology and designed for both security professionals and network administrators.

### 🔥 Key Features

- **🌐 Real-time Wireless Monitoring** - Continuous scanning and analysis of WiFi networks
- **🎯 Advanced Threat Detection** - Rogue APs, Evil Twins, Deauthentication attacks
- **🛡️ Active Prevention** - Automated countermeasures against confirmed threats
- **📊 Comprehensive Dashboard** - Modern web interface with real-time analytics
- **🔧 Universal Compatibility** - Works on any Linux distribution
- **⚡ High Performance** - Optimized for minimal resource usage
- **🔒 Enterprise Security** - Role-based access control and audit logging

---

## 🚀 Quick Start

### Prerequisites

- **Linux System** (Ubuntu, Debian, Fedora, Arch, AntiX, Kali, etc.)
- **Wireless Adapter** with monitor mode support
- **Root/Sudo Access** for network operations
- **2GB+ RAM** and **2GB+ Disk Space**

### One-Command Installation

```bash
# Clone the repository
git clone https://github.com/your-username/zeinaguard.git
cd zeinaguard

# Make the deployment script executable
chmod +x zeina.sh

# Deploy the entire system
./zeina.sh start
```

That's it! 🎉 ZeinaGuard will automatically:
- ✅ Detect your Linux distribution
- ✅ Install all dependencies
- ✅ Configure the database
- ✅ Start all services
- ✅ Launch the web interface

### Access Your System

- **🌐 Web Dashboard**: http://localhost:3000
- **🔧 API Endpoint**: http://localhost:5000
- **👤 Default Login**: `admin` / `admin123`

---

## 📋 System Requirements

### 🖥️ Supported Distributions

| Distribution | Package Manager | Status |
|--------------|------------------|---------|
| Ubuntu/Debian | apt | ✅ Full Support |
| AntiX Linux | apt-get | ✅ Optimized |
| Kali Linux | apt | ✅ Security Tools |
| Fedora/CentOS | dnf/yum | ✅ Enterprise |
| Arch Linux | pacman | ✅ Rolling |
| Alpine Linux | apk | ✅ Lightweight |
| Void Linux | xbps | ✅ Modern |
| openSUSE | zypper | ✅ Enterprise |

### ⚙️ Hardware Requirements

- **CPU**: 1+ cores (2+ recommended)
- **RAM**: 512MB minimum (2GB recommended)
- **Storage**: 2GB free space
- **Network**: Wireless adapter with monitor mode
- **Permissions**: Root/sudo access

### 🔌 Recommended Hardware

- **Alfa AWUS036ACH** - High performance monitor mode
- **TP-Link TL-WN722N v1** - Budget-friendly option
- **Panda PAU09** - Dual-band support
- **Generic USB WiFi** - Most adapters work

---

## 🛠️ Configuration

### 📁 Project Structure

```
zeinaguard/
├── zeina.sh              # Main deployment script
├── backend/              # Flask API server
│   ├── app.py           # Main application
│   ├── models.py        # Database models
│   └── routes/          # API endpoints
├── frontend/            # Next.js web dashboard
│   ├── app/             # React components
│   └── pages/           # Application pages
├── sensor/              # Wireless monitoring sensor
│   ├── main.py          # Sensor main process
│   ├── detection/       # Threat detection engine
│   └── monitoring/      # Network monitoring
├── scripts/             # Database and utility scripts
└── logs/                # Application logs
```

### ⚙️ Core Configuration

#### Sensor Configuration (`sensor/config.py`)

```python
# Wireless interface for monitoring
INTERFACE = "wlan1"  # Change to your monitor mode interface

# Trusted Access Points (whitelist)
TRUSTED_APS = {
    "YourNetworkSSID": {
        "bssid": "00:11:22:33:44:55",
        "channel": 6,
        "encryption": "WPA2"
    }
}

# Active Prevention Settings
ENABLE_ACTIVE_CONTAINMENT = True
DEAUTH_COUNT = 40
DEAUTH_INTERVAL = 0.1
```

#### Backend Configuration (Environment Variables)

```bash
# Database Configuration
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=zeinaguard_db
POSTGRES_USER=zeinaguard_user
POSTGRES_PASSWORD=secure_password

# Security Settings
JWT_SECRET_KEY=your-secret-key-here
FLASK_ENV=production

# Service Ports
FLASK_PORT=5000
```

---

## 🎮 Usage & Commands

### 🎯 Main Commands

```bash
# Start all services
./zeina.sh start

# Stop all services
./zeina.sh stop

# Restart all services
./zeina.sh restart

# Check service status
./zeina.sh status

# Show interactive menu
./zeina.sh menu
```

### 📡 Wireless Operations

```bash
# List wireless interfaces
./zeina.sh radar-list

# Enable monitor mode
./zeina.sh radar-on wlan1

# Disable monitor mode
./zeina.sh radar-off wlan1

# Show trusted APs
./zeina.sh radar-trusted
```

### 🔧 System Management

```bash
# Install dependencies
./zeina.sh install

# System information
./zeina.sh info

# Clean system
./zeina.sh clean

# Update system
./zeina.sh update
```

---

## 🌐 Web Interface

### 📊 Dashboard Features

- **🎯 Real-time Threat Map** - Visual network topology
- **📈 Analytics & Statistics** - Threat trends and patterns
- **⚠️ Alert Management** - Priority-based threat handling
- **👥 User Management** - Role-based access control
- **🔧 System Configuration** - Web-based settings
- **📱 Mobile Responsive** - Works on all devices

### 🔐 Security Features

- **🔑 JWT Authentication** - Secure token-based auth
- **👤 Role-Based Access** - Admin, Operator, Viewer roles
- **📝 Audit Logging** - Complete activity tracking
- **🛡️ CSRF Protection** - Cross-site request forgery prevention
- **🔒 HTTPS Support** - SSL/TLS encryption ready

---

## 🔍 API Documentation

### 🚀 Authentication

```bash
# Login
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```

### 📊 Data Endpoints

```bash
# Get system statistics
curl http://localhost:5000/api/dashboard/stats

# Get threats
curl http://localhost:5000/api/threats/

# Get sensors
curl http://localhost:5000/api/sensors/

# Get alerts
curl http://localhost:5000/api/alerts/
```

### 🎯 WebSocket Events

```javascript
// Connect to real-time updates
const socket = io('http://localhost:5000');

// Listen for threats
socket.on('threat_detected', (data) => {
    console.log('New threat:', data);
});

// Listen for sensor status
socket.on('sensor_status', (data) => {
    console.log('Sensor status:', data);
});
```

---

## 🛡️ Security Features

### 🔍 Threat Detection Engine

- **👹 Rogue AP Detection** - Unauthorized access points
- **🎭 Evil Twin Detection** - SSID spoofing attacks
- **💥 Deauth Detection** - Deauthentication floods
- **📡 Signal Analysis** - Anomalous signal patterns
- **🔐 Encryption Analysis** - Security protocol monitoring
- **📍 Geolocation Tracking** - Physical location mapping

### ⚡ Active Prevention

- **🚫 Deauthentication** - Disconnect malicious clients
- **📡 Containment** - Isolate threat sources
- **🔒 Network Isolation** - Segment compromised networks
- **⚠️ Alert Notification** - Real-time threat alerts

### 📊 Risk Scoring

| Score Range | Classification | Action |
|-------------|---------------|--------|
| 0-2 | **LEGIT** | Monitor only |
| 3-5 | **SUSPICIOUS** | Enhanced monitoring |
| 6+ | **ROGUE** | Active prevention |

---

## 🔧 Advanced Configuration

### 🎛️ Performance Tuning

```bash
# Resource limits for lightweight systems
export NODE_OPTIONS="--max-old-space-size=256"
export FLASK_ENV="production"

# Database connection pooling
export DB_POOL_SIZE=10
export DB_POOL_MAX_OVERFLOW=20
```

### 📡 Sensor Optimization

```python
# High-sensitivity monitoring
SCAN_INTERVAL = 0.1  # 100ms scan rate
MAX_SIGNAL_THRESHOLD = -30  # Very strong signals
MIN_CLIENTS_FOR_ALERT = 1  # Any connected clients
```

### 🔐 Security Hardening

```bash
# Enable HTTPS
export SSL_CERT_PATH="/path/to/cert.pem"
export SSL_KEY_PATH="/path/to/key.pem"

# Restrict API access
export API_WHITELIST="127.0.0.1,::1"
export CORS_ORIGINS="https://yourdomain.com"
```

---

## 🐛 Troubleshooting

### 🔧 Common Issues

#### **Service Won't Start**
```bash
# Check dependencies
./zeina.sh install

# Check logs
tail -f logs/backend.log
tail -f logs/frontend.log
tail -f logs/sensor.log
```

#### **Monitor Mode Issues**
```bash
# Check wireless interfaces
./zeina.sh radar-list

# Reset interface
sudo iwconfig wlan0 mode managed
sudo iwconfig wlan0 mode monitor
```

#### **Database Connection**
```bash
# Reset PostgreSQL password
sudo -u postgres psql -c "ALTER USER zeinaguard_user WITH PASSWORD 'secure_password';"

# Check database status
sudo -u postgres psql -c "\l"
```

### 📞 Getting Help

- **📖 Documentation**: Check `/docs/` directory
- **🐛 Issues**: Report on GitHub Issues
- **💬 Community**: Join our Discord server
- **📧 Support**: security@zeinaguard.local

---

## 🤝 Contributing

We welcome contributions! 🎉

### 🚀 Getting Started

1. **Fork** the repository
2. **Create** a feature branch
3. **Make** your changes
4. **Test** thoroughly
5. **Submit** a pull request

### 📋 Development Guidelines

- **🔍 Code Quality**: Follow PEP 8 and ESLint standards
- **🧪 Testing**: Add tests for new features
- **📖 Documentation**: Update docs for changes
- **🔒 Security**: Report vulnerabilities responsibly

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Scapy** - Packet manipulation library
- **Flask** - Web framework
- **Next.js** - React framework
- **PostgreSQL** - Database system
- **Socket.IO** - Real-time communication

---

## 📞 Contact

- **🌐 Website**: https://zeinaguard.local
- **📧 Email**: security@zeinaguard.local
- **🐛 Issues**: [GitHub Issues](https://github.com/your-username/zeinaguard/issues)
- **💬 Discord**: [Join our community](https://discord.gg/zeinaguard)

---

<div align="center">

**🛡️ Protect Your Wireless Networks with ZeinaGuard**

[⭐ Star on GitHub](https://github.com/your-username/zeinaguard) • [🐛 Report Issues](https://github.com/your-username/zeinaguard/issues) • [📖 Documentation](https://docs.zeinaguard.local)

Made with ❤️ for the cybersecurity community

</div>
