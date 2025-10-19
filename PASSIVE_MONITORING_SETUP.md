# Passive Wi-Fi Monitoring Setup Guide

## Overview
The Passive Monitoring module provides comprehensive Wi-Fi security analysis capabilities including real-time packet capture, threat detection, and security auditing. This guide covers installation, configuration, and usage.

## ⚠️ Important Security Notice
**This feature is designed for authorized security testing and lab environments only. Ensure you have proper permissions before using these tools.**

## Features Included

### Core Features
- **Passive Wi-Fi Monitoring** - Capture and analyze packets from all available Wi-Fi networks
- **Handshake Capture** - Detect and log WPA/WPA2/WPA3 4-way handshakes
- **Beacon Frame Analysis** - Analyze beacon frames for anomalies and security issues
- **Rogue AP Detection** - Identify suspicious or unauthorized access points
- **Security Auditing** - Comprehensive Wi-Fi security assessment with detailed reports

### Advanced Features
- **Deauthentication Attack Detection** - Monitor for deauth attack patterns
- **Channel Utilization Analysis** - Analyze Wi-Fi channel congestion
- **Client Device Tracking** - Map device connections and detect suspicious behavior
- **Packet Type Distribution** - Visualize traffic patterns and detect anomalies
- **Encryption Strength Analysis** - Identify weak security protocols

## Prerequisites

### System Requirements
- **Operating System**: Linux (preferred), Windows, or macOS
- **Python**: 3.8 or higher
- **Administrator/Root privileges**: Required for packet capture
- **Network Interface**: Wi-Fi adapter capable of monitor mode (Linux) or promiscuous mode

### Required Python Packages
```bash
# Install scapy for packet capture (required for full functionality)
pip install scapy

# Install additional dependencies
pip install psutil netifaces wireless
```

### Linux Setup (Recommended)
```bash
# Install wireless tools
sudo apt-get update
sudo apt-get install wireless-tools iw aircrack-ng

# Install Python dependencies
pip install scapy psutil netifaces

# Check available wireless interfaces
iwconfig
```

### Windows Setup
```bash
# Install Npcap (required for Windows packet capture)
# Download from: https://npcap.com/#download

# Install Python dependencies
pip install scapy psutil netifaces

# Note: Windows requires special drivers for monitor mode
# Consider using Linux in a VM for full functionality
```

## Configuration

### 1. Environment Variables
Add these to your `.env` file or environment:

```bash
# Enable lab mode (REQUIRED for passive monitoring)
LAB_MODE_ENABLED=true

# Admin users (comma-separated list)
ADMIN_USERS=admin,superuser,your_username

# Network allowlist path (optional)
NETWORK_ALLOWLIST_PATH=config/network_allowlist.json

# Capture limits
MAX_CAPTURE_DURATION=3600  # 1 hour maximum
MAX_CONCURRENT_CAPTURES=3
PACKET_BUFFER_SIZE=50000

# Detection thresholds
DEAUTH_ATTACK_THRESHOLD=10
PROBE_REQUEST_THRESHOLD=50
SIGNAL_ANOMALY_THRESHOLD=20
```

### 2. Network Allowlist (Optional)
Create `config/network_allowlist.json` to restrict monitoring to specific networks:

```json
{
  "allowed_networks": [
    "YourTestNetwork",
    "LabNetwork",
    "AuthorizedSSID"
  ],
  "description": "Networks authorized for passive monitoring"
}
```

### 3. User Permissions
Ensure your user account is in the ADMIN_USERS list and has appropriate system permissions:

```bash
# Linux: Add user to appropriate groups
sudo usermod -a -G wireshark,netdev $USER

# Or run application as root (not recommended for production)
sudo python app.py
```

## Usage

### 1. Access the Passive Monitoring Dashboard
1. Start your Flask application
2. Navigate to the main dashboard
3. Look for the "Passive Monitoring" section in the sidebar
4. Click "Monitor Dashboard" to access the main interface

### 2. Start Passive Monitoring
1. Go to **Passive Monitor → Traffic Capture**
2. Select your network interface (auto-detect recommended)
3. Set capture duration (default: 5 minutes)
4. Optionally select a specific Wi-Fi channel
5. Click "Start Capture"

### 3. Available Monitoring Tools

#### Traffic Capture
- **URL**: `/passive-monitor/traffic-capture`
- **Purpose**: Real-time packet capture and analysis
- **Features**: Live statistics, packet visualization, export capabilities

#### Beacon Analysis
- **URL**: `/passive-monitor/beacon-analysis`
- **Purpose**: Analyze beacon frames for security issues
- **Features**: SSID analysis, encryption detection, anomaly identification

#### Rogue AP Detection
- **URL**: `/passive-monitor/rogue-detector`
- **Purpose**: Identify suspicious access points
- **Features**: Evil twin detection, signal anomaly analysis, MAC address validation

#### Handshake Capture
- **URL**: `/passive-monitor/handshake-capture`
- **Purpose**: Capture WPA handshakes for security testing
- **Requirement**: Admin permissions
- **Features**: Automated handshake detection, quality assessment

#### Security Audit
- **URL**: `/passive-monitor/security-audit`
- **Purpose**: Comprehensive security assessment
- **Features**: Compliance checking, risk analysis, detailed recommendations

## API Endpoints

### Start Monitoring
```http
POST /api/passive-monitor/start
Content-Type: application/json

{
  "interface": "wlan0",
  "duration": 300,
  "channel": "6"
}
```

### Get Status
```http
GET /api/passive-monitor/status
```

### Stop Monitoring
```http
POST /api/passive-monitor/stop
```

### Get Results
```http
GET /api/passive-monitor/results
```

## Troubleshooting

### Common Issues

#### 1. "Insufficient permissions" Error
**Solution**: 
- Run application with administrator/root privileges
- Ensure LAB_MODE_ENABLED=true in configuration
- Verify user is in ADMIN_USERS list

#### 2. "No interfaces found" Error
**Solution**:
- Check if wireless adapter is connected
- Install wireless tools (Linux: `iwconfig`, Windows: ensure Wi-Fi adapter is enabled)
- Try running `iwconfig` or `ipconfig` to verify interfaces

#### 3. "Scapy not available" Warning
**Solution**:
- Install scapy: `pip install scapy`
- On Windows, install Npcap: https://npcap.com/
- On Linux, ensure user has packet capture permissions

#### 4. Monitor Mode Issues (Linux)
**Solution**:
```bash
# Check if interface supports monitor mode
iw list | grep monitor

# Enable monitor mode manually
sudo ip link set wlan0 down
sudo iw wlan0 set type monitor
sudo ip link set wlan0 up
```

#### 5. Performance Issues
**Solution**:
- Reduce capture duration
- Lower packet buffer size
- Use specific channel instead of channel hopping
- Ensure sufficient system resources

### Log Locations
- Application logs: `logs/app.log`
- Security logs: `logs/security.log`
- Audit logs: Database (audit_logs table)

## Security Considerations

### Legal and Ethical Use
- **Only use on networks you own or have explicit permission to test**
- **Comply with local laws and regulations regarding network monitoring**
- **Do not use for unauthorized surveillance or malicious purposes**

### Lab Environment Setup
- Use isolated test networks when possible
- Implement proper network segmentation
- Monitor and log all passive monitoring activities
- Regular security audits of the monitoring system itself

### Data Protection
- Captured packet data may contain sensitive information
- Implement secure storage and access controls
- Regular cleanup of old capture data
- Encryption of stored packet captures

## Performance Optimization

### For Large Networks
```python
# Reduce packet buffer size
PACKET_BUFFER_SIZE=25000

# Use shorter capture durations
MAX_CAPTURE_DURATION=1800  # 30 minutes

# Enable channel filtering
# Focus on specific channels of interest
```

### For Limited Resources
```python
# Disable real-time processing
# Process packets in batches
# Use sampling for large captures
```

## Advanced Configuration

### Custom Detection Rules
You can customize threat detection by modifying the configuration:

```python
# In config.py
CUSTOM_DETECTION_RULES = {
    'deauth_threshold': 5,  # Lower threshold for sensitive environments
    'probe_flood_threshold': 100,  # Higher threshold for busy areas
    'signal_jump_threshold': 30,  # dBm change that triggers alert
}
```

### Integration with External Tools
The passive monitoring system can be integrated with:
- **SIEM systems** via API endpoints
- **Network monitoring tools** via export functions
- **Alerting systems** via webhook notifications

## Support and Documentation

### Getting Help
1. Check application logs for detailed error messages
2. Verify configuration settings
3. Ensure all dependencies are installed
4. Test with minimal configuration first

### Further Reading
- Wi-Fi security best practices
- 802.11 protocol documentation
- Scapy documentation for advanced packet analysis
- Aircrack-ng suite for additional wireless tools

---

**Remember**: This tool is designed for defensive security purposes. Always ensure you have proper authorization before conducting any network monitoring activities.