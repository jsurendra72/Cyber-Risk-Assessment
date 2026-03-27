# 🛡️ CyberScan Pro - Network Threat Intelligence Console

A comprehensive cybersecurity risk assessment and vulnerability scanning tool that identifies network threats, calculates risk scores, generates detailed reports, and provides actionable security recommendations.

---

## 📋 Project Overview

CyberScan Pro is an integrated security scanning solution that performs network reconnaissance, analyzes vulnerabilities, calculates risk levels, generates comprehensive reports, and sends real-time alerts for critical threats.

---

## 📁 Project Structure

```
├── scanner.py              # Network scanning engine using Nmap
├── risk_engine.py          # Risk calculation and severity assessment
├── report_generator.py     # Report generation and summary creation
├── email_alert.py          # Email notification system for alerts
├── recommendations.py      # Security recommendations engine
├── dashboard.py            # Interactive Streamlit dashboard
├── run_dashboard.py        # Dashboard launcher script
├── requirements.txt        # Python dependencies
├── scan_results/           # Directory containing scan result XML files
├── scan_report.csv         # Generated scan report
├── summary.txt             # Scan summary file
├── results.json            # Results in JSON format
└── license.txt             # License information
```

---

## 🔧 Core Functionalities

### 1. **Network Scanner** (`scanner.py`)
- **Nmap Integration**: Executes Nmap scans against target hosts
- **Target Scanning**: Scans multiple targets for open ports and services
- **XML Output Processing**: Parses Nmap XML results for analysis
- **Service Detection**: Identifies running services on open ports
- **Vulnerability Checks**: Performs VirusTotal checks for threat intelligence
- **Data Organization**: Stores results in structured XML format within `scan_results/` directory
- **Error Handling**: Comprehensive error handling and retry mechanisms

**Key Features:**
- Processes Nmap output with detailed port and service information
- Integrates with VirusTotal API for threat intelligence
- Automatically creates and manages scan result directories
- Timestamps all scan operations

### 2. **Risk Engine** (`risk_engine.py`)
- **Risk Calculation**: Computes risk scores based on service type and vulnerability hits
- **Severity Classification**: Categorizes risks as LOW, MEDIUM, or HIGH
- **Service-Based Scoring**: 
  - High-risk services: FTP (4), Telnet (5), SMB (4), RDP (5), MySQL (3), SMTP (2), VNC (4)
  - Base risk score: 1 + service score + VirusTotal hits
- **Severity Levels**:
  - LOW: Score ≤ 2
  - MEDIUM: Score 3-5
  - HIGH: Score > 5

### 3. **Report Generator** (`report_generator.py`)
- **CSV Report Generation**: Creates detailed scan reports in CSV format
- **Summary Statistics**: Generates summary files with:
  - Scan timestamp
  - Total hosts scanned
  - Total ports found
  - Risk distribution (High/Medium/Low counts)
- **File Output**: Saves to `scan_report.csv` and `summary.txt`
- **Data Aggregation**: Consolidates scan data for analysis

### 4. **Email Alert System** (`email_alert.py`)
- **Smart Notifications**: Sends emails only for HIGH-RISK findings
- **Gmail Integration**: Uses Gmail SMTP for reliable delivery
- **Alert Format**: Structured alerts containing:
  - Target host information
  - Port and service details
  - Risk scores
  - Security severity assessment
- **Environment Configuration**: Uses `.env` file for secure credential management
- **SSL/TLS Security**: Encrypted email transmission on port 465

### 5. **Security Recommendations** (`recommendations.py`)
- **Service-Specific Advice**: Provides tailored recommendations for each service:
  - Telnet → Use SSH instead
  - FTP → Use SFTP or FTPS
  - SSH → Implement key authentication
  - HTTP → Upgrade to HTTPS
  - SMTP → Configure filtering
  - RDP → Restrict with firewall
  - VNC → Use VPN access
  - MySQL → Restrict remote access
  - PostgreSQL → Whitelist trusted IPs
- **Port-Based Recommendations**: Suggests actions based on exposed ports
  - Port 23 (Telnet) → Immediate closure
  - Port 21 (FTP) → Secure alternatives
  - Port 3389 (RDP) → Access restriction
  - Port 445 (SMB) → Ransomware protection
- **Generic Monitoring**: Default recommendations for unknown services

### 6. **Interactive Dashboard** (`dashboard.py`)
- **Streamlit Framework**: Web-based interactive interface
- **Dark Theme UI**: CyberSecurity-themed interface with neon accents (#00FFA6)
- **Visualization Components**:
  - Real-time metrics display
  - Risk distribution charts (High/Medium/Low)
  - Port statistics and service breakdown
  - Host vulnerability mapping
- **Threat Intelligence Console**: "Network Threat Intelligence Console" branding
- **Data Exploration**: Interactive filtering and analysis of scan results
- **Custom Styling**: Professional cybersecurity aesthetic

### 7. **Dashboard Launcher** (`run_dashboard.py`)
- **Automated Launch**: Starts Streamlit server automatically
- **Port Configuration**: Serves dashboard on `http://localhost:8501`
- **Process Management**: Spawns dashboard in separate process
- **Success Confirmation**: Prints connection information

---

## 📊 Data Flow

```
Nmap Scan → Risk Calculation → Report Generation
    ↓              ↓                  ↓
XML Results → Risk Scores → CSV Report + Summary
                  ↓
             Email Alerts (HIGH RISK)
                  ↓
           Dashboard Visualization
```

---

## 🚀 Installation & Setup

### Prerequisites
- Python 3.7+
- Nmap installed and in system PATH
- Gmail account (for email alerts)

### Dependencies
Install required packages:

```bash
pip install -r requirements.txt
```

**Required Libraries:**
- `streamlit` - Web dashboard framework
- `pandas` - Data manipulation
- `plotly` - Interactive visualizations
- `requests` - HTTP requests
- `reportlab` - PDF generation
- `python-dotenv` - Environment variable management

### Configuration

Create a `.env` file in the project root:

```env
GMAIL_SENDER=your-email@gmail.com
GMAIL_PASSWORD=your-app-password
GMAIL_RECIPIENT=recipient@email.com
```

**Note:** Use Gmail App Passwords (not your main password) for security.

---

## 💻 Usage

### Run Full Scan & Report Generation
```bash
python scanner.py
```

### Launch Interactive Dashboard
```bash
python run_dashboard.py
```

Access at: `http://localhost:8501`

### Manual Imports (For Integration)
```python
from scanner import run_scan
from risk_engine import calculate_risk, severity_level
from report_generator import generate_report
from email_alert import send_email
from recommendations import get_recommendation
```

---

## 📤 Output Files

| File | Description |
|------|-------------|
| `scan_report.csv` | Detailed vulnerability report with all findings |
| `summary.txt` | High-level scan summary with statistics |
| `results.json` | Results in JSON format for API integration |
| `scan_results/*.xml` | Raw Nmap scan results organized by target |

---

## 🔒 Security Features

- **Encrypted Email**: SSL/TLS protected SMTP connection
- **Environment Variables**: Secure credential storage via `.env`
- **Risk-Based Alerting**: Only alerts for HIGH-RISK findings
- **Vulnerability Intelligence**: VirusTotal integration for threat checks
- **Comprehensive Logging**: Timestamped operation records

---

## 📈 Risk Score Calculation

```
Risk Score = Base Score (1) + Service Score + VirusTotal Hits

Examples:
- Telnet + 3 VT Hits = 1 + 5 + 3 = 9 (HIGH)
- SMTP + 0 VT Hits = 1 + 2 + 0 = 3 (MEDIUM)
- Unknown Service + 0 VT Hits = 1 + 0 + 0 = 1 (LOW)
```

---

## 🎯 Use Cases

- **Network Administrators**: Monitor open ports and vulnerable services
- **Security Auditors**: Generate compliance reports with findings
- **Incident Response Teams**: Quick identification of high-risk targets
- **Penetration Testing**: Baseline vulnerability assessment
- **Threat Monitoring**: Real-time alerts for critical exposures

---

## 📝 License

See `license.txt` for licensing information.

---

## 🤝 Support

For issues or questions, refer to the individual module documentation or review the code comments.

---

**Last Updated:** March 2026  
**Version:** 1.0  
**Status:** Active Development