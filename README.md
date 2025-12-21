# 🛡️ CyberShield DLP Security System

## 📋 Overview

CyberShield is a high-performance **Data Loss Prevention (DLP)** platform designed to monitor, detect, and prevent unauthorized data exfiltration. Unlike passive scanners, this system features an active file-system observer that catches policy violations the moment they occur.

## 🚀 Key Features & Functionality

* **Live Security Monitor:** Utilizes the `watchdog` library to observe file system events in real-time.
* **Deep Content Inspection:** Rule-based scanning engine for `.txt` and `.xlsx` (Excel) files using Regex patterns.
* **Instant Alerts:** Real-time UI updates via **Flask-SocketIO**, eliminating the need for page refreshes.
* **Active Threat Management:** - **Review:** Detailed modal view of threat metadata.
* **Remediation:** "Take Action" capability to physically delete malicious/leaky files from the disk.
* **Resolution:** Status tracking for incident response.


* **Persistence Layer:** Automated state-saving using JSON-backed data structures (`threats.json`, `scans.json`).
* **Secure Access Control:** Session-based authentication and protected routes.

## ⚡ Quick Start

### Installation

```bash
# Clone your personal repository
git clone https://github.com/hasnainali/CyberShield-DLP-Security.git
cd CyberShield-DLP-Security

# Install dependencies
pip install -r requirements.txt

# Run application
python app.py

```

### Access Application

* **URL:** `http://localhost:5001`
* **Demo Credentials:**
* **Admin:** `hasnain` / `admin123`



## 🏗️ Technical Architecture

* **Backend:** Flask (Python)
* **Real-Time Communication:** Flask-SocketIO (WebSockets)
* **File System Observer:** Watchdog (Multi-threaded)
* **Data Storage:** JSON (Flat-file Database)
* **Frontend:** Bootstrap 5, Bi-Icons, Animate.css

## 🔧 Project Structure

```text
CyberShield-DLP-Security/
├── app.py              # Main Flask server & API routes
├── monitor.py          # Watchdog observer & Scanning logic
├── threats.json        # Persistent threat database
├── scans.json          # Historical scan logs
├── templates/          # Jinja2 HTML templates
│   ├── base.html       # Sidebar & Layout
│   ├── index.html      # Dashboard
│   ├── monitor.html    # Live Monitoring stream
│   ├── threats.html    # Threat management table
│   └── login.html      # Authentication page
└── static/             # Custom CSS and JavaScript

```

## 👥 Development Team

* **Hasnain Ali** - Monitoring and Scanning Tool Development
* **Sayyad Ali Naqi Naqvi** - Frontend Development and Logical Flow
* **Hassan Nasser** - Security Testing and Realtime Integration
* **Feroz-U-Din** - System Architecture and Backend Development

---

**📅 Last Updated:** December 2025

**🛡️ Developed for:** Cybersecurity DLP Capstone Project