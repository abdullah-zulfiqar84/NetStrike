# NetStrike

## A Network Penetration Testing Toolkit

A comprehensive GUI-based toolkit for network penetration testing, including scanning, ARP spoofing, DoS and DDoS attack simulations.

## Features

- Network scanning (host discovery, port scanning)
- Vulnerability assessment
- ARP spoofing
- DoS attack simulation
- DDoS attack simulation
- PDF report generation

## Installation

### Prerequisites

- Python 3.7 or higher
- **Npcap**: Required for packet capture and network operations
- Windows users: Download and install from [Npcap's official website](https://npcap.com/#download)

### Setup

1. Install the required dependencies:
```bash
pip install -r requirements.txt
```

2. Run the application:
```bash
python Project.py
```

### Important Notes for Windows Users

- The application requires administrator privileges to perform network operations
- Ensure Windows Defender or other antivirus software doesn't block the application
- If you encounter issues with Scapy, try reinstalling Npcap with all options enabled


## Note

This tool is intended for educational purposes and authorized penetration testing only.
