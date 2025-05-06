# NetStrike (Scan Spoof Strike)

NetStrike is a GUI-based Python application for network scanning, ARP spoofing, and basic DoS attack simulation. Built using **Kivy** for the graphical interface, **Nmap**, **Scapy**, and **socket**, this tool is designed for educational and ethical hacking purposes only...

## Features

###  Scanning
- **Host Discovery** (Ping Sweep)
- **Scan All Devices** in the local network
- **Quick Scan** (Top 100 Ports)
- **Aggressive Scan** (OS, services, versions, etc.)
- **Full Scan** (All Ports)

###  ARP Spoofing
- Sends ARP spoof packets to a target and gateway.
- Can simulate man-in-the-middle conditions for testing purposes.

###  DoS (Denial of Service) Attack (Simulation)
- Basic TCP-based DoS attack on a given IP and port.
- Uses multithreading for high traffic simulation.

> ⚠️ **Disclaimer:** All functionalities must be used in **authorized environments**. Misuse is illegal and unethical.

---

## 🖥️ GUI Built With
- [Kivy](https://kivy.org/) - Python framework for GUI (Graphical User Interface)

## Dependencies
- Python 3
- Nmap (Requires Npcap on Windows)
- Scapy
- Kivy

### On Linux

1. Install Python
   ```bash
   sudo apt install python3 python3-pip
   ```
2. Create a Virtual Environment
   ```bash
   python3 -m venv netstrike-env
   ```
3. Activate the Virtual Environment
   ```bash
   source netstrike-env/bin/activate
   ```
4. Install Required Libraries
   ```bash
   pip install kivy scapy python-nmap
   ```
5. Install and Verify Nmap Tool
   ```bash
   sudo apt update && sudo apt install nmap
   ```
Running the Tool
   ```bash
   sudo python3 toolkit.py
   ```
### On Windows

Install Python and pip
- Download and install Python from the official website: [Python](https://www.python.org/downloads/)
- Ensure Python is added to your system's PATH.

1. Install Required Libraries
   ```bash
   pip install python-nmap scapy kivy
   ```
2. Install Npcap Driver
- Download and install Npcap from the official website: [Npcap](https://npcap.com/#download)
- Ensure Npcap is added to your system's PATH.
  
Running the Tool
- Open the terminal(admin)
- Navigate to the project directory
   ```bash
   python toolkit.py
   ```
