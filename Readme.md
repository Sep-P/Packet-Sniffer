# Packet Sniffer: Low-Level Network Traffic Analyzer

![Python](https://img.shields.io/badge/Python-3.6%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey)

A Python-based tool to capture, dissect, and analyze raw network packets at the protocol level. 

---

## **Features**
- **Multi-Layer Packet Analysis**:
  - Ethernet frames (MAC addresses, EtherType).
  - IPv4 headers (TTL, protocol, source/destination IPs).
  - TCP/UDP headers (ports, flags, checksums).
- **Manual Header Parsing**: Decode raw bytes using Python’s `struct` module (no external libraries).
- **HTTP Credential Detection**: Filter HTTP traffic to identify `POST` requests and extract plaintext credentials.
- **Cross-Platform Compatibility**: Works on Windows (with Npcap) and Linux.

---

## **Installation**

### **Prerequisites**
- Python 3.6 or higher.
- **Windows**: Install [Npcap](https://nmap.org/npcap/) (enable "WinPcap Compatibility Mode" during installation).
- **Linux**: Ensure you have `sudo` privileges for raw socket access.

### **Steps**
1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/packet-sniffer.git
   cd packet-sniffer
Install Python dependencies:

bash
Copy
pip install scapy
Usage
Scapy Implementation (Quick Start)
Run the Scapy-based sniffer to capture and analyze packets:

bash
Copy
python src/scapy_sniffer.py
Raw Socket Implementation (Manual Parsing)
Run the raw socket sniffer for low-level packet dissection:

Linux:

bash
Copy
sudo python src/raw_socket_sniffer.py
Windows:
Run the script as Administrator:

bash
Copy
python src/raw_socket_sniffer.py
Example Output
plaintext
Copy
[ETH] Destination: 00:1a:2b:3c:4d:5e, Source: 00:a1:b2:c3:d4:e5, Protocol: 2048
[IP] 192.168.1.1 -> 192.168.1.2 | Protocol: 6, TTL: 64
  [TCP] Port: 54321 -> 80
[HTTP] Potential credentials detected:
POST /login HTTP/1.1
username=admin&password=WeakPassword123
