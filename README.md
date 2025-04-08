# 🔍 NETRA - Network Reconnaissance and Analysis Tool

**NETRA** (Network Exploration Tool by **Chalamalasetty Yaswanth Surya**) is a Python-based command-line tool designed for network reconnaissance and footprinting. It helps penetration testers, red teamers, and network administrators identify live hosts, scan open ports, and detect common services running on machines within a target network or subnet.

This tool provides a good balance between customization, educational value, and practical utility by leveraging **Scapy**, **socket**, and **requests** modules to manually craft and analyze packets.

---

## 🧠 Tool Description

NETRA works by:
- Discovering hosts on the local subnet using ARP scanning.
- Identifying open TCP/UDP ports by sending custom probes.
- Checking for common services like DHCP, POP3, SNMP, IMAP, LDAP, and NetBIOS.
- Looking up MAC address vendor details using the `macvendors.co` API.

It displays an interactive terminal interface using `pyfiglet` to provide a clean and branded feel while performing scanning operations efficiently and clearly.

---

## 🚀 Features

### ✅ Host Discovery
- Uses ARP requests to identify live hosts on the same subnet.
- Displays IP and MAC addresses.

### ✅ Port Scanning
- Scans for commonly used TCP ports (e.g., 21, 22, 23, 25, 80, 443, etc.).
- Attempts simple UDP scans on selected ports.
- Differentiates between open, closed, and filtered ports.

### ✅ Service Detection
- Detects the presence of key services:
  - DHCP
  - POP3
  - IMAP
  - SNMP
  - LDAP/LDAPS
  - NetBIOS
- Some services return version or banner details.

### ✅ MAC Address Vendor Lookup
- Uses MAC OUI to determine device manufacturer via public API.

### ✅ Stylized Terminal Output
- Includes custom ASCII art banner using `pyfiglet`.

---

## ⚖️ Pros and Cons

### ✅ Pros:
- Fully Python-based and beginner-friendly.
- Easy to extend for advanced functionality.
- Doesn't rely on bulky tools like Nmap.
- Useful in small to medium network recon tasks.
- Educational – shows how packet crafting and scanning work.

---

## 🧰 Requirements

Python 3.x is required. Install all dependencies with:

```bash
pip install scapy requests pyfiglet
```
## ⚙️ Usage
Run the tool as Admin:
```Terminal
python3 netra.py
```

You will be prompted to enter a target IP address or subnet (e.g., 192.168.1.0/24 or a specific host like 192.168.1.10). The tool then:
- Performs host discovery
- Scans open ports
- Detects running services
- Displays vendor/manufacturer information

## 🧪 Ideal Use Cases
- Internal penetration testing and recon
- Pre-engagement scanning in red teaming
- Cybersecurity education and demonstrations
- Quick network scans in labs and personal environments
- Asset discovery for small office/home office (SOHO) networks

## 🛡️ Legal Disclaimer
⚠️ This tool is intended for authorized use only. Do not scan networks or hosts that you do not own or have explicit permission to test. The author is not responsible for any misuse or damage caused by this tool.
