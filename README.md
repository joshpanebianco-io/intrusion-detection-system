# 🛡️ Lightweight Network-based Intrusion Detection System for Purple Teaming Exercise 🟣

## 📘 Overview

This project is a lightweight, custom-built network-based Intrusion Detection System (IDS) designed to run on a victim machine within a VirtualBox homelab environment. It detects network attacks launched from an attacker machine (e.g., Kali Linux) and logs suspicious activity for analysis.

This setup simulates a **purple teaming** exercise, combining offensive and defensive cybersecurity techniques to deepen understanding of network security, attack vectors & detection, and incident response.

## 🎯 Project Goals

- 🏗️ Build a simple network IDS from scratch to detect basic attacks  
- 🧠 Gain hands-on experience with networking, packet analysis, and security monitoring  
- 💻 Setup and use a VirtualBox homelab for isolated attacker and victim machines  
- ⚔️ Practice offensive tactics (attacks from Kali) and defensive tactics (IDS detection & logging)  
- 🔍 Understand how to analyze logs and tune detection rules

## 🔍 Current Detection Capabilities

The IDS currently detects the following network activities:

- 🔁 **ARP Spoofing**
- 📡 **C2 Beaconing**  
- 🌐 **DNS Tunneling**
- 🌊 **ICMP Flood**
- 💣 **Payload Strings** (e.g., known malicious payloads)
- 🔎 **Port Scans**
- 🔐 **SSH Brute Force**
- 🌊 **SYN Flood**
- 🌊 **TCP RST Flood**

## 🧪 Homelab Setup

- 🖥️ **Victim Machine:** Runs the custom IDS script monitoring network traffic and logging alerts  
- 🐉 **Attacker Machine:** Kali Linux, used to launch network attacks (e.g., ARP spoofing, port scans, SSH bruteforce)  
- 📦 **VirtualBox:** Hosts both VMs with configured internal networking  

## ✨ Features

- 🕵️ Lightweight packet sniffing and anomaly detection  
- 🗃️ Logging suspicious network events with timestamps  
- 🚨 Simple alert mechanism based on custom detection logic  
- 🔧 Modular code for easy extension and tuning  

## ▶️ Usage

1. 🟢 Launch the victim machine VM and start the IDS script  
2. 🔴 Launch the Kali Linux attacker VM  
3. 💣 Execute network attacks from Kali (e.g., `arping`, `nmap`, `reverse shells`) targeting the victim  
4. 📋 Observe IDS logs for detection alerts  
5. 📈 Analyze logs and tune detection parameters  

## 📦 Prerequisites

- 🖥️ VirtualBox installed  
- 🧑‍💻 Two VMs: Victim (Linux with Python), Attacker (Kali Linux)  
- 🐍 Python 3.x installed on the victim VM  
- 📚 Required Python packages (e.g., `scapy`) installed on victim VM  

## 🧪 Example Commands

- Start IDS:  
  ```bash
  python3 ids.py

## 📷 Screenshots

Here are example detections from running various attacks against the victim machine.

### 🔁 ARP Spoofing Detection
![ARP Spoofing](screenshots/arp_spoofing.png)

### 📡 C2 Beaconing Detection
![C2 Beaconing](screenshots/c2_beaconing.png)

### 🌐 DNS Tunneling Detection
![DNS Tunneling](screenshots/dns_tunneling.png)

### 🌊 ICMP Flood Detection
![ICMP Flood](screenshots/icmp_flood.png)

### 💣 Payload Strings Detection
![Payload Strings](screenshots/payload_strings.png)

### 🔎 Port Scan Detection
![Port Scan](screenshots/port_scan.png)

### 🔐 SSH Brute Force Detection
![SSH Brute Force](screenshots/ssh_brute_force.png)

### 🌊 SYN Flood Detection
![SYN Flood](screenshots/syn_flood.png)

### 🌊 TCP RST Flood Detection
![TCP RST Flood](screenshots/tcp_rst_flood.png)


  
