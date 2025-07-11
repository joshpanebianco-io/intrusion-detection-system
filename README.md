# Lightweight Network-based Intrusion Detection System for Purple Teaming Exercise

## Overview

This project is a lightweight, custom-built network-based Intrusion Detection System (IDS) designed to run on a victim machine within a VirtualBox homelab environment. It detects network attacks launched from an attacker machine (e.g., Kali Linux) and logs suspicious activity for analysis.

This setup simulates a purple teaming exercise, combining offensive and defensive cybersecurity techniques to deepen understanding of network security, attack detection, and incident response.

## Project Goals

- Build a simple network IDS from scratch to detect basic attacks
- Gain hands-on experience with networking, packet analysis, and security monitoring
- Setup and use a VirtualBox homelab for isolated attacker and victim machines
- Practice offensive tactics (attacks from Kali) and defensive tactics (IDS detection & logging)
- Understand how to analyze logs and tune detection rules

## Homelab Setup

- **Victim Machine:** Runs the custom IDS script monitoring network traffic and logging alerts  
- **Attacker Machine:** Kali Linux, used to launch network attacks (e.g., ARP spoofing, port scans)  
- **VirtualBox:** Hosts both VMs with configured internal networking  

## Features

- Lightweight packet sniffing and anomaly detection  
- Logging suspicious network events with timestamps  
- Simple alert mechanism based on custom detection logic  
- Modular code for easy extension and tuning  

## Usage

1. Launch the victim machine VM and start the IDS script  
2. Launch the Kali Linux attacker VM  
3. Execute network attacks from Kali (e.g., `arping`, `nmap`) targeting the victim  
4. Observe IDS logs for detection alerts  
5. Analyze logs and tune detection parameters  

## Prerequisites

- VirtualBox installed  
- Two VMs: Victim (Linux with Python), Attacker (Kali Linux)  
- Python 3.x installed on the victim VM  
- Required Python packages (e.g., `scapy`) installed on victim VM  

## Example Commands

- Start IDS:  
  ```bash
  python3 lightweight_ids.py
