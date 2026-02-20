# 🛡️ Nexus NIDPS - Network Intrusion Detection & Prevention System

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![CustomTkinter](https://img.shields.io/badge/GUI-CustomTkinter-green.svg)
![Scapy](https://img.shields.io/badge/Packet%20Analysis-Scapy-orange.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

## 📋 Overview
Nexus NIDPS is a comprehensive **Network Intrusion Detection and Prevention System** developed for the Ethical Hacking and Cyber Security course. It provides real-time network monitoring, attack detection, and automatic IP blocking capabilities with a modern dark-themed GUI.

## ✨ Features

### 🔍 Detection Capabilities
- **DoS/DDoS Attack Detection** - Detects flooding attacks (>100 packets/second)
- **Port Scan Detection** - Identifies SYN port scans scanning >30 unique ports
- **Real-time Packet Analysis** - Monitors network traffic in real-time

### 🛡️ Prevention Features
- **Automatic IP Blocking** - Integrates with iptables to block malicious IPs
- **Manual IP Block/Unblock** - Block or unblock IPs manually through the GUI
- **Protected IPs** - Cannot block localhost/loopback addresses

### 👤 User System
- **Secure Login/Registration** - User authentication system
- **Session Management** - User-specific monitoring sessions
- **Logout Functionality** - Return to login screen

### 📊 GUI Features
- **Live Alert Log** - Real-time display of security alerts
- **Attack Statistics** - Visual counters for alerts and blocked IPs
- **IP Selection Dropdowns** - Easy selection of attackers and blocked IPs
- **Alert Suppression** - Prevents alert flooding with cooldown mechanism
- **Dark Theme** - Professional dark mode interface

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- iptables (for Linux systems)
- Root/Administrator privileges

### Required Python Packages
```bash
pip install customtkinter scapy
