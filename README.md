# KUNetMonit v1.0 - Network Monitoring and Packet Capturing Application

**Developed by:** Safiullah Yusufzai
**Under the mentorship of:** Sibghatullah Rahmatzai
**Organization:** Kabul University

# Features

* Monitor network clients, ports, and bandwidth.
* Auto-detect connected devices.
* Capture the incoming and outgoing packets from the client computers.
* Supports network monitoring when deployed on a Windows Server configured as a gateway or on a switch mirror/SPAN port.

## Prerequisites

Before running KUNetMonit, the following is required:

* **Windows operating system**
* **Npcap** required for network packet capture and monitoring.

## Deployment Environment

KUNetMonit is designed to operate in network environments where the monitoring system can receive the relevant network traffic.

It can be deployed in either of the following configurations:

1. **Windows Server configured as a network gateway**
   KUNetMonit can monitor network traffic passing through the Windows Server.

2. **Switch with a mirrored/SPAN port**
   KUNetMonit can be connected to a switch mirror port configured to provide a copy of the relevant network traffic to the monitoring system.

## Usage

To start, double-click the desktop shortcut.

## Support

For support, contact: **[Safiullahy7@gmail.com](mailto:Safiullahy7@gmail.com)**

## License

Copyright (c) 2026 Safiullah Yusufzai

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for the full license text.
