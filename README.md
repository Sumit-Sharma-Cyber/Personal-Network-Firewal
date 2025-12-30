🛡️ Personal Network Firewall (Python & Scapy)
📌 Project Overview
This project is a custom-built Personal Firewall application developed in Python. It is designed to perform Deep Packet Inspection (DPI) and filter network traffic in real-time. By monitoring the data link and network layers, the application identifies unauthorized access attempts and logs potential threats from specific IP addresses.

🛠️ Features
Real-Time Packet Sniffing: Monitors all incoming and outgoing IP traffic using the Scapy library.

IP Blacklisting: Automatically identifies and flags traffic from unauthorized or malicious IP addresses (e.g., a Metasploitable 2 instance).

Protocol Analysis: Inspects packet headers to distinguish between various protocols such as TCP, UDP, and ICMP.

Live Security Logging: Provides instant feedback on the terminal for "Allowed" vs. "Blocked" traffic.

🚀 Technical Implementation
The firewall operates by intercepting raw packets before they reach the higher levels of the OS networking stack.

Packet Capture: Uses sniff() to listen on the network interface.

Header Parsing: Extracts the IP.src (Source IP) from the packet header.

Rule Matching: Compares the source IP against a predefined list of blocked targets.

Logging: Outputs a security alert if a match is found, otherwise allows the traffic to pass.

💻 How to Run
Requirements:

Kali Linux

Python 3

Scapy Library (sudo apt install python3-scapy)

Execution: Run the script with root privileges to allow raw socket access:

Bash

sudo python3 firewall.py
Testing: Simulate an attack by pinging the host from a secondary machine (e.g., Metasploitable). The firewall will instantly log the attempt.

📊 Skills Learned
Network Security: Understanding of ingress/egress filtering and perimeter defense.

Protocol Analysis: Hands-on experience with the TCP/IP stack and packet header structures.

Defensive Programming: Writing Python scripts to automate security monitoring and incident response.
