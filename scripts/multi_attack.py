#!/usr/bin/env python3
"""
MULTI-ATTACK DEMO SCRIPT
=========================
Run this INSIDE Mininet CLI after topology.py is running.
Usage: mininet> py execfile('/home/animesh/Desktop/network_threat_detection/scripts/multi_attack.py')

OR run each command manually in Mininet CLI as shown below.
"""

# ── INSTRUCTIONS FOR VIVA DEMO ────────────────────────────
# After topology.py starts, run these commands in Mininet CLI:
#
# Step 1: Start normal traffic from h1
#   mininet> h1 iperf -c 10.0.0.2 -t 30 &
#
# Step 2: Start DDoS from h3
#   mininet> h3 hping3 --flood -p 80 10.0.0.2 &
#
# Step 3: Start SYN Flood from h4
#   mininet> h4 hping3 -S --flood -p 443 10.0.0.2 &
#
# Step 4: Start Port Scan from h5
#   mininet> h5 nmap -sS 10.0.0.2 &
#
# Step 5: Start Brute Force from h6
#   mininet> h6 hping3 -S --flood -p 22 10.0.0.2 &
#
# All attacks run simultaneously!
# Switch to live_demo terminal and press ENTER to capture.
# ──────────────────────────────────────────────────────────

print("Multi-attack instructions loaded.")
print("Run the commands above in Mininet CLI.")
