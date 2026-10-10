#!/usr/bin/env python3
from mininet.net import Mininet
from mininet.node import Controller
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import TCLink

def create_topology():
    setLogLevel('info')
    net = Mininet(controller=Controller, link=TCLink)

    print("=" * 55)
    print("  NETWORK THREAT DETECTION — TOPOLOGY")
    print("=" * 55)

    # Add controller and switch
    print("[*] Adding Controller...")
    c0 = net.addController('c0')

    print("[*] Adding Switch...")
    s1 = net.addSwitch('s1')

    print("[*] Adding Hosts...")
    h1 = net.addHost('h1', ip='10.0.0.1')  # Normal User
    h2 = net.addHost('h2', ip='10.0.0.2')  # Target Server
    h3 = net.addHost('h3', ip='10.0.0.3')  # DDoS Attacker
    h4 = net.addHost('h4', ip='10.0.0.4')  # SYN Flood Attacker
    h5 = net.addHost('h5', ip='10.0.0.5')  # Port Scanner
    h6 = net.addHost('h6', ip='10.0.0.6')  # Brute Force Attacker

    print("[*] Adding Links...")
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
    net.addLink(h4, s1)
    net.addLink(h5, s1)
    net.addLink(h6, s1)

    print("[*] Starting Network...")
    net.start()

    print("\n" + "=" * 55)
    print("  Network Topology Created Successfully!")
    print("=" * 55)
    print("  h1 (Normal User)       -> IP: 10.0.0.1")
    print("  h2 (Target Server)     -> IP: 10.0.0.2")
    print("  h3 (DDoS Attacker)     -> IP: 10.0.0.3")
    print("  h4 (SYN Flood Att.)    -> IP: 10.0.0.4")
    print("  h5 (Port Scanner)      -> IP: 10.0.0.5")
    print("  h6 (Brute Force Att.)  -> IP: 10.0.0.6")
    print("=" * 55)

    print("\n[*] Testing Connectivity...")
    net.pingAll()

    print("\n[*] Starting services on h2 (Target Server)...")
    h2.cmd('iperf -s &')
    h2.cmd('python3 -m http.server 8080 &')
    print("    iperf server running on port 5001")
    print("    HTTP server running on port 8080")

    print("\n[*] Network is Ready!")
    print("[*] Type 'exit' to stop the network")
    print("=" * 55)

    CLI(net)
    net.stop()
    print("[*] Network Stopped!")

if __name__ == '__main__':
    create_topology()
