#!/usr/bin/env python3
"""
LIVE DEMO PIPELINE
==================
Run this AFTER starting topology.py in another terminal.
This script:
  1. Captures live traffic from Mininet interface
  2. Extracts flow-level features
  3. Classifies using pre-trained model
  4. Prints results in real time
"""

import subprocess
import threading
import time
import os
import pickle
import numpy as np
from collections import defaultdict
import dpkt

# ── Paths ─────────────────────────────────────────────────
DATASET_DIR  = '/home/animesh/Desktop/network_threat_detection/dataset/'
PCAP_LIVE    = '/tmp/live_capture.pcap'
IFACE        = 's1-eth2'   # Mininet switch interface

# ── Load pre-trained model and scaler ─────────────────────
print("="*55)
print("  NETWORK THREAT DETECTION — LIVE DEMO")
print("="*55)

print("\n[*] Loading pre-trained XGBoost model...")
with open(DATASET_DIR + 'xgboost_model.pkl', 'rb') as f:
    model = pickle.load(f)

with open(DATASET_DIR + 'scaler.pkl', 'rb') as f:
    scaler = pickle.load(f)

classes = np.load(DATASET_DIR + 'label_classes.npy', allow_pickle=True)
print(f"[*] Model loaded. Classes: {list(classes)}")
print(f"[*] Capture interface: {IFACE}")

# ── Feature extraction from PCAP ─────────────────────────
def extract_flows(pcap_path):
    flows = defaultdict(list)
    try:
        with open(pcap_path, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            for ts, buf in pcap:
                try:
                    # Try Ethernet
                    ip = None
                    try:
                        eth = dpkt.ethernet.Ethernet(buf)
                        if isinstance(eth.data, dpkt.ip.IP):
                            ip = eth.data
                    except:
                        pass
                    if ip is None:
                        try:
                            if len(buf) >= 16:
                                ip = dpkt.ip.IP(buf[16:])
                        except:
                            pass
                    if ip is None:
                        continue

                    proto    = ip.p
                    pkt_len  = len(buf)
                    ttl      = ip.ttl
                    src_ip   = str(ip.src)
                    dst_ip   = str(ip.dst)
                    src_port = dst_port = 0
                    syn = ack = fin = rst = 0

                    if isinstance(ip.data, dpkt.tcp.TCP):
                        tcp = ip.data
                        src_port = tcp.sport
                        dst_port = tcp.dport
                        syn = 1 if tcp.flags & 0x02 else 0
                        ack = 1 if tcp.flags & 0x10 else 0
                        fin = 1 if tcp.flags & 0x01 else 0
                        rst = 1 if tcp.flags & 0x04 else 0
                    elif isinstance(ip.data, dpkt.udp.UDP):
                        udp = ip.data
                        src_port = udp.sport
                        dst_port = udp.dport

                    key = (src_ip, dst_ip, src_port, dst_port, proto)
                    flows[key].append((ts, pkt_len, syn, ack, fin, rst, ttl, dst_port))

                except Exception:
                    continue
    except Exception as e:
        print(f"  [!] PCAP read error: {e}")

    return flows

def flows_to_features(flows):
    rows = []
    for key, packets in flows.items():
        if len(packets) < 2:
            continue
        packets.sort(key=lambda x: x[0])
        timestamps = [p[0] for p in packets]
        pkt_sizes  = [p[1] for p in packets]
        syn_flags  = [p[2] for p in packets]
        ack_flags  = [p[3] for p in packets]
        fin_flags  = [p[4] for p in packets]
        rst_flags  = [p[5] for p in packets]
        ttls       = [p[6] for p in packets]
        dst_ports  = [p[7] for p in packets]

        flow_dur = timestamps[-1] - timestamps[0]
        if flow_dur == 0:
            flow_dur = 0.0001

        total_pkts  = len(packets)
        total_bytes = sum(pkt_sizes)
        avg_pkt     = total_bytes / total_pkts
        mean        = avg_pkt
        std_pkt     = (sum((x - mean)**2 for x in pkt_sizes) / total_pkts) ** 0.5

        syn_c = sum(syn_flags)
        ack_c = sum(ack_flags)
        fin_c = sum(fin_flags)
        rst_c = sum(rst_flags)

        rows.append([
            flow_dur,
            total_pkts,
            total_bytes,
            avg_pkt,
            std_pkt,
            min(pkt_sizes),
            max(pkt_sizes),
            total_bytes / flow_dur,
            total_pkts  / flow_dur,
            syn_c,
            ack_c,
            fin_c,
            rst_c,
            syn_c / total_pkts,
            ack_c / total_pkts,
            len(set(dst_ports)),
            key[4],
            sum(ttls) / total_pkts
        ])
    return rows

# ── Classify and print results ────────────────────────────
def classify_and_print(pcap_path, round_num):
    print(f"\n{'='*55}")
    print(f"  CLASSIFICATION ROUND {round_num}")
    print(f"{'='*55}")

    flows = extract_flows(pcap_path)
    if not flows:
        print("  [!] No flows extracted. Generate some traffic first.")
        return

    feature_rows = flows_to_features(flows)
    if not feature_rows:
        print("  [!] Not enough flows (need packets > 1 per flow).")
        return

    X = np.array(feature_rows)
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
    X_scaled = scaler.transform(X)
    predictions = model.predict(X_scaled)
    pred_labels = [classes[p] for p in predictions]

    # Count results
    from collections import Counter
    counts = Counter(pred_labels)
    total  = len(pred_labels)

    print(f"\n  Flows analysed : {total}")
    print(f"\n  {'Traffic Type':<20} {'Flows':>8} {'%':>8}")
    print(f"  {'-'*38}")

    threat_detected = False
    for label in ['NORMAL', 'DDOS', 'SYN_FLOOD', 'PORT_SCAN', 'BRUTE_FORCE']:
        count = counts.get(label, 0)
        pct   = (count / total * 100) if total > 0 else 0
        flag  = " ⚠  THREAT" if label != 'NORMAL' and count > 0 else ""
        if label != 'NORMAL' and count > 0:
            threat_detected = True
        print(f"  {label:<20} {count:>8} {pct:>7.1f}%{flag}")

    print(f"\n  {'─'*38}")
    if threat_detected:
        print(f"  *** ALERT: MALICIOUS TRAFFIC DETECTED ***")
    else:
        print(f"  ✓  All traffic appears NORMAL")
    print(f"{'='*55}")

# ── Main Demo Loop ────────────────────────────────────────
def run_capture(duration=15):
    """Capture live traffic for given duration in seconds."""
    if os.path.exists(PCAP_LIVE):
        os.remove(PCAP_LIVE)

    print(f"\n[*] Capturing live traffic on {IFACE} for {duration} seconds...")
    print(f"[*] GO TO MININET TERMINAL NOW AND RUN YOUR ATTACK!\n")

    cmd = ['sudo', 'tcpdump', '-i', IFACE,
           '-w', PCAP_LIVE, '-G', str(duration),
           '-W', '1', '--immediate-mode']
    try:
        proc = subprocess.Popen(cmd,
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        # Countdown
        for i in range(duration, 0, -1):
            print(f"\r  Capturing... {i}s remaining  ", end='', flush=True)
            time.sleep(1)
        proc.terminate()
        proc.wait()
        print(f"\r  Capture complete!              ")
    except Exception as e:
        print(f"[!] Capture error: {e}")

# ── Entry Point ───────────────────────────────────────────
if __name__ == '__main__':
    print("\n[*] Instructions:")
    print("    1. Keep topology.py running in another terminal")
    print("    2. This script will capture 15 seconds of traffic")
    print("    3. During capture, go to Mininet and run attacks")
    print("    4. Results will show automatically\n")

    round_num = 1
    while True:
        input("  Press ENTER to start a new capture round (Ctrl+C to exit)...")
        run_capture(duration=15)
        time.sleep(1)
        if os.path.exists(PCAP_LIVE):
            classify_and_print(PCAP_LIVE, round_num)
        else:
            print("  [!] No capture file found. Check interface name.")
        round_num += 1
        print("\n  You can run another round or press Ctrl+C to exit.")
