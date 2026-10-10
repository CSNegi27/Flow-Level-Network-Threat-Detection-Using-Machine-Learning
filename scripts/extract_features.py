#!/usr/bin/env python3
import dpkt
import socket
import csv
import os
import sys
from datetime import datetime

def mac_addr(address):
    return ':'.join('%02x' % b for b in address)

def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

def extract_features(pcap_file, label, output_csv):
    features = []
    try:
        with open(pcap_file, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            prev_time = None
            pkt_count = 0
            for timestamp, buf in pcap:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    if not isinstance(eth.data, dpkt.ip.IP):
                        continue
                    ip = eth.data
                    proto = ip.p
                    src_ip = inet_to_str(ip.src)
                    dst_ip = inet_to_str(ip.dst)
                    pkt_len = len(buf)
                    ttl = ip.ttl
                    # Time between packets
                    if prev_time is None:
                        iat = 0
                    else:
                        iat = timestamp - prev_time
                    prev_time = timestamp
                    # TCP features
                    src_port = 0
                    dst_port = 0
                    tcp_flags = 0
                    syn_flag = 0
                    ack_flag = 0
                    fin_flag = 0
                    rst_flag = 0
                    if isinstance(ip.data, dpkt.tcp.TCP):
                        tcp = ip.data
                        src_port = tcp.sport
                        dst_port = tcp.dport
                        tcp_flags = tcp.flags
                        syn_flag = 1 if tcp.flags & dpkt.tcp.TH_SYN else 0
                        ack_flag = 1 if tcp.flags & dpkt.tcp.TH_ACK else 0
                        fin_flag = 1 if tcp.flags & dpkt.tcp.TH_FIN else 0
                        rst_flag = 1 if tcp.flags & dpkt.tcp.TH_RST else 0
                    # UDP features
                    elif isinstance(ip.data, dpkt.udp.UDP):
                        udp = ip.data
                        src_port = udp.sport
                        dst_port = udp.dport
                    feature = {
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'protocol': proto,
                        'pkt_len': pkt_len,
                        'ttl': ttl,
                        'iat': round(iat, 6),
                        'tcp_flags': tcp_flags,
                        'syn_flag': syn_flag,
                        'ack_flag': ack_flag,
                        'fin_flag': fin_flag,
                        'rst_flag': rst_flag,
                        'label': label
                    }
                    features.append(feature)
                    pkt_count += 1
                    # Limit to 50000 packets per file
                    if pkt_count >= 50000:
                        print(f'[*] Reached 50000 packet limit for {label}')
                        break
                except Exception:
                    continue
    except Exception as e:
        print(f'Error reading {pcap_file}: {e}')
        return
    # Write to CSV
    if features:
        fieldnames = ['src_ip','dst_ip','src_port','dst_port',
                     'protocol','pkt_len','ttl','iat',
                     'tcp_flags','syn_flag','ack_flag',
                     'fin_flag','rst_flag','label']
        file_exists = os.path.exists(output_csv)
        with open(output_csv, 'a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            if not file_exists:
                writer.writeheader()
            writer.writerows(features)
        print(f'[+] {label}: {len(features)} packets extracted -> {output_csv}')

if __name__ == '__main__':
    pcap_dir = '/home/animesh/Desktop/network_threat_detection/pcap_files'
    output = '/home/animesh/Desktop/network_threat_detection/dataset/network_data.csv'
    # Remove old dataset if exists
    if os.path.exists(output):
        os.remove(output)
        print('[*] Removed old dataset')
    # Process each pcap file
    files = {
        'normal_traffic.pcap': 'NORMAL',
        'ddos_traffic.pcap': 'DDOS',
        'syn_flood.pcap': 'SYN_FLOOD',
        'port_scan.pcap': 'PORT_SCAN',
        'brute_force.pcap': 'BRUTE_FORCE'
    }
    print('[*] Starting feature extraction...')
    print('='*50)
    for pcap_file, label in files.items():
        full_path = os.path.join(pcap_dir, pcap_file)
        if os.path.exists(full_path):
            print(f'[*] Processing {pcap_file} as {label}...')
            extract_features(full_path, label, output)
        else:
            print(f'[-] File not found: {pcap_file}')
    print('='*50)
    print(f'[+] Dataset saved to: {output}')
    print('[+] Feature extraction complete!')
