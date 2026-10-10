#!/usr/bin/env python3
import dpkt
import csv
import os
from collections import defaultdict

PCAP_DIR = '/home/animesh/Desktop/network_threat_detection/pcap_files'
OUTPUT = '/home/animesh/Desktop/network_threat_detection/dataset/network_data.csv'

files = {
    'normal_traffic.pcap': 'NORMAL',
    'ddos_traffic.pcap': 'DDOS',
    'syn_flood.pcap': 'SYN_FLOOD',
    'port_scan.pcap': 'PORT_SCAN',
    'brute_force.pcap': 'BRUTE_FORCE'
}

def parse_packet(buf):
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
        try:
            ip = dpkt.ip.IP(buf)
        except:
            pass
    return ip

fieldnames = [
    'flow_duration',
    'total_packets',
    'total_bytes',
    'avg_packet_size',
    'std_packet_size',
    'min_packet_size',
    'max_packet_size',
    'bytes_per_second',
    'packets_per_second',
    'syn_count',
    'ack_count',
    'fin_count',
    'rst_count',
    'syn_ratio',
    'ack_ratio',
    'unique_dst_ports',
    'protocol',
    'avg_ttl',
    'label'
]

print(f'Writing to: {OUTPUT}')
csvfile = open(OUTPUT, 'w', newline='')
writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
writer.writeheader()

total_flows = 0
FLOW_TIMEOUT = 5.0      # seconds - group packets into flows by time window
MAX_FLOWS = 60000       # max flows per attack type

for pcap_file, label in files.items():
    full_path = os.path.join(PCAP_DIR, pcap_file)
    if not os.path.exists(full_path):
        print(f'SKIPPING {pcap_file} - file not found')
        continue

    print(f'\nProcessing {pcap_file} → label: {label}')

    # flows dict: key = (src_ip, dst_ip, src_port, dst_port, proto)
    # value = list of (timestamp, pkt_len, flags, ttl, dst_port)
    flows = defaultdict(list)

    try:
        with open(full_path, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            pkt_count = 0

            for ts, buf in pcap:
                try:
                    ip = parse_packet(buf)
                    if ip is None:
                        continue

                    proto = ip.p
                    pkt_len = len(buf)
                    ttl = ip.ttl
                    src_port = dst_port = 0
                    syn = ack = fin = rst = 0

                    src_ip = str(ip.src)
                    dst_ip = str(ip.dst)

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

                    flow_key = (src_ip, dst_ip, src_port, dst_port, proto)
                    flows[flow_key].append((ts, pkt_len, syn, ack, fin, rst, ttl, dst_port))

                    pkt_count += 1
                    if pkt_count % 500000 == 0:
                        print(f'  Packets read: {pkt_count}, Flows so far: {len(flows)}')

                except Exception:
                    continue

    except Exception as e:
        print(f'  Error reading {pcap_file}: {e}')
        continue

    print(f'  Total packets read: {pkt_count}')
    print(f'  Total raw flows: {len(flows)}')

    # Now compute flow-level features
    flow_count = 0
    for flow_key, packets in flows.items():
        if flow_count >= MAX_FLOWS:
            break

        if len(packets) < 2:
            # Single packet flows are noise, skip
            continue

        # Sort by timestamp
        packets.sort(key=lambda x: x[0])

        timestamps   = [p[0] for p in packets]
        pkt_sizes    = [p[1] for p in packets]
        syn_flags    = [p[2] for p in packets]
        ack_flags    = [p[3] for p in packets]
        fin_flags    = [p[4] for p in packets]
        rst_flags    = [p[5] for p in packets]
        ttls         = [p[6] for p in packets]
        dst_ports    = [p[7] for p in packets]

        flow_duration = timestamps[-1] - timestamps[0]
        if flow_duration == 0:
            flow_duration = 0.0001  # avoid division by zero

        total_packets   = len(packets)
        total_bytes     = sum(pkt_sizes)
        avg_pkt_size    = total_bytes / total_packets
        min_pkt_size    = min(pkt_sizes)
        max_pkt_size    = max(pkt_sizes)

        # Standard deviation of packet sizes
        mean = avg_pkt_size
        std_pkt_size = (sum((x - mean) ** 2 for x in pkt_sizes) / total_packets) ** 0.5

        bytes_per_sec   = total_bytes / flow_duration
        pkts_per_sec    = total_packets / flow_duration

        syn_count = sum(syn_flags)
        ack_count = sum(ack_flags)
        fin_count = sum(fin_flags)
        rst_count = sum(rst_flags)

        syn_ratio = syn_count / total_packets
        ack_ratio = ack_count / total_packets

        unique_dst_ports = len(set(dst_ports))
        avg_ttl          = sum(ttls) / total_packets
        protocol         = flow_key[4]

        writer.writerow({
            'flow_duration':     round(flow_duration, 6),
            'total_packets':     total_packets,
            'total_bytes':       total_bytes,
            'avg_packet_size':   round(avg_pkt_size, 2),
            'std_packet_size':   round(std_pkt_size, 2),
            'min_packet_size':   min_pkt_size,
            'max_packet_size':   max_pkt_size,
            'bytes_per_second':  round(bytes_per_sec, 2),
            'packets_per_second':round(pkts_per_sec, 2),
            'syn_count':         syn_count,
            'ack_count':         ack_count,
            'fin_count':         fin_count,
            'rst_count':         rst_count,
            'syn_ratio':         round(syn_ratio, 4),
            'ack_ratio':         round(ack_ratio, 4),
            'unique_dst_ports':  unique_dst_ports,
            'protocol':          protocol,
            'avg_ttl':           round(avg_ttl, 2),
            'label':             label
        })

        flow_count += 1
        total_flows += 1

    print(f'  Flows written for {label}: {flow_count}')

csvfile.close()
print(f'\nTotal flows written: {total_flows}')
print(f'Saved to: {OUTPUT}')
print('DONE!')
