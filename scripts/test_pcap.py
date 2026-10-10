import dpkt
import os

pcap_file = '/home/animesh/Desktop/network_threat_detection/pcap_files/normal_traffic.pcap'

print(f'File exists: {os.path.exists(pcap_file)}')
print(f'File size: {os.path.getsize(pcap_file)} bytes')

try:
    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        count = 0
        for ts, buf in pcap:
            count += 1
            if count >= 5:
                break
        print(f'Successfully read {count} packets!')
except Exception as e:
    print(f'Error: {e}')
