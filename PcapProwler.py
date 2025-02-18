#!/usr/bin/env python3
import argparse
import os
from collections import defaultdict
from datetime import datetime

from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
def analyze_pcap(pcap_path):
    """Analyze PCAP file and generate insights report."""
    try:
        packets = rdpcap(pcap_path)
    except FileNotFoundError:
        return "Error: PCAP file not found"
    except Exception as e:
        return f"Error reading PCAP file: {str(e)}"

    if not packets:
        return "Error: No packets found in PCAP file"

    # Basic statistics
    file_name = os.path.basename(pcap_path)
    total_packets = len(packets)
    start_time = datetime.fromtimestamp(packets[0].time).strftime('%Y-%m-%d %H:%M:%S')
    end_time = datetime.fromtimestamp(packets[-1].time).strftime('%Y-%m-%d %H:%M:%S')

    # Source IP analysis
    ip_counts = defaultdict(int)
    for pkt in packets:
        if IP in pkt:
            ip_counts[pkt[IP].src] += 1
    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]

    # Protocol distribution
    proto_counts = {'TCP': 0, 'UDP': 0, 'ICMP': 0}
    for pkt in packets:
        if TCP in pkt:
            proto_counts['TCP'] += 1
        elif UDP in pkt:
            proto_counts['UDP'] += 1
        elif ICMP in pkt:
            proto_counts['ICMP'] += 1

    # Anomaly detection
    anomalies = []
    
    # Port analysis
    port_traffic = defaultdict(int)
    src_port_map = defaultdict(lambda: defaultdict(int))
    for pkt in packets:
        if IP in pkt:
            src_ip = pkt[IP].src
            if TCP in pkt:
                port = pkt[TCP].dport
                port_traffic[port] += 1
                src_port_map[src_ip][port] += 1
            elif UDP in pkt:
                port = pkt[UDP].dport
                port_traffic[port] += 1
                src_port_map[src_ip][port] += 1

    suspicious_ports = {4444: 'Common exploit/Metasploit', 
                        23: 'Telnet', 
                        22: 'SSH brute-force potential',
                        3389: 'RDP access'}
    
    for src_ip, ports in src_port_map.items():
        for port, count in ports.items():
            if port in suspicious_ports and count > 500:
                anomalies.append(
                    f"High traffic from {src_ip} to {suspicious_ports[port]} port {port} ({count} packets)"
                )

    # ICMP spike detection
    icmp_times = [pkt.time for pkt in packets if ICMP in pkt]
    time_bins = defaultdict(int)
    for t in icmp_times:
        bin_key = datetime.fromtimestamp(t).strftime('%Y-%m-%d %H:%M')
        time_bins[bin_key] += 1
    
    if time_bins:
        max_bin = max(time_bins, key=time_bins.get)
        max_count = time_bins[max_bin]
        if max_count > 100 and max_count > 2 * (sum(time_bins.values())/len(time_bins)):
            anomalies.append(
                f"ICMP traffic spike ({max_count} packets) at {max_bin}:00"
            )

    # Generate report
    report = [
        "NetOverview Analysis Report",
        "-" * 28,
        f"File: {file_name}",
        f"Packets Analyzed: {total_packets:,}",
        f"Time Range: {start_time} - {end_time}",
        "\nTop 5 Source IPs:"
    ]
    
    for i, (ip, count) in enumerate(top_ips, 1):
        report.append(f"{i}. {ip} ({count:,} packets)")

    report.append("\nProtocol Distribution:")
    total = sum(proto_counts.values())
    for proto, count in proto_counts.items():
        if total > 0:
            percentage = (count / total) * 100
            report.append(f"- {proto}: {percentage:.1f}%")

    report.append("\nUnusual Patterns Detected:")
    if anomalies:
        for anomaly in anomalies[:3]:  # Show top 3 anomalies
            report.append(f"- {anomaly}")
    else:
        report.append("- No significant anomalies detected")

    return "\n".join(report)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Network Traffic Analysis Tool')
    parser.add_argument('pcap_file', help='Path to PCAP file for analysis')
    args = parser.parse_args()
    
    print(analyze_pcap(args.pcap_file))
