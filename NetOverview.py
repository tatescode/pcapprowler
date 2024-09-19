import scapy

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def parse_pcap(pcap_file):
    """Parse PCAP file and extract relevant features."""
    packets = scapy.rdpcap(pcap_file)
    data = []
    for packet in packets:
        if packet.haslayer(scapy.IP):
            data.append({
                'src': packet[scapy.IP].src,
                'dst': packet[scapy.IP].dst,
                'proto': packet[scapy.IP].proto,
                'len': len(packet),
                'ttl': packet[scapy.IP].ttl
            })
    return pd.DataFrame(data)