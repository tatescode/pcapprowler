from scapy.all import *

getPcapFilePath = input("Please input the full filepath of the PCAP you want to analyze...")

def read_pcap(filepath):
    if filepath.endswith('.pcap') or filepath.endswith('.pcapng'):
        try:
            packets = rdpcap(filepath)
            return packets
        except:
            print("File not found")
    else:
        print("File not readable - must be .pcap or .pcapng")
    
    
