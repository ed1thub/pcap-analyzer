from scapy.all import rdpcap


def analyze_pcap(file_path: str):
    packets = rdpcap(file_path)
    return {
        "total_packets": len(packets)
    }