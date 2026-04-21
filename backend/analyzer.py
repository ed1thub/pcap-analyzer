from collections import Counter
from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP


def get_protocol_name(packet):
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(IP):
        return "IP"
    return "Other"


def analyze_pcap(file_path: str):
    packets = rdpcap(file_path)

    src_ips = Counter()
    dst_ips = Counter()
    protocols = Counter()
    ports = Counter()

    for packet in packets:
        if packet.haslayer(IP):
            src_ips[packet[IP].src] += 1
            dst_ips[packet[IP].dst] += 1

        protocols[get_protocol_name(packet)] += 1

        if packet.haslayer(TCP):
            ports[packet[TCP].dport] += 1
        elif packet.haslayer(UDP):
            ports[packet[UDP].dport] += 1

    suspicious_ports = []
    interesting_ports = {21, 22, 23, 25, 53, 80, 110, 123, 135, 137, 138, 139, 143, 161, 389, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080}

    for port, count in ports.most_common():
        if port in interesting_ports or port > 1024:
            suspicious_ports.append({
                "port": port,
                "count": count
            })

    return {
        "total_packets": len(packets),
        "top_source_ips": [{"ip": ip, "count": count} for ip, count in src_ips.most_common(5)],
        "top_destination_ips": [{"ip": ip, "count": count} for ip, count in dst_ips.most_common(5)],
        "protocol_distribution": [{"protocol": proto, "count": count} for proto, count in protocols.items()],
        "top_ports": [{"port": port, "count": count} for port, count in ports.most_common(10)],
        "flagged_ports": suspicious_ports[:10]
    }