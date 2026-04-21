from collections import Counter
from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP


SUSPICIOUS_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    69: "TFTP",
    110: "POP3",
    135: "RPC",
    137: "NetBIOS",
    138: "NetBIOS",
    139: "NetBIOS",
    1433: "MSSQL",
    3389: "RDP",
    4444: "Metasploit/Backdoor",
    5555: "ADB/Backdoor",
    5900: "VNC",
    8080: "HTTP-Alt",
}

COMMON_SERVICE_PORTS = {
    53: "DNS",
    80: "HTTP",
    123: "NTP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    993: "IMAPS",
    995: "POP3S",
    143: "IMAP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1900: "SSDP",
}


def get_protocol_name(packet):
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(IP):
        return "IP"
    return "Other"


def analyze_pcap(file_path: str):
    packets = rdpcap(file_path)

    src_ips = Counter()
    dst_ips = Counter()
    protocols = Counter()
    ports = Counter()
    tcp_count = 0
    udp_count = 0

    for packet in packets:
        if packet.haslayer(IP):
            src_ips[packet[IP].src] += 1
            dst_ips[packet[IP].dst] += 1

        protocol = get_protocol_name(packet)
        protocols[protocol] += 1

        if packet.haslayer(TCP):
            tcp_count += 1
            ports[packet[TCP].dport] += 1
        elif packet.haslayer(UDP):
            udp_count += 1
            ports[packet[UDP].dport] += 1

    total_packets = len(packets)

    flagged_ports = []
    for port, count in ports.most_common():
        if port in SUSPICIOUS_PORTS:
            flagged_ports.append({
                "port": port,
                "count": count,
                "label": SUSPICIOUS_PORTS[port],
                "severity": "high"
            })
        elif port not in COMMON_SERVICE_PORTS and port > 1024 and count >= 50:
            flagged_ports.append({
                "port": port,
                "count": count,
                "label": "Uncommon high port",
                "severity": "medium"
            })

    tcp_percentage = round((tcp_count / total_packets) * 100, 2) if total_packets else 0
    udp_percentage = round((udp_count / total_packets) * 100, 2) if total_packets else 0

    return {
        "total_packets": total_packets,
        "tcp_percentage": tcp_percentage,
        "udp_percentage": udp_percentage,
        "top_source_ips": [{"ip": ip, "count": count} for ip, count in src_ips.most_common(5)],
        "top_destination_ips": [{"ip": ip, "count": count} for ip, count in dst_ips.most_common(5)],
        "protocol_distribution": [{"protocol": proto, "count": count} for proto, count in protocols.items()],
        "top_ports": [
            {
                "port": port,
                "count": count,
                "label": COMMON_SERVICE_PORTS.get(port, SUSPICIOUS_PORTS.get(port, "Unknown"))
            }
            for port, count in ports.most_common(10)
        ],
        "flagged_ports": flagged_ports[:10]
    }