from collections import Counter, defaultdict
import ipaddress
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


def top_ips(counter: Counter, limit: int = 10):
    return [{"ip": ip, "count": count} for ip, count in counter.most_common(limit)]


def top_ports(counter: Counter, limit: int = 10):
    return [
        {
            "port": port,
            "count": count,
            "label": COMMON_SERVICE_PORTS.get(port, SUSPICIOUS_PORTS.get(port, "Unknown"))
        }
        for port, count in counter.most_common(limit)
    ]


def flagged_ports(counter: Counter, limit: int = 10):
    flagged = []

    for port, count in counter.most_common():
        if port in SUSPICIOUS_PORTS:
            flagged.append({
                "port": port,
                "count": count,
                "label": SUSPICIOUS_PORTS[port],
                "severity": "high"
            })
        elif port not in COMMON_SERVICE_PORTS and port > 1024 and count >= 50:
            flagged.append({
                "port": port,
                "count": count,
                "label": "Uncommon high port",
                "severity": "medium"
            })

    return flagged[:limit]


def top_conversations(counter: Counter, limit: int = 12):
    results = []
    for conversation, count in counter.most_common(limit):
        src, dst = conversation.split(" -> ", maxsplit=1)
        results.append({
            "conversation": conversation,
            "src": src,
            "dst": dst,
            "count": count
        })
    return results


def classify_port(port: int):
    if 0 <= port <= 1023:
        return "well_known"
    if 1024 <= port <= 49151:
        return "registered"
    if 49152 <= port <= 65535:
        return "dynamic"
    return "unknown"


def is_internal_ip(ip_text: str):
    try:
        ip_obj = ipaddress.ip_address(ip_text)
    except ValueError:
        return False

    return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local


def is_multicast_ip(ip_text: str):
    try:
        return ipaddress.ip_address(ip_text).is_multicast
    except ValueError:
        return False


def is_broadcast_ipv4(ip_text: str):
    if ip_text == "255.255.255.255":
        return True

    # Directed broadcast heuristic for IPv4.
    return ip_text.count(".") == 3 and ip_text.endswith(".255")


def summarize_packet_sizes(packet_sizes):
    if not packet_sizes:
        return {
            "min": 0,
            "max": 0,
            "avg": 0,
            "p50": 0,
            "p95": 0,
        }

    ordered = sorted(packet_sizes)
    total = len(ordered)

    def percentile(percent):
        index = max(0, min(total - 1, int((total - 1) * percent)))
        return ordered[index]

    return {
        "min": ordered[0],
        "max": ordered[-1],
        "avg": round(sum(ordered) / total, 2),
        "p50": percentile(0.50),
        "p95": percentile(0.95),
    }


def related_ports(ip_port_counters: dict, src_ips: Counter, dst_ips: Counter):
    top_ip_set = {ip for ip, _ in src_ips.most_common(20)}
    top_ip_set.update(ip for ip, _ in dst_ips.most_common(20))

    results = {}
    for ip in top_ip_set:
        counter = ip_port_counters.get(ip)
        if not counter:
            continue

        results[ip] = [
            {
                "port": port,
                "count": count,
                "label": COMMON_SERVICE_PORTS.get(port, SUSPICIOUS_PORTS.get(port, "Unknown"))
            }
            for port, count in counter.most_common(12)
        ]

    return results


def analyze_pcap(file_path: str):
    packets = rdpcap(file_path)

    src_ips = Counter()
    dst_ips = Counter()
    protocols = Counter()
    ports = Counter()
    tcp_count = 0
    udp_count = 0
    packet_sizes = []
    port_class_counts = Counter()
    ip_scope_counts = Counter()
    multicast_count = 0
    broadcast_count = 0
    destination_pairs = Counter()

    protocol_keys = ("ALL", "TCP", "UDP")
    src_by_protocol = {key: Counter() for key in protocol_keys}
    dst_by_protocol = {key: Counter() for key in protocol_keys}
    ports_by_protocol = {key: Counter() for key in protocol_keys}
    conversations_by_protocol = {key: Counter() for key in protocol_keys}
    ip_ports_by_protocol = {key: defaultdict(Counter) for key in protocol_keys}

    for packet in packets:
        packet_sizes.append(len(packet))
        protocol = get_protocol_name(packet)
        scoped_protocols = ["ALL"]
        if protocol in {"TCP", "UDP"}:
            scoped_protocols.append(protocol)

        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            src_ips[src_ip] += 1
            dst_ips[dst_ip] += 1
            destination_pairs[f"{src_ip} -> {dst_ip}"] += 1

            src_is_internal = is_internal_ip(src_ip)
            dst_is_internal = is_internal_ip(dst_ip)

            if src_is_internal and dst_is_internal:
                ip_scope_counts["internal_to_internal"] += 1
            elif src_is_internal and not dst_is_internal:
                ip_scope_counts["internal_to_external"] += 1
            elif not src_is_internal and dst_is_internal:
                ip_scope_counts["external_to_internal"] += 1
            else:
                ip_scope_counts["external_to_external"] += 1

            if is_multicast_ip(dst_ip):
                multicast_count += 1
            if is_broadcast_ipv4(dst_ip):
                broadcast_count += 1

            for scope in scoped_protocols:
                src_by_protocol[scope][src_ip] += 1
                dst_by_protocol[scope][dst_ip] += 1
                conversations_by_protocol[scope][f"{src_ip} -> {dst_ip}"] += 1

        protocols[protocol] += 1

        if packet.haslayer(TCP):
            tcp_count += 1
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            ports[dport] += 1

            for scope in scoped_protocols:
                ports_by_protocol[scope][dport] += 1

            port_class_counts[classify_port(dport)] += 1

            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                for scope in scoped_protocols:
                    ip_ports_by_protocol[scope][src_ip][sport] += 1
                    ip_ports_by_protocol[scope][dst_ip][dport] += 1
        elif packet.haslayer(UDP):
            udp_count += 1
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            ports[dport] += 1

            for scope in scoped_protocols:
                ports_by_protocol[scope][dport] += 1

            port_class_counts[classify_port(dport)] += 1

            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                for scope in scoped_protocols:
                    ip_ports_by_protocol[scope][src_ip][sport] += 1
                    ip_ports_by_protocol[scope][dst_ip][dport] += 1

    total_packets = len(packets)

    tcp_percentage = round((tcp_count / total_packets) * 100, 2) if total_packets else 0
    udp_percentage = round((udp_count / total_packets) * 100, 2) if total_packets else 0

    top_source_all = top_ips(src_by_protocol["ALL"], limit=10)
    top_destination_all = top_ips(dst_by_protocol["ALL"], limit=10)
    top_ports_all = top_ports(ports_by_protocol["ALL"], limit=10)
    flagged_all = flagged_ports(ports_by_protocol["ALL"], limit=10)

    drilldown = {
        "top_source_ips_by_protocol": {
            key: top_ips(src_by_protocol[key], limit=15)
            for key in protocol_keys
        },
        "top_destination_ips_by_protocol": {
            key: top_ips(dst_by_protocol[key], limit=15)
            for key in protocol_keys
        },
        "top_ports_by_protocol": {
            key: top_ports(ports_by_protocol[key], limit=15)
            for key in protocol_keys
        },
        "flagged_ports_by_protocol": {
            key: flagged_ports(ports_by_protocol[key], limit=15)
            for key in protocol_keys
        },
        "conversations_by_protocol": {
            key: top_conversations(conversations_by_protocol[key], limit=15)
            for key in protocol_keys
        },
        "ip_related_ports_by_protocol": {
            key: related_ports(ip_ports_by_protocol[key], src_by_protocol[key], dst_by_protocol[key])
            for key in protocol_keys
        },
    }

    top_destination_pairs = []
    for pair, count in destination_pairs.most_common(10):
        src, dst = pair.split(" -> ", maxsplit=1)
        top_destination_pairs.append({
            "src": src,
            "dst": dst,
            "count": count,
        })

    ip_scope_breakdown = {
        "internal_to_internal": ip_scope_counts["internal_to_internal"],
        "internal_to_external": ip_scope_counts["internal_to_external"],
        "external_to_internal": ip_scope_counts["external_to_internal"],
        "external_to_external": ip_scope_counts["external_to_external"],
    }

    return {
        "total_packets": total_packets,
        "tcp_percentage": tcp_percentage,
        "udp_percentage": udp_percentage,
        "top_source_ips": top_source_all,
        "top_destination_ips": top_destination_all,
        "protocol_distribution": [{"protocol": proto, "count": count} for proto, count in protocols.items()],
        "top_ports": top_ports_all,
        "flagged_ports": flagged_all,
        "drilldown": drilldown,
        "port_class_distribution": {
            "well_known": port_class_counts["well_known"],
            "registered": port_class_counts["registered"],
            "dynamic": port_class_counts["dynamic"],
            "unknown": port_class_counts["unknown"],
        },
        "ip_scope_breakdown": ip_scope_breakdown,
        "multicast_packets": multicast_count,
        "broadcast_packets": broadcast_count,
        "packet_size_stats": summarize_packet_sizes(packet_sizes),
        "top_destination_pairs": top_destination_pairs,
    }