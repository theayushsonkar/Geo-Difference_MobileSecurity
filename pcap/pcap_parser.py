"""
pcap_parser.py
--------------
Parses PCAP files into normalized event records for network analysis.
"""

import socket
import logging
from dataclasses import dataclass, field
from pathlib import Path
import dpkt

# Setup logger
logger = logging.getLogger("pcap_parser")

@dataclass
class RawEvent:
    """Normalized network event parsed from a raw packet."""
    timestamp: float = 0.0
    event_type: str = ""  # dns, tls, http, tcp, udp
    domain: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: str = ""
    payload_size: int = 0
    dns_query: str = ""
    dns_response_ips: list[str] = field(default_factory=list)
    tls_sni: str = ""
    http_host: str = ""
    is_dns: bool = False
    is_tls: bool = False
    is_http: bool = False
    is_quic: bool = False


def _ip_to_string(ip_bytes: bytes) -> str:
    """Converts IP bytes to standard string format."""
    try:
        return socket.inet_ntoa(ip_bytes)
    except Exception:
        return ""


def _dns_name_to_str(name) -> str:
    """Safely converts DNS query/record name to a string."""
    if isinstance(name, bytes):
        return name.decode("utf-8", errors="ignore")
    return str(name)


def _clean_http_host(host: str) -> str:
    """Cleans Host header by stripping port suffixes and lowercasing."""
    host = host.strip()
    if host.startswith("[") and "]" in host:
        # IPv6 address in brackets: [2001:db8::1]:80
        parts = host.split("]")
        ip_part = parts[0] + "]"
        return ip_part.lower()
    else:
        # Standard domain or IPv4
        return host.split(":")[0].lower()



def _extract_dns(payload: bytes) -> tuple[str, list[str]]:
    """Attempts to parse payload as a DNS packet, returning query name and response IPs."""
    dns = dpkt.dns.DNS(payload)
    query_name = ""
    if dns.qd:
        query_name = _dns_name_to_str(dns.qd[0].name)
        
    response_ips = []
    for answer in dns.an:
        if answer.type == dpkt.dns.DNS_A:
            try:
                response_ips.append(socket.inet_ntoa(answer.rdata))
            except Exception:
                pass
        elif answer.type == dpkt.dns.DNS_AAAA:
            try:
                response_ips.append(socket.inet_ntop(socket.AF_INET6, answer.rdata))
            except Exception:
                pass
    return query_name, response_ips


def _extract_tls_sni(payload: bytes) -> str:
    """Attempts to parse payload as TLS ClientHello to extract the SNI domain name."""
    # 1. Attempt using dpkt.ssl
    try:
        tls = dpkt.ssl.TLS(payload)
        for r in tls.records:
            if r.type == 22:  # Handshake
                handshake = dpkt.ssl.TLSHandshake(r.data)
                if handshake.type == 1:  # ClientHello
                    ch = handshake.data
                    if hasattr(ch, "extensions"):
                        for ext_id, ext_val in ch.extensions:
                            if ext_id == 0:  # Server Name
                                if len(ext_val) >= 5:
                                    pos = 2
                                    while pos + 3 <= len(ext_val):
                                        name_type = ext_val[pos]
                                        name_len = int.from_bytes(
                                            ext_val[pos + 1 : pos + 3], "big"
                                        )
                                        pos += 3
                                        if pos + name_len <= len(ext_val):
                                            if name_type == 0:  # host_name
                                                return ext_val[
                                                    pos : pos + name_len
                                                ].decode("utf-8", errors="ignore")
                                        pos += name_len
    except Exception:
        pass

    # 2. Fallback to manual parsing (robust to packet fragmentation / grease handshake types)
    try:
        if len(payload) >= 5 and payload[0] == 0x16:
            pos = 5
            if pos + 4 <= len(payload):
                handshake_type = payload[pos]
                if handshake_type == 1:  # ClientHello
                    pos += 4
                    if pos + 34 <= len(payload):
                        pos += 2  # version
                        pos += 32  # random
                        session_id_len = payload[pos]
                        pos += 1 + session_id_len
                        if pos + 2 <= len(payload):
                            cipher_suites_len = int.from_bytes(
                                payload[pos : pos + 2], "big"
                            )
                            pos += 2 + cipher_suites_len
                            if pos + 1 <= len(payload):
                                comp_len = payload[pos]
                                pos += 1 + comp_len
                                if pos + 2 <= len(payload):
                                    extensions_len = int.from_bytes(
                                        payload[pos : pos + 2], "big"
                                    )
                                    pos += 2
                                    while pos + 4 <= len(payload):
                                        ext_type = int.from_bytes(
                                            payload[pos : pos + 2], "big"
                                        )
                                        ext_len = int.from_bytes(
                                            payload[pos + 2 : pos + 4], "big"
                                        )
                                        pos += 4
                                        if ext_type == 0:
                                            ext_data = payload[pos : pos + ext_len]
                                            if len(ext_data) >= 5:
                                                name_type = ext_data[2]
                                                name_len = int.from_bytes(
                                                    ext_data[3:5], "big"
                                                )
                                                if (
                                                    name_type == 0
                                                    and len(ext_data)
                                                    >= 5 + name_len
                                                ):
                                                    return ext_data[
                                                        5 : 5 + name_len
                                                    ].decode(
                                                        "utf-8", errors="ignore"
                                                    )
                                        pos += ext_len
    except Exception:
        pass

    return ""


def _extract_http_host(payload: bytes) -> str:
    """Attempts to parse payload as cleartext HTTP Request to extract the Host header."""
    try:
        req = dpkt.http.Request(payload)
        host = req.headers.get("host", "")
        if host:
            return _clean_http_host(host)
    except Exception:
        pass
    return ""


def parse_pcap(path: Path) -> list[RawEvent]:
    """Parses a PCAP file and returns a list of normalized RawEvent objects."""
    events: list[RawEvent] = []

    total_packets = 0
    dns_count = 0
    tls_count = 0
    http_count = 0
    tcp_count = 0
    udp_count = 0
    parse_errors = 0

    try:
        f = open(path, "rb")
    except Exception as e:
        logger.error("Failed to open PCAP file: %s. Error: %s", path, e)
        return []

    try:
        pcap = dpkt.pcap.Reader(f)
        logger.info("PCAP opened: %s", path)
    except Exception as e:
        logger.error("Failed to initialize PCAP reader: %s", e)
        f.close()
        return []

    try:
        for ts, buf in pcap:
            total_packets += 1
            try:
                ip = None
                # Attempt to parse directly as raw IP packet (DLT_RAW)
                try:
                    parsed_ip = dpkt.ip.IP(buf)
                    if parsed_ip.v == 4:
                        ip = parsed_ip
                except Exception:
                    pass

                # Fallback to Ethernet framing
                if ip is None:
                    try:
                        eth = dpkt.ethernet.Ethernet(buf)
                        if isinstance(eth.data, dpkt.ip.IP) and eth.data.v == 4:
                            ip = eth.data
                    except Exception:
                        pass

                # If we couldn't parse a valid IPv4 layer, skip the packet
                if ip is None:
                    continue

                src_ip = _ip_to_string(ip.src)
                dst_ip = _ip_to_string(ip.dst)

                if not src_ip or not dst_ip:
                    continue

                # Prepare common event attributes
                event_type = ""
                domain = ""
                dns_query = ""
                dns_response_ips = []
                tls_sni = ""
                http_host = ""
                is_dns = False
                is_tls = False
                is_http = False
                is_quic = False
                
                src_port = 0
                dst_port = 0
                protocol = ""
                payload_len = 0

                # Check transport protocol
                if isinstance(ip.data, dpkt.tcp.TCP):
                    protocol = "TCP"
                    tcp = ip.data
                    src_port = tcp.sport
                    dst_port = tcp.dport
                    payload_len = len(tcp.data)

                    # DNS over TCP check
                    if src_port == 53 or dst_port == 53:
                        try:
                            dns_query, dns_response_ips = _extract_dns(tcp.data)
                            if dns_query:
                                event_type = "dns"
                                is_dns = True
                                dns_count += 1
                        except Exception:
                            pass

                    # TLS ClientHello / SNI check
                    if not event_type and payload_len > 0:
                        sni = _extract_tls_sni(tcp.data)
                        if sni:
                            event_type = "tls"
                            is_tls = True
                            tls_sni = sni
                            tls_count += 1

                    # Cleartext HTTP Host check
                    if not event_type and (dst_port in [80, 8080, 8008] or src_port in [80, 8080, 8008]) and payload_len > 0:
                        host = _extract_http_host(tcp.data)
                        if host:
                            event_type = "http"
                            is_http = True
                            http_host = host
                            http_count += 1

                    # Fallback to generic TCP event
                    if not event_type:
                        event_type = "tcp"
                        tcp_count += 1

                elif isinstance(ip.data, dpkt.udp.UDP):
                    protocol = "UDP"
                    udp = ip.data
                    src_port = udp.sport
                    dst_port = udp.dport
                    payload_len = len(udp.data)

                    # DNS over UDP check
                    if src_port == 53 or dst_port == 53:
                        try:
                            dns_query, dns_response_ips = _extract_dns(udp.data)
                            if dns_query:
                                event_type = "dns"
                                is_dns = True
                                dns_count += 1
                        except Exception:
                            pass

                    # QUIC Detection (UDP port 443)
                    if dst_port == 443 or src_port == 443:
                        is_quic = True

                    # Fallback to generic UDP event
                    if not event_type:
                        event_type = "udp"
                        udp_count += 1

                else:
                    # Ignore non-TCP/UDP packets
                    continue

                # Determine domain using the priority: TLS SNI -> HTTP Host -> DNS Query -> empty
                if tls_sni:
                    domain = tls_sni
                elif http_host:
                    domain = http_host
                elif dns_query:
                    domain = dns_query
                else:
                    domain = ""

                # Create and record the event
                event = RawEvent(
                    timestamp=ts,
                    event_type=event_type,
                    domain=domain,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                    payload_size=payload_len,
                    dns_query=dns_query,
                    dns_response_ips=dns_response_ips,
                    tls_sni=tls_sni,
                    http_host=http_host,
                    is_dns=is_dns,
                    is_tls=is_tls,
                    is_http=is_http,
                    is_quic=is_quic,
                )
                events.append(event)

            except Exception as e:
                parse_errors += 1
                logger.warning("Error parsing packet %d: %s", total_packets, e)
                continue
    finally:
        f.close()

    logger.info(
        "Parsing complete. Packets: %d, DNS: %d, TLS: %d, HTTP: %d, TCP: %d, UDP: %d, Errors: %d",
        total_packets, dns_count, tls_count, http_count, tcp_count, udp_count, parse_errors
    )

    return events
