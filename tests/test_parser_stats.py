import sys
import socket
from pathlib import Path
from collections import Counter
from pprint import pprint
import dpkt

# Add workspace directory to path
workspace_dir = Path(r"d:\New folder\Geo-Difference_MobileSecurity")
sys.path.append(str(workspace_dir))

from pcap.pcap_parser import (
    parse_pcap, RawEvent, _ip_to_string, _extract_tls_sni, _extract_http_host, _dns_name_to_str
)

pcap_path = workspace_dir / "data" / "pcap" / "arrow_escape.pcap"

print("="*60)
print("Part 1 & 2 & 3 & 4 & 5 & 6 & 8 & 9: Parser Verification Analysis")
print("="*60)

# Check errors by re-running a tracking pass
total_packets = 0
dns_events_count = 0
tls_events_count = 0
http_events_count = 0
tcp_events_count = 0
udp_events_count = 0

dns_parse_errors = 0
tls_parse_errors = 0
http_parse_errors = 0
packet_parse_errors = 0

with open(pcap_path, "rb") as f:
    try:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            total_packets += 1
            ip = None
            try:
                # DLT_RAW check
                try:
                    parsed_ip = dpkt.ip.IP(buf)
                    if parsed_ip.v == 4:
                        ip = parsed_ip
                except Exception:
                    pass
                
                # Ethernet fallback
                if ip is None:
                    try:
                        eth = dpkt.ethernet.Ethernet(buf)
                        if isinstance(eth.data, dpkt.ip.IP) and eth.data.v == 4:
                            ip = eth.data
                    except Exception:
                        pass
                
                if ip is None:
                    continue

                if isinstance(ip.data, dpkt.tcp.TCP):
                    tcp = ip.data
                    src_port = tcp.sport
                    dst_port = tcp.dport
                    payload_len = len(tcp.data)
                    
                    # DNS check
                    if src_port == 53 or dst_port == 53:
                        try:
                            # Try parsing
                            dpkt.dns.DNS(tcp.data)
                            dns_events_count += 1
                        except Exception:
                            dns_parse_errors += 1
                    
                    # TLS check
                    is_tls_attempt = False
                    if payload_len > 0 and len(tcp.data) >= 5 and tcp.data[0] == 0x16:
                        is_tls_attempt = True
                        try:
                            tls = dpkt.ssl.TLS(tcp.data)
                            for r in tls.records:
                                if r.type == 22:
                                    handshake = dpkt.ssl.TLSHandshake(r.data)
                                    if handshake.type == 1:
                                        tls_events_count += 1
                        except Exception:
                            tls_parse_errors += 1
                    
                    # HTTP check
                    if (dst_port in [80, 8080, 8008] or src_port in [80, 8080, 8008]) and payload_len > 0:
                        try:
                            dpkt.http.Request(tcp.data)
                            http_events_count += 1
                        except Exception:
                            http_parse_errors += 1
                            
                elif isinstance(ip.data, dpkt.udp.UDP):
                    udp = ip.data
                    src_port = udp.sport
                    dst_port = udp.dport
                    
                    # DNS check
                    if src_port == 53 or dst_port == 53:
                        try:
                            dpkt.dns.DNS(udp.data)
                            dns_events_count += 1
                        except Exception:
                            dns_parse_errors += 1

            except Exception as e:
                packet_parse_errors += 1
    except Exception as e:
        print(f"Error opening PCAP file: {e}")

# Run parser normally
events = parse_pcap(pcap_path)

# --- Part 1: Stats ---
total_events = len(events)
event_types = Counter(e.event_type for e in events)
quic_events = sum(1 for e in events if e.is_quic)
events_with_domain = sum(1 for e in events if e.domain != "")
events_without_domain = sum(1 for e in events if e.domain == "")
unique_domains = len(set(e.domain for e in events if e.domain != ""))
unique_dst_ips = len(set(e.dst_ip for e in events if e.dst_ip != ""))

print(f"Total Packets Processed: {total_packets}")
print(f"Total Events Extracted: {total_events}")
print(f"DNS Events: {event_types['dns']}")
print(f"TLS Events: {event_types['tls']}")
print(f"HTTP Events: {event_types['http']}")
print(f"TCP Events: {event_types['tcp']}")
print(f"UDP Events: {event_types['udp']}")
print(f"QUIC Events: {quic_events}")
print(f"Events with Domain: {events_with_domain}")
print(f"Events without Domain: {events_without_domain}")
print(f"Unique Domains: {unique_domains}")
print(f"Unique Destination IPs: {unique_dst_ips}")

# --- Part 2: Show Sample Events ---
print("\n" + "="*40)
print("Part 2 — First 20 Events")
print("="*40)
for idx, e in enumerate(events[:20]):
    print(f"Event {idx+1}: type={e.event_type}, domain={e.domain!r}, dst_ip={e.dst_ip}, dst_port={e.dst_port}, protocol={e.protocol}")

# --- Part 3: DNS Validation ---
print("\n" + "="*40)
print("Part 3 — First 20 DNS Events")
print("="*40)
dns_events = [e for e in events if e.is_dns]
for idx, e in enumerate(dns_events[:20]):
    print(f"DNS {idx+1}: query={e.dns_query!r}, response_ips={e.dns_response_ips}, dst_ip={e.dst_ip}")

# --- Part 4: TLS SNI Validation ---
print("\n" + "="*40)
print("Part 4 — First 50 TLS Events")
print("="*40)
tls_events = [e for e in events if e.is_tls]
for idx, e in enumerate(tls_events[:50]):
    print(f"TLS {idx+1}: sni={e.tls_sni!r}, domain={e.domain!r}, dst_ip={e.dst_ip}")

tls_total = len(tls_events)
tls_with_sni = sum(1 for e in tls_events if e.tls_sni != "")
tls_success_rate = (tls_with_sni / tls_total * 100) if tls_total > 0 else 0.0

print(f"\nTLS Events Total: {tls_total}")
print(f"TLS Events with SNI: {tls_with_sni}")
print(f"TLS Success Rate: {tls_success_rate:.2f}%")

# --- Part 5: Domain Quality Check ---
print("\n" + "="*40)
print("Part 5 — Top 50 Domains")
print("="*40)
domain_counts = Counter(e.domain for e in events if e.domain != "")
for idx, (dom, count) in enumerate(domain_counts.most_common(50), 1):
    print(f"{idx:2d}. {dom}: {count}")

# --- Part 6: QUIC Validation ---
print("\n" + "="*40)
print("Part 6 — First 20 QUIC Events")
print("="*40)
quic_events_list = [e for e in events if e.is_quic]
for idx, e in enumerate(quic_events_list[:20]):
    print(f"QUIC {idx+1}: protocol={e.protocol}, port={e.dst_port}, src={e.src_ip}, dst={e.dst_ip}")

# --- Part 8: Error Analysis ---
print("\n" + "="*40)
print("Part 8 — Error Analysis")
print("="*40)
pct_packet = (packet_parse_errors / total_packets * 100) if total_packets > 0 else 0.0
pct_dns = (dns_parse_errors / total_packets * 100) if total_packets > 0 else 0.0
pct_tls = (tls_parse_errors / total_packets * 100) if total_packets > 0 else 0.0
pct_http = (http_parse_errors / total_packets * 100) if total_packets > 0 else 0.0

print(f"Total Packets Checked for Sub-parsers: {total_packets}")
print(f"Packet Parse Errors: {packet_parse_errors} ({pct_packet:.2f}%)")
print(f"DNS Parse Errors: {dns_parse_errors} ({pct_dns:.2f}%)")
print(f"TLS Parse Errors: {tls_parse_errors} ({pct_tls:.2f}%)")
print(f"HTTP Parse Errors: {http_parse_errors} ({pct_http:.2f}%)")

# --- Part 9: Coverage Analysis ---
print("\n" + "="*40)
print("Part 9 — Coverage Analysis")
print("="*40)
represented_packets = total_events
coverage_pct = (represented_packets / total_packets * 100) if total_packets > 0 else 0.0
print(f"Total Packets in PCAP: {total_packets}")
print(f"Packets Represented by Events: {represented_packets}")
print(f"Coverage %: {coverage_pct:.2f}%")
