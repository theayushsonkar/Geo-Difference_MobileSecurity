import sys
from pathlib import Path
from collections import Counter

# Add workspace directory to path
workspace_dir = Path(r"d:\New folder\Geo-Difference_MobileSecurity")
sys.path.append(str(workspace_dir))

from pcap.pcap_parser import parse_pcap

pcap_path = workspace_dir / "data" / "pcap" / "arrow_escape.pcap"

print("="*60)
# Run parser normally
events = parse_pcap(pcap_path)
print("="*60)

# Filter UDP events (all events where protocol == 'UDP')
udp_events = [e for e in events if e.protocol == 'UDP']
quic_events = [e for e in events if e.is_quic]

# Check validation rule: protocol == UDP and (src_port == 443 or dst_port == 443)
invalid_quic = []
for e in events:
    if e.is_quic:
        if e.protocol != 'UDP' or (e.src_port != 443 and e.dst_port != 443):
            invalid_quic.append(e)

print(f"Total UDP events: {len(udp_events)}")
print(f"Total QUIC events: {len(quic_events)}")
print(f"Invalid QUIC events (not matching validation rule): {len(invalid_quic)}")

print("\n" + "="*40)
print("Top 30 UDP Port Pairs (src_port -> dst_port)")
print("="*40)

port_pair_counts = Counter((e.src_port, e.dst_port) for e in udp_events)
for idx, ((sport, dport), count) in enumerate(port_pair_counts.most_common(30), 1):
    print(f"{idx:2d}. {sport} -> {dport} : {count}")
