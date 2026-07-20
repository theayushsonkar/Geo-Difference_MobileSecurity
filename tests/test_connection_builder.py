import sys
import logging
from pathlib import Path
from collections import Counter
from pprint import pprint

# Setup logging to console
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stdout
)

# Add workspace directory to path
workspace_dir = Path(r"d:\New folder\Geo-Difference_MobileSecurity")
sys.path.append(str(workspace_dir))

from pcap.pcap_parser import parse_pcap
from pcap.connection_builder import ConnectionBuilder
from pcap.network_context import NetworkContext
from pcap.schemas import GeoFact, ASNFact
from unittest.mock import MagicMock

pcap_path = workspace_dir / "data" / "pcap" / "arrow_escape.pcap"

print("="*60)
print("Step 1: Parsing PCAP File")
print("="*60)
events = parse_pcap(pcap_path)

print("\n" + "="*60)
print("Step 2: Initializing GeoMapper and ConnectionBuilder")
print("="*60)
# Mock GeoMapper
geo_mapper_mock = MagicMock()
geo_mapper_mock.lookup_geo.return_value = GeoFact(ip="8.8.8.8", country_code="US", country_name="United States", continent="NA")
geo_mapper_mock.lookup_asn.return_value = ASNFact(ip="8.8.8.8", asn="15169", organization="Google LLC", organization_type="")

network_context = NetworkContext(geo_mapper=geo_mapper_mock)
builder = ConnectionBuilder(network_context=network_context)

print("\n" + "="*60)
print("Step 3: Building Connection, DNS, and Geo Records")
print("="*60)
result = builder.build(events, sample_id="arrow_escape", session_id="session_123")

print("\n" + "="*60)
print("Step 4: Counts and Metrics")
print("="*60)
print(f"ConnectionRecord count: {len(result.connections)}")
print(f"DNSRecord count: {len(result.dns_records)}")
print(f"DomainGeoRecord count: {len(result.domain_geo_records)}")

# Top 20 domains (weighted by connection count or just counts in records)
domain_counts = Counter()
for c in result.connections:
    if c.domain:
        domain_counts[c.domain] += c.connection_count
print("\nTop 20 Domains (by connection count):")
for idx, (dom, count) in enumerate(domain_counts.most_common(20), 1):
    print(f"  {idx:2d}. {dom}: {count}")

# Top 20 countries
country_counts = Counter()
for c in result.connections:
    cc = c.geo_fact.country_code if c.geo_fact else "Unknown"
    country_counts[cc] += c.connection_count
print("\nTop 20 Countries (by connection count):")
for idx, (cc, count) in enumerate(country_counts.most_common(20), 1):
    print(f"  {idx:2d}. {cc}: {count}")

# Top 20 ASNs
asn_counts = Counter()
for c in result.connections:
    asn = c.asn_fact.organization if c.asn_fact else "Unknown"
    asn_counts[asn] += c.connection_count
print("\nTop 20 ASNs (by connection count):")
for idx, (asn, count) in enumerate(asn_counts.most_common(20), 1):
    print(f"  {idx:2d}. {asn}: {count}")

print("\n" + "="*60)
print("Step 5: Sample Records")
print("="*60)

print("--- ConnectionRecord Sample ---")
if result.connections:
    pprint(result.connections[0].__dict__)
else:
    print("None found")

print("\n--- DNSRecord Sample ---")
if result.dns_records:
    # Find one with response IPs if possible
    dns_with_ips = [r for r in result.dns_records if r.response_ips]
    sample_dns = dns_with_ips[0] if dns_with_ips else result.dns_records[0]
    pprint(sample_dns.__dict__)
else:
    print("None found")

print("\n--- DomainGeoRecord Sample ---")
if result.domain_geo_records:
    pprint(result.domain_geo_records[0].__dict__)
else:
    print("None found")

print("\n" + "="*60)
print("Step 6: Validation Answers")
print("="*60)

# Answer validation checks
has_conns = len(result.connections) > 0
has_dns = len(result.dns_records) > 0

# Deduplicated check
geo_pairs = [(r.domain, r.dst_ip) for r in result.domain_geo_records]
is_deduped = len(geo_pairs) == len(set(geo_pairs))

# Tracker matches appearing
has_trackers = any(r.tracker_matched for r in result.connections)

# ASN/Country check
has_country = any(r.geo_fact and r.geo_fact.country_code != "" and r.geo_fact.country_code != "PRIVATE" for r in result.connections)
has_asn = any(r.asn_fact and r.asn_fact.asn != "" for r in result.connections if r.geo_fact and r.geo_fact.country_code != "PRIVATE")

# Anti-analysis
has_anti = any(r.is_anti_analysis_probe for r in result.connections)

# Nonstandard port
has_nonstd = any(r.is_nonstandard_port for r in result.connections)

print(f"1. Are ConnectionRecords being generated? {'YES' if has_conns else 'NO'}")
print(f"2. Are DNSRecords populated? {'YES' if has_dns else 'NO'}")
print(f"3. Are DomainGeoRecords deduplicated? {'YES' if is_deduped else 'NO'} (Total: {len(result.domain_geo_records)}, Unique: {len(set(geo_pairs))})")
print(f"4. Are tracker matches appearing? {'YES' if has_trackers else 'NO'}")
print(f"5. Are ASN fields populated? {'YES' if has_asn else 'NO'}")
print(f"6. Are country fields populated? {'YES' if has_country else 'NO'}")
print(f"7. Are anti-analysis probes detected? {'YES' if has_anti else 'NO'}")
print(f"8. Are nonstandard ports detected? {'YES' if has_nonstd else 'NO'}")

