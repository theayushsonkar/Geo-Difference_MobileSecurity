"""
validate_kb_pipeline.py
-----------------------
Validation-only script. Does NOT modify any KB code.
Runs the full PCAP pipeline on all available PCAPs and produces
a structured validation report covering Tracker KB, GeoLite2,
DNS Resolver KB, PII KB, and AppSummary correctness.
"""

import json
import sys
import time
import logging
from collections import Counter, defaultdict
from pathlib import Path

# ── Path setup ─────────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pcap.pcap_parser import parse_pcap
from pcap.connection_builder import ConnectionBuilder
from pcap.app_summary import AppSummaryBuilder
from pcap.network_context import NetworkContext
from pcap.matchers.pii_matcher import PIIMatcher
from pcap.matchers.dns_resolver_matcher import DNSResolverMatcher
from pcap.matchers.tracker_matcher import TrackerMatcher
from knowledge_base.dataset_manager import DatasetManager

logging.basicConfig(level=logging.WARNING)

PCAP_DIR = ROOT / "data" / "pcap"
SAMPLE_INDEX = ROOT / "sample_index.csv"
OUTPUT = ROOT / "scripts" / "validation_report.json"

# ── Load KBs ───────────────────────────────────────────────────────────────
print("[*] Loading Knowledge Bases …")
manager = DatasetManager()

geo_mapper   = manager.load_geolite()

tracker_facts   = manager.load_network_trackers()
tracker_matcher = TrackerMatcher(tracker_facts)
print(f"[*] TrackerMatcher: {len(tracker_facts)} rules")

dns_facts    = manager.load_dns_resolvers()
dns_dict     = {r.ip_address: r.__dict__ for r in dns_facts}
dns_matcher  = DNSResolverMatcher(dns_dict)
pii_patterns = manager.load_pii_patterns()
pii_matcher  = PIIMatcher(pii_patterns)

ctx = NetworkContext(
    tracker_matcher     = tracker_matcher,
    geo_mapper          = geo_mapper,
    dns_resolver_matcher= dns_matcher,
    pii_matcher         = pii_matcher,
)
conn_builder    = ConnectionBuilder(network_context=ctx)
summary_builder = AppSummaryBuilder()

# ── Accumulators ────────────────────────────────────────────────────────────
pcap_files = sorted(f for f in PCAP_DIR.glob("*.pcap") if f.stat().st_size > 0)
print(f"[*] Found {len(pcap_files)} non-empty PCAP files")

# Tracker
tracker_domain_hits   = Counter()
tracker_vendor_counts = Counter()
tracker_category_counts = Counter()
unmatched_domains     = Counter()

# GeoLite
all_dst_ips           = Counter()
geo_country_counts    = Counter()
asn_counts            = Counter()
org_counts            = Counter()
unresolved_ips        = Counter()

# DNS KB
dns_resolver_hits     = Counter()      # resolver_ip -> count
dns_known_ips         = set()
dns_unknown_ips       = Counter()
dns_provider_counts   = Counter()

# PII
pii_category_counts   = Counter()
pii_pattern_counts    = Counter()
pii_source_counts     = Counter()
pii_all_matches       = []

# Summary sanity
total_connections     = 0
total_pcaps_processed = 0
total_pcaps_failed    = 0
failed_pcaps          = []

# Per-PCAP storage
per_pcap = {}

t0 = time.time()

for pcap_path in pcap_files:
    try:
        events = parse_pcap(pcap_path)
        if not events:
            continue
        result  = conn_builder.build(events, pcap_path.stem, f"{pcap_path.stem}_s1")
        summary = summary_builder.build(
            connections       = result.connections,
            dns_records       = result.dns_records,
            domain_geo_records= result.domain_geo_records,
        )
        total_pcaps_processed += 1
        total_connections     += len(result.connections)
    except Exception as exc:
        total_pcaps_failed += 1
        failed_pcaps.append({"pcap": pcap_path.name, "error": str(exc)})
        continue

    # ── Tracker ────────────────────────────────────────────────────────────
    for c in result.connections:
        dom = c.domain or c.registered_domain
        if c.tracker_fact is not None:
            tracker_domain_hits[dom] += 1
            if c.tracker_fact.canonical_vendor:
                tracker_vendor_counts[c.tracker_fact.canonical_vendor] += 1
            if c.tracker_fact.category:
                tracker_category_counts[c.tracker_fact.category] += 1
        elif dom:
            unmatched_domains[dom] += 1

    # ── GeoLite ────────────────────────────────────────────────────────────
    for c in result.connections:
        ip = c.dst_ip
        all_dst_ips[ip] += 1
        if c.geo_fact:
            geo_country_counts[c.geo_fact.country_code] += 1
        else:
            unresolved_ips[ip] += 1
        if c.asn_fact:
            asn_counts[c.asn_fact.asn] += 1
            org_counts[c.asn_fact.organization] += 1

    # ── DNS KB ─────────────────────────────────────────────────────────────
    for dr in result.dns_records:
        resolver_ip = dr.resolver_ip
        dns_resolver_hits[resolver_ip] += 1
        if dr.dns_resolver_fact:
            dns_known_ips.add(resolver_ip)
            dns_provider_counts[dr.dns_resolver_fact.canonical_provider] += 1
        else:
            dns_unknown_ips[resolver_ip] += 1

    # ── PII ────────────────────────────────────────────────────────────────
    for c in result.connections:
        for pf in c.pii_facts:
            pii_category_counts[pf.category] += 1
            pii_pattern_counts[pf.pattern_name] += 1
            pii_source_counts[pf.source_location] += 1
            pii_all_matches.append({
                "pcap"          : pcap_path.name,
                "domain"        : c.domain,
                "pattern_name"  : pf.pattern_name,
                "category"      : pf.category,
                "source_location": pf.source_location,
                "confidence"    : pf.confidence,
                "matched_value" : pf.matched_value[:60],  # truncated for safety
            })

    per_pcap[pcap_path.name] = {
        "connections"        : len(result.connections),
        "dns_records"        : len(result.dns_records),
        "tracker_matches"    : summary.tracker_connection_count,
        "tracker_domains"    : summary.tracker_domain_count,
        "unique_domains"     : summary.unique_domains,
        "unique_ips"         : summary.unique_ips,
        "geo_countries"      : summary.unique_destination_countries,
        "pii_matches"        : summary.total_pii_matches,
        "dns_provider_diversity": summary.dns_provider_diversity,
        "doh_detected"       : summary.doh_detected,
        "hardcoded_dns"      : summary.hardcoded_dns_detected,
        "top_dns_providers"  : summary.top_dns_providers,
    }

elapsed = time.time() - t0

# ── Coverage computations ───────────────────────────────────────────────────
total_connections_global = sum(v["connections"] for v in per_pcap.values())
unique_ips_total         = len(all_dst_ips)
geo_resolved             = unique_ips_total - len(unresolved_ips)
geo_coverage_pct         = round(geo_resolved / unique_ips_total * 100, 1) if unique_ips_total else 0

total_domain_hits        = sum(tracker_domain_hits.values()) + sum(unmatched_domains.values())
tracker_coverage_pct     = round(
    sum(tracker_domain_hits.values()) / total_domain_hits * 100, 1
) if total_domain_hits else 0

total_dns_queries        = sum(dns_resolver_hits.values())
dns_known_queries        = sum(dns_resolver_hits[ip] for ip in dns_known_ips)
dns_coverage_pct         = round(dns_known_queries / total_dns_queries * 100, 1) if total_dns_queries else 0

# PII coverage: fraction of connections where PII was detected
conns_with_pii = sum(1 for v in per_pcap.values() if v["pii_matches"] > 0)
pii_coverage_pct = round(conns_with_pii / total_pcaps_processed * 100, 1) if total_pcaps_processed else 0

# ── False-positive detection heuristics ────────────────────────────────────
# Flag any PII hit that came from a DNS Name (domains rarely contain true PII)
possible_fp = [m for m in pii_all_matches if m["source_location"] == "DNS Name"]

# Flag IPv4 matches — likely internal routing IPs rather than actual PII leakage
possible_fp += [m for m in pii_all_matches
                if m["pattern_name"] == "IPv4"
                and m["source_location"] in ("DNS Name", "HTTP URL")]

# ── Missing KB entries ──────────────────────────────────────────────────────
top_unmatched_domains = unmatched_domains.most_common(30)
top_unknown_dns       = dns_unknown_ips.most_common(20)

# ── Build report ───────────────────────────────────────────────────────────
report = {
    "meta": {
        "pcaps_found"    : len(pcap_files),
        "pcaps_processed": total_pcaps_processed,
        "pcaps_failed"   : total_pcaps_failed,
        "total_connections": total_connections,
        "elapsed_sec"    : round(elapsed, 1),
    },
    "failed_pcaps": failed_pcaps,

    # ── Tracker KB ──────────────────────────────────────────────────────────
    "tracker_kb": {
        "total_domains_seen"  : total_domain_hits,
        "tracker_domain_hits" : sum(tracker_domain_hits.values()),
        "unique_vendors"      : len(tracker_vendor_counts),
        "unique_categories"   : len(tracker_category_counts),
        "tracker_coverage_pct": tracker_coverage_pct,
        "top_vendors"         : tracker_vendor_counts.most_common(15),
        "top_categories"      : tracker_category_counts.most_common(10),
        "top_unmatched_domains": top_unmatched_domains,
    },

    # ── GeoLite2 ────────────────────────────────────────────────────────────
    "geolite_kb": {
        "unique_dst_ips"   : unique_ips_total,
        "geo_resolved"     : geo_resolved,
        "unresolved_ips"   : len(unresolved_ips),
        "geo_coverage_pct" : geo_coverage_pct,
        "unique_countries" : len(geo_country_counts),
        "unique_asns"      : len(asn_counts),
        "unique_orgs"      : len(org_counts),
        "top_countries"    : geo_country_counts.most_common(15),
        "top_asns"         : asn_counts.most_common(10),
        "top_orgs"         : org_counts.most_common(10),
        "top_unresolved"   : unresolved_ips.most_common(20),
    },

    # ── DNS Resolver KB ─────────────────────────────────────────────────────
    "dns_resolver_kb": {
        "total_dns_queries"  : total_dns_queries,
        "known_resolver_ips" : len(dns_known_ips),
        "unknown_resolver_ips": len(dns_unknown_ips),
        "dns_coverage_pct"   : dns_coverage_pct,
        "dns_provider_counts": dns_provider_counts.most_common(20),
        "top_unknown_resolvers": top_unknown_dns,
        "dns_known_ip_list"  : sorted(dns_known_ips),
    },

    # ── PII KB ──────────────────────────────────────────────────────────────
    "pii_kb": {
        "total_pii_matches"   : len(pii_all_matches),
        "pcaps_with_pii"      : conns_with_pii,
        "pii_coverage_pct"    : pii_coverage_pct,
        "pii_category_counts" : dict(pii_category_counts),
        "pii_pattern_counts"  : dict(pii_pattern_counts),
        "pii_source_field_counts": dict(pii_source_counts),
        "all_pii_matches"     : pii_all_matches,
        "possible_false_positives": possible_fp,
    },

    # ── Coverage summary ────────────────────────────────────────────────────
    "coverage": {
        "tracker_pct" : tracker_coverage_pct,
        "geolite_pct" : geo_coverage_pct,
        "dns_pct"     : dns_coverage_pct,
        "pii_pct"     : pii_coverage_pct,
    },

    # ── Per-PCAP ────────────────────────────────────────────────────────────
    "per_pcap": per_pcap,
}

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
with open(OUTPUT, "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2)

print(f"\n[✓] Validation complete in {round(elapsed,1)}s")
print(f"    PCAPSs processed : {total_pcaps_processed}")
print(f"    PCAPSs failed    : {total_pcaps_failed}")
print(f"    Total connections: {total_connections}")
print(f"\n    Tracker  coverage: {tracker_coverage_pct}%")
print(f"    GeoLite  coverage: {geo_coverage_pct}%")
print(f"    DNS      coverage: {dns_coverage_pct}%")
print(f"    PII      coverage: {pii_coverage_pct}%")
print(f"\n[✓] Full report written to: {OUTPUT}")
