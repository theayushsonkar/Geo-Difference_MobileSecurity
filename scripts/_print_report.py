import json
from pathlib import Path

r = json.loads(Path('scripts/validation_report.json').read_text(encoding='utf-8'))
m = r['meta']
print("PCAPSs found:", m["pcaps_found"], " processed:", m["pcaps_processed"], " failed:", m["pcaps_failed"])
print("Total connections:", m["total_connections"], " elapsed:", m["elapsed_sec"], "s")

print("\n--- TRACKER KB ---")
t = r['tracker_kb']
print("  Total domains seen:  ", t["total_domains_seen"])
print("  Tracker domain hits: ", t["tracker_domain_hits"])
print("  Coverage pct:        ", t["tracker_coverage_pct"], "%")
print("  Unique vendors:      ", t["unique_vendors"])
print("  Unique categories:   ", t["unique_categories"])
print("  Top vendors:")
for v in t['top_vendors'][:10]:
    print("   ", v[0], ":", v[1])
print("  Top categories:")
for c in t['top_categories']:
    print("   ", c[0], ":", c[1])
print("  Top unmatched domains:")
for d in t['top_unmatched_domains'][:15]:
    print("   ", d[0], ":", d[1])

print("\n--- GEOLITE KB ---")
g = r['geolite_kb']
print("  Unique dst IPs:   ", g["unique_dst_ips"])
print("  GeoIP resolved:   ", g["geo_resolved"])
print("  Unresolved IPs:   ", g["unresolved_ips"])
print("  GeoIP coverage:   ", g["geo_coverage_pct"], "%")
print("  Unique countries: ", g["unique_countries"])
print("  Unique ASNs:      ", g["unique_asns"])
print("  Unique orgs:      ", g["unique_orgs"])
print("  Top countries:")
for c in g['top_countries'][:10]:
    print("   ", c[0], ":", c[1])
print("  Top orgs:")
for o in g['top_orgs'][:10]:
    print("   ", o[0], ":", o[1])
print("  Top unresolved:")
for u in g['top_unresolved'][:10]:
    print("   ", u[0], ":", u[1])

print("\n--- DNS RESOLVER KB ---")
d = r['dns_resolver_kb']
print("  Total DNS queries:   ", d["total_dns_queries"])
print("  Known resolver IPs:  ", d["known_resolver_ips"])
print("  Unknown resolver IPs:", d["unknown_resolver_ips"])
print("  DNS coverage:        ", d["dns_coverage_pct"], "%")
print("  Provider counts:")
for p in d['dns_provider_counts'][:10]:
    print("   ", p[0], ":", p[1])
print("  Top unknown resolvers:")
for u in d['top_unknown_resolvers'][:15]:
    print("   ", u[0], ":", u[1])
print("  Known IPs:", d["dns_known_ip_list"])

print("\n--- PII KB ---")
p = r['pii_kb']
print("  Total PII matches:  ", p["total_pii_matches"])
print("  PCAPs with PII:     ", p["pcaps_with_pii"])
print("  PII coverage:       ", p["pii_coverage_pct"], "%")
print("  Category counts:    ", p["pii_category_counts"])
print("  Pattern counts:     ", p["pii_pattern_counts"])
print("  Source field counts:", p["pii_source_field_counts"])
print("  Possible FPs count: ", len(p["possible_false_positives"]))
print("  Sample PII matches (first 10):")
for m2 in p['all_pii_matches'][:10]:
    print("   ", m2["pattern_name"], "|", m2["category"], "|", m2["source_location"], "|", m2["confidence"], "| value:", m2["matched_value"][:40])
print("  Possible FP samples:")
for fp in p['possible_false_positives'][:10]:
    print("   FP?", fp["pattern_name"], "|", fp["source_location"], "|", fp["matched_value"][:40])

print("\n--- COVERAGE SUMMARY ---")
cv = r['coverage']
print("  Tracker: ", cv["tracker_pct"], "%")
print("  GeoLite: ", cv["geolite_pct"], "%")
print("  DNS:     ", cv["dns_pct"], "%")
print("  PII:     ", cv["pii_pct"], "%")

print("\n--- FAILED PCAPS ---")
for f2 in r['failed_pcaps']:
    print("   FAILED:", f2["pcap"], "->", f2["error"][:80])
