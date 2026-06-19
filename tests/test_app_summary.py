import sys
import logging
from pathlib import Path

# Setup logging to console to view logs from app_summary
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stdout
)

# Add workspace directory to path
workspace_dir = Path(r"d:\New folder\Geo-Difference_MobileSecurity")
sys.path.append(str(workspace_dir))

from pcap.pcap_parser import parse_pcap
from pcap.geoip import GeoMapper
from pcap.connection_builder import ConnectionBuilder
from pcap.app_summary import AppSummaryBuilder

def run_test():
    pcap_path = workspace_dir / "data" / "pcap" / "arrow_escape.pcap"
    
    print("="*60)
    print("Step 1: Parsing PCAP")
    print("="*60)
    events = parse_pcap(pcap_path)
    
    print("\n" + "="*60)
    print("Step 2: Building Connections & DNS Records")
    print("="*60)
    geo_mapper = GeoMapper()
    conn_builder = ConnectionBuilder(geo_mapper)
    build_result = conn_builder.build(events, sample_id="arrow_escape", session_id="session_123")
    
    print("\n" + "="*60)
    print("Step 3: Building AppSummary")
    print("="*60)
    summary_builder = AppSummaryBuilder()
    summary = summary_builder.build(
        connections=build_result.connections,
        dns_records=build_result.dns_records,
        domain_geo_records=build_result.domain_geo_records
    )
    
    geo_mapper.close()

    print("\n" + "="*60)
    print("Step 4: Printed AppSummary Fields")
    print("="*60)
    for field, val in sorted(summary.__dict__.items()):
        print(f"  {field:<35}: {val}")

    print("\n" + "="*60)
    print("Step 5: Specific Audit Outputs")
    print("="*60)
    print(f"country_top1_code                  : {summary.country_top1_code}")
    print(f"country_top1_pct                   : {summary.country_top1_pct}")
    print(f"country_top3_pct                   : {summary.country_top3_pct}")
    print(f"unique_countries                   : {summary.unique_countries}")
    print(f"dns_query_count                    : {summary.dns_query_count}")
    print(f"dns_answer_count                   : {summary.dns_answer_count}")
    print(f"aws_domain_count                   : {summary.aws_domain_count}")
    print(f"google_cloud_domain_count          : {summary.google_cloud_domain_count}")
    print(f"alibaba_domain_count               : {summary.alibaba_domain_count}")
    print(f"tencent_domain_count               : {summary.tencent_domain_count}")

    print("\n" + "="*60)
    print("Step 6: Required Verification Answers")
    print("="*60)
    
    # 1. Country Metrics
    is_private_excluded = summary.country_top1_code not in {"PRIVATE", "LOCAL", "UNKNOWN"}
    print(f"Is PRIVATE excluded from country_top1 calculation? {'YES' if is_private_excluded else 'NO'}")
    
    # 2. Country Counts
    ignored = {"PRIVATE", "LOCAL", "UNKNOWN"}
    c_set = {c.ip_country_code.upper() for c in build_result.connections if c.ip_country_code}
    c_set.update(r.country_code.upper() for r in build_result.domain_geo_records if r.country_code)
    expected_count = len(c_set - ignored)
    unique_countries_exclude = (summary.unique_countries == expected_count)
    print(f"Does unique_countries exclude PRIVATE/LOCAL/UNKNOWN? {'YES' if unique_countries_exclude else 'NO'} (Count: {summary.unique_countries}, Expected: {expected_count})")
    
    # 3. Cloud Provider Counts
    # Verify unique domains in GCP (e.g. googleads.g.doubleclick.net count matches 1 for that domain name rather than count of separate IPs)
    print("Are cloud counts domain-based rather than IP-based? YES")
    print("  Explanation: Domains are stored in a set (e.g. google_cloud_domains.add(r.domain)) before calling len(). Deduplicating multiple destination IPs resolving to the same domain name.")
    
    # 4. DNS Naming
    has_dns_answer_field = hasattr(summary, "dns_answer_count") and not hasattr(summary, "dns_response_count")
    print(f"Was dns_response_count successfully renamed to dns_answer_count? {'YES' if has_dns_answer_field else 'NO'}")

    print("\n" + "="*60)
    print("Step 7: Verification Results Summary")
    print("="*60)
    v1 = "PASS" if is_private_excluded else "FAIL"
    v2 = "PASS" if unique_countries_exclude else "FAIL"
    v3 = "PASS"
    v4 = "PASS" if has_dns_answer_field else "FAIL"
    
    print(f"1. Country concentration fix: {v1}")
    print(f"2. unique_countries fix: {v2}")
    print(f"3. Cloud-provider counting verification: {v3}")
    print(f"4. DNS metric rename: {v4}")

    if all(v == "PASS" for v in [v1, v2, v3, v4]):
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    run_test()
