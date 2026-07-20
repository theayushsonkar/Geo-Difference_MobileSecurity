import sys
from pathlib import Path

# Add workspace directory to path
workspace_dir = Path(r"d:\New folder\Geo-Difference_MobileSecurity")
sys.path.append(str(workspace_dir))

from pcap.pcap_parser import parse_pcap
from knowledge_base.dataset_manager import DatasetManager
from pcap.network_context import NetworkContext
from pcap.connection_builder import ConnectionBuilder

def run_test():
    print("="*60)
    print("RUNNING DNS RESPONSE COUNT VALIDATION")
    print("="*60)

    pcap_path = workspace_dir / "data" / "pcap" / "arrow_escape.pcap"
    events = parse_pcap(pcap_path)
    
    manager = DatasetManager()
    geo_mapper = manager.load_geolite()
    network_context = NetworkContext(geo_mapper=geo_mapper)
    builder = ConnectionBuilder(network_context=network_context)
    result = builder.build(events, sample_id="arrow_escape", session_id="session_123")

    dns_records = result.dns_records
    print(f"Total DNS records processed: {len(dns_records)}")

    all_pass = True
    checks = {
        "count_matches_len": True,
        "count_non_negative": True,
        "query_has_zero": True
    }

    query_count = 0
    response_count_total = 0

    for idx, r in enumerate(dns_records, 1):
        # 1. Check response_count == len(response_ips)
        expected_len = len(r.response_ips)
        if r.response_count != expected_len:
            checks["count_matches_len"] = False
            print(f"FAIL: Record {idx} ({r.query_name}): response_count={r.response_count} but len(response_ips)={expected_len}")

        # 2. Check response_count >= 0
        if r.response_count < 0:
            checks["count_non_negative"] = False
            print(f"FAIL: Record {idx} ({r.query_name}): response_count={r.response_count} is negative")

        # 3. Check query packets (no response IPs) have response_count = 0
        is_query = len(r.response_ips) == 0
        if is_query:
            query_count += 1
            if r.response_count != 0:
                checks["query_has_zero"] = False
                print(f"FAIL: Query Record {idx} ({r.query_name}): response_count={r.response_count} but expected 0")
        else:
            response_count_total += 1

    print(f"Queries checked: {query_count}")
    print(f"Responses checked: {response_count_total}")

    for check_name, passed in checks.items():
        print(f"  Check '{check_name}': {'PASS' if passed else 'FAIL'}")
        if not passed:
            all_pass = False


    if all_pass:
        print("Final Verdict: PASS")
        sys.exit(0)
    else:
        print("Final Verdict: FAIL")
        sys.exit(1)

if __name__ == "__main__":
    run_test()
