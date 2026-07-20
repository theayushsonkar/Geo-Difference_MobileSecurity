import sys, traceback
from pathlib import Path
ROOT = Path(".").resolve()
sys.path.insert(0, str(ROOT))

from pcap.pcap_parser import parse_pcap
from pcap.connection_builder import ConnectionBuilder
from pcap.app_summary import AppSummaryBuilder
from pcap.network_context import NetworkContext
from pcap.matchers.pii_matcher import PIIMatcher
from pcap.matchers.dns_resolver_matcher import DNSResolverMatcher
from pcap.matchers.tracker_matcher import TrackerMatcher
from knowledge_base.dataset_manager import DatasetManager

import logging
logging.basicConfig(level=logging.WARNING)

manager = DatasetManager()
geo_mapper = manager.load_geolite()
tracker_facts = manager.load_network_trackers()
tracker_matcher = TrackerMatcher(tracker_facts)
dns_facts = manager.load_dns_resolvers()
dns_dict = {r.ip_address: r.__dict__ for r in dns_facts}
dns_matcher = DNSResolverMatcher(dns_dict)
pii_patterns = manager.load_pii_patterns()
pii_matcher = PIIMatcher(pii_patterns)

ctx = NetworkContext(
    tracker_matcher=tracker_matcher,
    geo_mapper=geo_mapper,
    dns_resolver_matcher=dns_matcher,
    pii_matcher=pii_matcher,
)
conn_builder = ConnectionBuilder(network_context=ctx)
sb = AppSummaryBuilder()

# Test the first failing PCAP
test_pcap = Path("data/pcap/ai.art.generator.photo.image.geni_in.pcap")
try:
    events = parse_pcap(test_pcap)
    result = conn_builder.build(events, test_pcap.stem, f"{test_pcap.stem}_s1")
    summary = sb.build(result.connections, result.dns_records, result.domain_geo_records)
    print("SUCCESS - tracker_connection_count:", summary.tracker_connection_count)
    print("tracker_vendor_distribution:", summary.tracker_vendor_distribution)
    print("tracker_category_distribution:", summary.tracker_category_distribution)
except Exception as e:
    traceback.print_exc()
