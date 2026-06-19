import sys
import logging
from pathlib import Path

# Setup logging to console
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stdout
)

# Add workspace directory to path
workspace_dir = Path(r"d:\New folder\Geo-Difference_MobileSecurity")
sys.path.append(str(workspace_dir))

from pcap.tracker_matcher import match_domain, match_domains

# Test cases from user request
test_domains = [
    "logs.ads.vungle.com",
    "graph.facebook.com",
    "sdk-api-v1.singular.net",
    "unknown.example.com",
    "8.8.8.8",
    ""
]

print("="*60)
print("Part 1: Running match_domain() Tests")
print("="*60)

for d in test_domains:
    res = match_domain(d)
    print(f"Input: {d!r}")
    print(f"  - Matched: {res.matched}")
    print(f"  - SDK Name: {res.sdk_name!r}")
    print(f"  - Vendor Country: {res.vendor_country!r}")
    print(f"  - Category: {res.sdk_category!r}")
    print(f"  - Suffix Matched: {res.matched_suffix!r}")
    print("-" * 40)

print("\n" + "="*60)
print("Part 2: Running match_domains() Batch & Deduplication Test")
print("="*60)

batch_input = [
    "logs.ads.vungle.com",
    "logs.ads.vungle.com",
    "graph.facebook.com",
    "applovin.com",
    "applovin.com",
    "unknown.example.com"
]

print(f"Batch input size (with duplicates): {len(batch_input)}")
batch_results = match_domains(batch_input)
print(f"Batch output dict size (unique): {len(batch_results)}")

for d, res in batch_results.items():
    print(f"Domain: {d!r} -> SDK Name: {res.sdk_name!r} (Matched: {res.matched})")

print("\n" + "="*60)
print("Part 3: Edge Case Normlization Tests")
print("="*60)

edge_cases = [
    "  LOGS.ADS.VUNGLE.COM  ",
    "graph.facebook.com.",
    None,
    " "
]

for d in edge_cases:
    res = match_domain(d)
    print(f"Input: {d!r} -> Normalized & Matched: {res.matched} (SDK: {res.sdk_name!r}, Suffix: {res.matched_suffix!r})")
