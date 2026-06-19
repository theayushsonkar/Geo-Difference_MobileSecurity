import sys
from pathlib import Path

# Add workspace directory to path
workspace_dir = Path(r"d:\New folder\Geo-Difference_MobileSecurity")
sys.path.append(str(workspace_dir))

from pcap.tracker_matcher import match_domain

def run_test():
    print("="*60)
    print("RUNNING CANONICAL VENDOR VALIDATION")
    print("="*60)

    # Test cases: (domain, expected_sdk_name, expected_canonical)
    test_cases = [
        ("logs.ads.vungle.com", "Vungle Metrics", "Vungle"),
        ("googleads.g.doubleclick.net", "Google Ads", "Google"),
        ("graph.facebook.com", "Facebook Graph API", "Facebook"),
    ]

    all_pass = True

    for domain, expected_sdk, expected_canonical in test_cases:
        match = match_domain(domain)
        print(f"Domain: {domain}")
        print(f"  sdk_name         : {match.sdk_name} (Expected: {expected_sdk})")
        print(f"  canonical_vendor : {match.canonical_vendor} (Expected: {expected_canonical})")
        
        sdk_match = match.sdk_name == expected_sdk
        vendor_match = match.canonical_vendor == expected_canonical

        if sdk_match and vendor_match:
            print("  Result: PASS")
        else:
            print("  Result: FAIL")
            all_pass = False
        print("-" * 40)

    if all_pass:
        print("Final Verdict: PASS")
        sys.exit(0)
    else:
        print("Final Verdict: FAIL")
        sys.exit(1)

if __name__ == "__main__":
    run_test()
