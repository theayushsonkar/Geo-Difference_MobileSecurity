import csv
import random

def verify():
    # 2. Verify Community Bucket
    community = []
    with open('knowledge_base/network/processed/dns_resolvers.csv', 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        all_rows = list(reader)
        for r in all_rows:
            if r['canonical_provider'] == 'Community':
                community.append(r['resolver_name'])
    
    print("--- 2. Community Bucket Samples ---")
    random.seed(42) # deterministic sample
    samples = random.sample(community, min(20, len(community)))
    for s in samples:
        print(f"  - {s}")
        
    # 3. Verify Merge Logic
    # We need to simulate the merge to catch the 22 conflicts
    from knowledge_base.network.importers.dns_resolver_importer import DNSResolverImporter
    from knowledge_base.network.importers.dnscrypt_importer import DNSCryptResolverImporter
    from pathlib import Path
    
    dnscrypt_models = list(DNSCryptResolverImporter(Path('knowledge_base/raw/dns_resolvers/dnscrypt_resolvers.md')).process())
    override_models = list(DNSResolverImporter(Path('knowledge_base/raw/dns_resolvers/public_dns.csv')).process())
    
    unique = {m.ip_address: m for m in dnscrypt_models}
    conflicts = []
    for model in override_models:
        if model.ip_address in unique:
            existing = unique[model.ip_address]
            if existing.resolver_name != model.resolver_name or existing.provider != model.provider:
                conflicts.append((existing, model))
    
    print("\n--- 3. Merge Logic Conflicts ---")
    # Show 5 examples
    for ex, ov in conflicts[:5]:
        print(f"IP: {ov.ip_address}")
        print(f"  Existing (dnscrypt): Provider={ex.provider}, Name={ex.resolver_name}, DoH={ex.supports_doh}, DoT={ex.supports_dot}, DNSCrypt={ex.supports_dnscrypt}")
        print(f"  Override (public_dns): Provider={ov.provider}, Name={ov.resolver_name}, DoH={ov.supports_doh}, DoT={ov.supports_dot}, DNSCrypt={ov.supports_dnscrypt}")
        # Look up final in all_rows
        final = next(r for r in all_rows if r['ip_address'] == ov.ip_address)
        print(f"  Final Record: Provider={final['provider']}, Canonical={final['canonical_provider']}, DoH={final['supports_doh']}, DoT={final['supports_dot']}, DNSCrypt={final['supports_dnscrypt']}, Confidence={final['confidence']}")
        print()

    # 4. Verify Known Resolver Records
    print("--- 4. Known Resolver Records ---")
    targets = ['8.8.8.8', '1.1.1.1', '9.9.9.9', '208.67.222.222', '223.5.5.5', '119.29.29.29']
    for t in targets:
        final = next((r for r in all_rows if r['ip_address'] == t), None)
        if final:
            print(f"{t}: Provider={final['provider']}, Canonical={final['canonical_provider']}, Name={final['resolver_name']}, DoH={final['supports_doh']}, DoT={final['supports_dot']}, DNSCrypt={final['supports_dnscrypt']}, Confidence={final['confidence']}, Source={final['source_dataset']}")
        else:
            print(f"{t}: NOT FOUND")
            
    # 5. Verify Cloudflare Variants
    print("\n--- 5. Cloudflare Variants ---")
    cf_targets = ['1.1.1.1', '1.0.0.1', '1.1.1.2', '1.0.0.2', '1.1.1.3', '1.0.0.3']
    for c in cf_targets:
        exists = any(r['ip_address'] == c for r in all_rows)
        print(f"{c}: {'FOUND' if exists else 'NOT FOUND'}")
        
    # 6. Verify DoT Overrides
    print("\n--- 6. DoT Overrides ---")
    with open('knowledge_base/raw/dns_resolvers/public_dns.csv', 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row['provider'] in ['Google', 'Cloudflare', 'Quad9']:
                print(f"public_dns.csv -> {row['ip_address']} ({row['provider']}): DoH={row['supports_doh']}, DoT={row['supports_dot']}")

if __name__ == "__main__":
    verify()
