from pathlib import Path
from knowledge_base.network.importers.dnscrypt_importer import DNSCryptResolverImporter

importer = DNSCryptResolverImporter(Path('knowledge_base/raw/dns_resolvers/dnscrypt_resolvers.md'))
models = list(importer.process())

targets = ["Google", "Cloudflare", "Quad9", "AdGuard"]
seen_names = set()

print("SDNS Validation Report:")
for m in models:
    for t in targets:
        if t.lower() in m.resolver_name.lower():
            if m.resolver_name not in seen_names:
                print(f"- {m.resolver_name}: DNSCrypt={m.supports_dnscrypt}, DoH={m.supports_doh}, DoT={m.supports_dot}")
                seen_names.add(m.resolver_name)
