import csv
from pathlib import Path
from typing import Generator

from knowledge_base.network.schemas.kb_schemas import NormalizedDNSResolver

class DNSResolverImporter:
    """Importer for raw DNS Resolver dataset."""
    
    def __init__(self, raw_path: Path):
        self.raw_path = raw_path

    def process(self) -> Generator[NormalizedDNSResolver, None, None]:
        if not self.raw_path.exists():
            return
            
        with open(self.raw_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                ip = row.get("ip_address", "").strip()
                if not ip:
                    continue
                yield NormalizedDNSResolver(
                    ip_address=ip,
                    provider=row.get("provider", "").strip(),
                    canonical_provider="",
                    resolver_name=row.get("resolver_name", "").strip(),
                    provider_country=row.get("provider_country", "").strip(),
                    supports_doh=row.get("supports_doh", "").strip().lower() == "true",
                    supports_dot=row.get("supports_dot", "").strip().lower() == "true",
                    supports_dnscrypt=False,
                    source_dataset="PublicDNS",
                    source_version="1.0",
                    confidence="HIGH"
                )
