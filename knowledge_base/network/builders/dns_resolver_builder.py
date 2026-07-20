import csv
import json
import time
import hashlib
from pathlib import Path
from typing import Dict, List

from knowledge_base.network.schemas.kb_schemas import NormalizedDNSResolver
from knowledge_base.network.importers.dns_resolver_importer import DNSResolverImporter
from knowledge_base.network.importers.dnscrypt_importer import DNSCryptResolverImporter
from knowledge_base.network.utils import resolve_canonical_dns_provider

class DNSResolverBuilder:
    """Builds the final processed DNS resolver dataset."""
    
    def __init__(self, raw_dir: Path, processed_dir: Path, metadata_dir: Path):
        self.raw_dir = raw_dir
        self.processed_dir = processed_dir
        self.metadata_dir = metadata_dir
        self.processed_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_dir.mkdir(parents=True, exist_ok=True)

    def _hash_file(self, path: Path) -> str:
        if not path.exists():
            return ""
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for b in iter(lambda: f.read(4096), b""):
                h.update(b)
        return h.hexdigest()

    def build(self) -> None:
        start_time = time.time()
        
        # 1. Ingest DNSCrypt
        dnscrypt_path = self.raw_dir / "dns_resolvers" / "dnscrypt_resolvers.md"
        dnscrypt_importer = DNSCryptResolverImporter(dnscrypt_path)
        dnscrypt_models = list(dnscrypt_importer.process())
        
        # 2. Ingest overrides
        override_path = self.raw_dir / "dns_resolvers" / "public_dns.csv"
        override_importer = DNSResolverImporter(override_path)
        override_models = list(override_importer.process())
        
        # 3. Merge
        unique_resolvers: Dict[str, NormalizedDNSResolver] = {}
        conflicts_resolved = 0
        duplicates_removed = 0
        
        # Load primary first
        for model in dnscrypt_models:
            if model.ip_address in unique_resolvers:
                duplicates_removed += 1
            else:
                unique_resolvers[model.ip_address] = model
                
        # Apply overrides
        for model in override_models:
            if model.ip_address in unique_resolvers:
                existing = unique_resolvers[model.ip_address]
                
                # If fields differ, resolve conflict by preferring override
                if (existing.resolver_name != model.resolver_name or 
                    existing.provider != model.provider):
                    conflicts_resolved += 1
                
                # Apply overrides, preserving fields missing in override like dnscrypt support
                unique_resolvers[model.ip_address] = NormalizedDNSResolver(
                    ip_address=model.ip_address,
                    provider=model.provider or existing.provider,
                    canonical_provider="",
                    resolver_name=model.resolver_name or existing.resolver_name,
                    provider_country=model.provider_country or existing.provider_country,
                    supports_doh=model.supports_doh or existing.supports_doh,
                    supports_dot=model.supports_dot or existing.supports_dot,
                    supports_dnscrypt=existing.supports_dnscrypt, # Inherit from primary since override lacks this
                    source_dataset="public_dns.csv (override) + dnscrypt",
                    source_version="v3",
                    confidence="HIGH"
                )
            else:
                unique_resolvers[model.ip_address] = model
                
        # Resolve canonical providers
        for ip, t in unique_resolvers.items():
            canonical = resolve_canonical_dns_provider(t.provider)
            unique_resolvers[ip] = NormalizedDNSResolver(
                ip_address=t.ip_address,
                provider=t.provider,
                canonical_provider=canonical,
                resolver_name=t.resolver_name,
                provider_country=t.provider_country,
                supports_doh=t.supports_doh,
                supports_dot=t.supports_dot,
                supports_dnscrypt=t.supports_dnscrypt,
                source_dataset=t.source_dataset,
                source_version=t.source_version,
                confidence=t.confidence
            )
                
        csv_path = self.processed_dir / "dns_resolvers.csv"
        
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            fieldnames = ['ip_address', 'provider', 'canonical_provider', 'resolver_name', 'provider_country', 'supports_doh', 'supports_dot', 'supports_dnscrypt', 'source_dataset', 'source_version', 'confidence']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for ip in sorted(unique_resolvers.keys()):
                t = unique_resolvers[ip]
                row = {
                    'ip_address': t.ip_address,
                    'provider': t.provider,
                    'canonical_provider': t.canonical_provider,
                    'resolver_name': t.resolver_name,
                    'provider_country': t.provider_country,
                    'supports_doh': str(t.supports_doh).lower(),
                    'supports_dot': str(t.supports_dot).lower(),
                    'supports_dnscrypt': str(t.supports_dnscrypt).lower(),
                    'source_dataset': t.source_dataset,
                    'source_version': t.source_version,
                    'confidence': t.confidence
                }
                writer.writerow(row)
                
        # 4. Generate Metadata
        meta_path = self.metadata_dir / "dns_resolvers_metadata.json"
        metadata = {
            "version": "2.0",
            "build_timestamp": int(time.time()),
            "build_duration_sec": round(time.time() - start_time, 2),
            "total_resolvers": len(unique_resolvers),
            "providers": len(set(r.canonical_provider for r in unique_resolvers.values() if r.canonical_provider)),
            "dnscrypt": {
                "version": "v3",
                "source_url": "https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md"
            },
            "override": {
                "version": "1.0",
                "sha256": self._hash_file(override_path)
            }
        }
        with open(meta_path, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=4)
            
        # 5. Generate Stats
        stats_path = self.processed_dir / ".stats_dns.json"
        
        # Calculate stats for reporting
        num_community = sum(1 for r in unique_resolvers.values() if r.canonical_provider == "Community")
        num_high = sum(1 for r in unique_resolvers.values() if r.confidence == "HIGH")
        num_medium = sum(1 for r in unique_resolvers.values() if r.confidence == "MEDIUM")
        
        stats = {
            "rows_dnscrypt": len(dnscrypt_models),
            "rows_override": len(override_models),
            "duplicates_removed": duplicates_removed,
            "conflicts_resolved": conflicts_resolved,
            "final_resolver_count": len(unique_resolvers),
            "provider_count": len(set(r.canonical_provider for r in unique_resolvers.values() if r.canonical_provider)),
            "num_community": num_community,
            "num_high": num_high,
            "num_medium": num_medium
        }
        with open(stats_path, 'w', encoding='utf-8') as f:
            json.dump(stats, f, indent=4)
