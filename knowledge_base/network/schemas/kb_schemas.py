from dataclasses import dataclass

@dataclass
class NormalizedTracker:
    """Normalized model for Tracker data emitted by Importers."""
    domain_suffix: str
    vendor: str
    canonical_vendor: str
    category: str
    source_dataset: str
    source_version: str

@dataclass
class NormalizedDNSResolver:
    """Normalized model for DNS Resolver data emitted by Importers."""
    ip_address: str
    provider: str
    canonical_provider: str
    resolver_name: str
    provider_country: str
    supports_doh: bool
    supports_dot: bool
    supports_dnscrypt: bool
    source_dataset: str
    source_version: str
    confidence: str

@dataclass(frozen=True)
class NormalizedPIIPattern:
    """Normalized model for PII pattern data emitted by Importers."""
    pattern_name: str
    category: str
    regex: str
    source_reference: str
    source_dataset: str
    confidence: str
