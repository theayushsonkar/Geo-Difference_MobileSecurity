"""
schemas.py
----------
Dataclasses for the PCAP analysis module.
All fields are plain Python types for easy CSV serialization.
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, List


@dataclass(frozen=True)
class TrackerFact:
    """Represents a guaranteed, atomic truth extracted from the Tracker Knowledge Base."""
    domain_suffix: str
    vendor: str
    canonical_vendor: str
    category: str
    source_dataset: str
    source_version: str


@dataclass(frozen=True)
class DNSResolverFact:
    """Represents a deterministic mapping of an IP to a known public DNS resolver."""
    ip_address: str
    provider: str
    canonical_provider: str
    resolver_name: str
    provider_country: str
    supports_doh: bool
    supports_dot: bool
    source_dataset: str
    source_version: str
    confidence: str
    supports_dnscrypt: bool = False

@dataclass(frozen=True)
class PIIFact:
    """Represents a matched PII instance in network traffic."""
    pattern_name: str
    category: str
    matched_value: str
    source_location: str
    start_offset: int
    end_offset: int
    confidence: str
    source_dataset: str
    source_reference: str

@dataclass(frozen=True)
class GeoFact:
    """Represents a deterministic country mapping from GeoLite2."""
    ip: str
    country_code: str
    country_name: str
    continent: str
    latitude: Optional[float] = None
    longitude: Optional[float] = None


@dataclass(frozen=True)
class ASNFact:
    """Represents a deterministic ASN mapping from GeoLite2."""
    ip: str
    asn: str
    organization: str
    organization_type: str


@dataclass
class ConnectionRecord:
    """One unique domain per app session."""

    # ── Metadata ────────────────────────────────────────────────
    run_id:             str = ""
    schema_version:     str = "1.0"
    parser_version:     str = "1.0"

    # ── App identity ─────────────────────────────────────────────
    sample_id:          str = ""
    package_name:       str = ""
    app_country_code:   str = ""
    app_region_group:   str = ""
    session_id:         str = ""
    pcap_file:          str = ""

    # ── Session timing ───────────────────────────────────────────
    session_start:      str = ""
    session_end:        str = ""
    session_duration_sec: float = 0.0

    # ── Domain ───────────────────────────────────────────────────
    domain:             str = ""
    registered_domain:  str = ""
    tld:                str = ""
    subdomain:          str = ""

    # ── Network ──────────────────────────────────────────────────
    dst_ip:             str = ""
    dst_port:           str = ""
    protocol:           str = ""
    discovery_source:   str = ""   # dns_query | tls_sni | http_host | hardcoded_ip | all

    # ── Traffic stats ────────────────────────────────────────────
    connection_count:   int = 0
    bytes_sent:         int = 0
    bytes_rcvd:         int = 0
    success_count:      int = 0
    error_count:        int = 0
    success_rate:       float = 0.0
    first_seen:         str = ""
    last_seen:          str = ""

    # ── Geo / ASN ────────────────────────────────────────────────
    geo_fact:               Optional[GeoFact] = None
    asn_fact:               Optional[ASNFact] = None

    # ── Tracker identity ─────────────────────────────────────────
    sdk_name:               str = ""
    sdk_vendor_country:     str = ""
    sdk_category:           str = ""
    canonical_vendor:       str = ""
    is_known_tracker:       bool = False
    matched_in_manifest:    bool = False   # cross-validation
    tracker_fact:           Optional[TrackerFact] = None

    # ── Security flags ───────────────────────────────────────────
    is_cleartext_http:      bool = False
    is_quic:                bool = False
    is_nonstandard_port:    bool = False
    is_hardcoded_dns:       bool = False
    is_anti_analysis_probe: bool = False
    is_large_download:      bool = False
    is_doh:                 bool = False

    # ── GeoLite2 DB version used ─────────────────────────────────
    geoip_db_version:       str = ""


@dataclass
class PIIFinding:
    """One PII field detected in one request body."""

    run_id:             str = ""
    sample_id:          str = ""
    package_name:       str = ""
    app_country_code:   str = ""

    domain:             str = ""
    sdk_name:           str = ""
    sdk_vendor_country: str = ""

    pii_type:           str = ""   # GAID | Android_ID | Device_Model | ...
    pii_confidence:     str = ""   # high | medium | low
    is_cleartext:       bool = False
    evidence_snippet:   str = ""   # first 60 chars of match — no actual values


@dataclass
class AppSummary:
    """One row per app session — aggregated stats."""

    run_id:             str = ""
    sample_id:          str = ""
    package_name:       str = ""
    app_country_code:   str = ""
    app_region_group:   str = ""
    session_id:         str = ""
    session_start:      str = ""
    session_end:        str = ""
    session_duration_sec: float = 0.0

    # ── Connection counts ────────────────────────────────────────
    total_connections:      int = 0
    unique_domains:         int = 0
    unique_ips:             int = 0
    unique_countries:       int = 0
    total_bytes_sent:       int = 0
    total_bytes_rcvd:       int = 0
    error_rate:             float = 0.0

    # ── Protocol breakdown ───────────────────────────────────────
    https_count:            int = 0
    http_count:             int = 0
    quic_count:             int = 0
    dns_query_count:        int = 0
    nonstandard_port_count: int = 0

    # ── Geographic distribution ──────────────────────────────────
    country_top1_code:          str = ""
    country_top1_domain_pct:    float = 0.0
    country_top3_domain_pct:    float = 0.0
    chinese_cloud_domain_count: int = 0
    eu_domain_count:            int = 0
    us_domain_count:            int = 0
    in_domain_count:            int = 0

    # ── Tracker breakdown ────────────────────────────────────────
    known_tracker_domain_count: int = 0
    ad_network_count:           int = 0
    attribution_sdk_count:      int = 0
    analytics_domain_count:     int = 0
    data_broker_count:          int = 0
    chinese_sdk_domain_count:   int = 0
    tracker_vendor_distribution: Dict[str, int] = field(default_factory=dict)
    tracker_category_distribution: Dict[str, int] = field(default_factory=dict)
    top_tracker_vendors:        List[str] = field(default_factory=list)
    tracker_diversity:          int = 0

    # ── Security findings ────────────────────────────────────────
    cleartext_http_domain_count:    int = 0
    hardcoded_dns_detected:         bool = False
    hardcoded_dns_domain_count:     int = 0
    anti_analysis_probe_detected:   bool = False
    anti_analysis_probe_count:      int = 0
    large_download_detected:        bool = False
    large_download_max_bytes:       int = 0
    nonstandard_port_domains:       str = ""   # pipe-separated list
    doh_detected:                   bool = False

    # ── Cross-validation with manifest ──────────────────────────
    sdks_in_traffic_not_in_manifest: int = 0
    sdks_in_manifest_not_in_traffic: int = 0

    # ── PII ──────────────────────────────────────────────────────
    pii_types_detected:     int = 0
    pii_types_list:         str = ""   # pipe-separated

    # ── Data ─────────────────────────────────────────────────────
    geoip_db_version:       str = ""
    tracker_db_version:     str = ""


@dataclass
class RTBCluster:
    """One RTB auction cluster (multiple parallel ad requests)."""
    run_id:             str = ""
    sample_id:          str = ""
    cluster_id:         str = ""
    cluster_start:      str = ""
    cluster_window_ms:  int = 0
    bidder_count:       int = 0
    bidder_domains:     str = ""   # pipe-separated
    bidder_countries:   str = ""   # pipe-separated unique countries


@dataclass
class DNSRecord:
    """One DNS query observed in the session."""
    run_id:             str = ""
    sample_id:          str = ""
    query_name:         str = ""
    query_type:         str = ""
    resolver_ip:        str = ""
    is_hardcoded_resolver: bool = False
    is_anti_analysis:   bool = False
    is_doh_resolver:    bool = False
    response_ips:       str = ""   # pipe-separated
    response_count:     int = 0
    failed:             bool = False
    timestamp:          str = ""
