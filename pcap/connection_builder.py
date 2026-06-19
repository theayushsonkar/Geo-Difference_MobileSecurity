"""
connection_builder.py
──────────────────────
Builds connection, DNS, and GeoIP lookup records from raw PCAP events.
All records are structured as flat fact tables suitable for downstream
statistical and forensic analysis.
"""

import logging
import ipaddress
from dataclasses import dataclass
import tldextract

from pcap.pcap_parser import RawEvent
from pcap.tracker_matcher import match_domain
from pcap.geoip import GeoMapper
from pcap.constants import (
    HARDCODED_DNS_RESOLVERS,
    DOH_DOMAINS,
    ANTI_ANALYSIS_DOMAINS,
    STANDARD_PORTS
)

# Setup logger
logger = logging.getLogger("connection_builder")


@dataclass
class ConnectionRecord:
    """Aggregated network connection record representing a unique flow bucket."""
    sample_id: str
    session_id: str
    domain: str
    registered_domain: str
    tld: str
    subdomain: str
    dst_ip: str
    dst_port: int
    protocol: str
    connection_count: int
    payload_bytes_total: int
    first_seen: float
    last_seen: float
    tracker_matched: bool
    sdk_name: str
    sdk_vendor_country: str
    sdk_category: str
    canonical_vendor: str
    ip_country_code: str
    ip_country_name: str
    ip_asn: str
    ip_asn_org: str
    is_quic: bool
    is_tls: bool
    is_dns: bool
    is_http: bool
    is_nonstandard_port: bool
    is_hardcoded_dns: bool
    is_anti_analysis_probe: bool


@dataclass
class DNSRecord:
    """Individual DNS query or response event."""
    sample_id: str
    session_id: str
    timestamp: float
    query_name: str
    resolver_ip: str
    response_ips: list[str]
    response_count: int
    query_type: str
    is_hardcoded_resolver: bool
    is_doh_resolver: bool
    is_anti_analysis_probe: bool


@dataclass
class DomainGeoRecord:
    """Deduplicated association between a domain and a destination IP, containing GeoIP and ASN metadata."""
    domain: str
    dst_ip: str
    country_code: str
    country_name: str
    asn: str
    asn_org: str
    geoip_db_version: str


@dataclass
class BuildResult:
    """Encapsulates the structured list of records built from raw events."""
    connections: list[ConnectionRecord]
    dns_records: list[DNSRecord]
    domain_geo_records: list[DomainGeoRecord]


def _is_ip_address(val: str) -> bool:
    """Returns True if the string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(val)
        return True
    except ValueError:
        return False


class ConnectionBuilder:
    """Aggregates and enriches RawEvents into research-quality Connection, DNS, and Geo records."""

    def __init__(self, geo_mapper: GeoMapper):
        self.geo_mapper = geo_mapper

    def build(self, events: list[RawEvent], sample_id: str, session_id: str) -> BuildResult:
        """
        Transforms a list of RawEvents into structured ConnectionRecord,
        DNSRecord, and DomainGeoRecord objects.
        """
        connections: list[ConnectionRecord] = []
        dns_records: list[DNSRecord] = []
        domain_geo_records: list[DomainGeoRecord] = []

        seen_geo = set()
        buckets = {}

        # 1. First Pass: Process individual DNS events and populate aggregation buckets
        for event in events:
            # Process DNS Events (do NOT aggregate)
            if event.is_dns:
                resolver_ip = event.dst_ip if event.dst_port == 53 else event.src_ip
                
                # Check for Hardcoded DNS
                is_hardcoded_resolver = resolver_ip in HARDCODED_DNS_RESOLVERS

                # Check for DoH resolvers
                is_doh_resolver = False
                if event.dns_query:
                    for doh in DOH_DOMAINS:
                        if event.dns_query == doh or event.dns_query.endswith("." + doh):
                            is_doh_resolver = True
                            break

                # Check for Anti-Analysis Probes
                is_anti_analysis = False
                if event.dns_query:
                    for aa in ANTI_ANALYSIS_DOMAINS:
                        if event.dns_query == aa or event.dns_query.endswith("." + aa):
                            is_anti_analysis = True
                            break

                # Guess query_type (simple check)
                query_type = "A"
                response_ips = event.dns_response_ips or []
                response_count = len(response_ips)
                if response_ips:
                    # If any IP contains ':' it's IPv6 / AAAA
                    if any(":" in ip for ip in response_ips):
                        query_type = "AAAA"

                dns_rec = DNSRecord(
                    sample_id=sample_id,
                    session_id=session_id,
                    timestamp=event.timestamp,
                    query_name=event.dns_query,
                    resolver_ip=resolver_ip,
                    response_ips=response_ips,
                    response_count=response_count,
                    query_type=query_type,
                    is_hardcoded_resolver=is_hardcoded_resolver,
                    is_doh_resolver=is_doh_resolver,
                    is_anti_analysis_probe=is_anti_analysis
                )
                dns_records.append(dns_rec)

            # Deduplicate Domain-Geo lookups once per unique (domain, IP) pair
            if event.domain:
                geo_key = (event.domain, event.dst_ip)
                if geo_key not in seen_geo:
                    seen_geo.add(geo_key)
                    
                    if event.dst_ip not in self.geo_mapper._cache:
                        self.geo_mapper.lookup(event.dst_ip)
                    geo = self.geo_mapper._cache[event.dst_ip]

                    geo_rec = DomainGeoRecord(
                        domain=event.domain,
                        dst_ip=event.dst_ip,
                        country_code=geo.country_code,
                        country_name=geo.country_name,
                        asn=geo.asn,
                        asn_org=geo.asn_org,
                        geoip_db_version=self.geo_mapper.db_version
                    )
                    domain_geo_records.append(geo_rec)

            # Grouping key for connection records
            key = (
                sample_id,
                session_id,
                event.domain,
                event.dst_ip,
                event.dst_port,
                event.protocol
            )
            if key not in buckets:
                buckets[key] = []
            buckets[key].append(event)

        # 2. Second Pass: Aggregate connection records
        for key, bucket_events in buckets.items():
            domain = key[2]
            dst_ip = key[3]
            dst_port = key[4]
            protocol = key[5]

            # Domain parsing using tldextract
            if not domain or _is_ip_address(domain):
                registered_domain = ""
                tld = ""
                subdomain = ""
            else:
                ext = tldextract.extract(domain)
                registered_domain = ext.registered_domain
                tld = ext.suffix
                subdomain = ext.subdomain

            # Tracker matching
            tracker = match_domain(domain)

            # GeoIP enrichment (uses GeoMapper's own cache)
            geo = self.geo_mapper.lookup(dst_ip)

            # Port/Resolver flags
            is_nonstandard_port = str(dst_port) not in STANDARD_PORTS
            is_hardcoded_dns = dst_ip in HARDCODED_DNS_RESOLVERS

            # Anti-analysis probe check
            is_anti_analysis_probe = False
            if domain:
                for aa in ANTI_ANALYSIS_DOMAINS:
                    if domain == aa or domain.endswith("." + aa):
                        is_anti_analysis_probe = True
                        break

            # Protocol sub-flags
            is_quic = any(e.is_quic for e in bucket_events)
            is_tls = any(e.is_tls for e in bucket_events)
            is_dns = any(e.is_dns for e in bucket_events)
            is_http = any(e.is_http for e in bucket_events)

            # Times and counts
            connection_count = len(bucket_events)
            payload_bytes_total = sum(e.payload_size for e in bucket_events)
            first_seen = min(e.timestamp for e in bucket_events)
            last_seen = max(e.timestamp for e in bucket_events)

            conn_rec = ConnectionRecord(
                sample_id=sample_id,
                session_id=session_id,
                domain=domain,
                registered_domain=registered_domain,
                tld=tld,
                subdomain=subdomain,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=protocol,
                connection_count=connection_count,
                payload_bytes_total=payload_bytes_total,
                first_seen=first_seen,
                last_seen=last_seen,
                tracker_matched=tracker.matched,
                sdk_name=tracker.sdk_name,
                sdk_vendor_country=tracker.vendor_country,
                sdk_category=tracker.sdk_category,
                canonical_vendor=tracker.canonical_vendor,
                ip_country_code=geo.country_code,
                ip_country_name=geo.country_name,
                ip_asn=geo.asn,
                ip_asn_org=geo.asn_org,
                is_quic=is_quic,
                is_tls=is_tls,
                is_dns=is_dns,
                is_http=is_http,
                is_nonstandard_port=is_nonstandard_port,
                is_hardcoded_dns=is_hardcoded_dns,
                is_anti_analysis_probe=is_anti_analysis_probe
            )
            connections.append(conn_rec)

        # Logging stats
        unique_domains = len({k[2] for k in buckets.keys() if k[2]})
        unique_ips = len({k[3] for k in buckets.keys()})
        logger.info(
            "ConnectionBuilder completed: connections=%d, dns=%d, domain_geo=%d. "
            "Unique domains: %d, Unique destination IPs: %d. Geo lookups cached: %d.",
            len(connections), len(dns_records), len(domain_geo_records),
            unique_domains, unique_ips, len(self.geo_mapper._cache)
        )

        return BuildResult(
            connections=connections,
            dns_records=dns_records,
            domain_geo_records=domain_geo_records
        )
