"""
app_summary.py
──────────────
Computes high-level aggregated network metrics and exposure profiles for a
given mobile app session (sample_id, session_id).
"""

import logging
from dataclasses import dataclass, field
from collections import Counter
from typing import Dict, List

from pcap.connection_builder import ConnectionRecord, DNSRecord, DomainGeoRecord

# Setup logger
logger = logging.getLogger("app_summary")


@dataclass
class AppSummary:
    """Represents the final aggregated research facts for a sample session."""
    sample_id: str
    session_id: str
    
    # Basic Volume
    total_connection_records: int
    total_connection_events: int
    total_payload_bytes: int
    session_first_seen: float
    session_last_seen: float
    session_duration_sec: float
    
    # Domain Statistics
    unique_domains: int
    unique_registered_domains: int
    unique_ips: int
    # Geographic Distribution
    destination_country_distribution: Dict[str, int]
    destination_continent_distribution: Dict[str, int]
    unique_destination_countries: int
    
    # ASN Distribution
    destination_asn_distribution: Dict[str, int]
    top_organizations: List[str]
    unique_destination_asns: int
    
    # Protocol Distribution
    dns_connection_count: int
    http_connection_count: int
    tls_connection_count: int
    quic_connection_count: int
    tcp_connection_count: int
    udp_connection_count: int
    
    # Transport Flags
    nonstandard_port_connection_count: int
    nonstandard_port_domain_count: int
    
    # Tracker Statistics
    tracker_connection_count: int
    tracker_domain_count: int
    tracker_vendor_count: int
    tracker_category_count: int
    
    # Canonical Vendor Statistics
    top_tracker_vendor: str
    top_tracker_vendor_pct: float
    tracker_vendor_distribution: Dict[str, int]
    tracker_category_distribution: Dict[str, int]
    top_tracker_vendors: List[str]
    tracker_diversity: int
    
    # DNS Statistics
    dns_query_count: int
    dns_answer_count: int
    hardcoded_dns_detected: bool
    doh_detected: bool
    
    # DNS Resolution Statistics
    avg_dns_response_count: float
    max_dns_response_count: int
    
    # DNS Provider Exposure
    dns_provider_distribution: Dict[str, int]
    dns_provider_diversity: int
    top_dns_providers: List[str]
    top_dns_provider_pct: float
    doh_capable_resolver_count: int
    dot_capable_resolver_count: int
    
    # Anti Analysis
    anti_analysis_detected: bool
    anti_analysis_domain_count: int
    # Cloud Provider Exposure
    aws_domain_count: int
    google_cloud_domain_count: int
    alibaba_domain_count: int
    tencent_domain_count: int

    # PII Detection
    pii_category_distribution: Dict[str, int]
    pii_pattern_distribution: Dict[str, int]
    unique_pii_categories: int
    unique_pii_patterns: int
    total_pii_matches: int


class AppSummaryBuilder:
    """Aggregates list of Connection, DNS, and Geo records into a single AppSummary."""

    def __init__(self):
        pass

    def build(
        self,
        connections: list[ConnectionRecord],
        dns_records: list[DNSRecord],
        domain_geo_records: list[DomainGeoRecord]
    ) -> AppSummary:
        """
        Builds a single AppSummary from raw connection, DNS, and geo-resolution lists.
        """
        # Default sample/session IDs from first available record
        sample_id = ""
        session_id = ""
        if connections:
            sample_id = connections[0].sample_id
            session_id = connections[0].session_id
        elif dns_records:
            sample_id = dns_records[0].sample_id
            session_id = dns_records[0].session_id

        # ── 1. Basic Volume ──────────────────────────────────────────────────
        total_connection_records = len(connections)
        total_connection_events = sum(c.connection_count for c in connections)
        total_payload_bytes = sum(c.payload_bytes_total for c in connections)

        if connections:
            session_first_seen = min(c.first_seen for c in connections)
            session_last_seen = max(c.last_seen for c in connections)
            session_duration_sec = session_last_seen - session_first_seen
        else:
            session_first_seen = 0.0
            session_last_seen = 0.0
            session_duration_sec = 0.0

        # ── 2. Domain Statistics ─────────────────────────────────────────────
        unique_domains = len({c.domain for c in connections if c.domain})
        unique_registered_domains = len({c.registered_domain for c in connections if c.registered_domain})
        unique_ips = len({c.dst_ip for c in connections if c.dst_ip})

        # ── 3. Geo and ASN Distribution (unique domains per entity) ──────────
        country_domains = {}
        continent_domains = {}
        asn_domains = {}
        org_domains = {}
        
        ignored_countries = {"PRIVATE", "LOCAL", "UNKNOWN", ""}
        
        for c in connections:
            if not c.domain:
                continue
            
            if c.geo_fact:
                cc = c.geo_fact.country_code
                if cc and cc.upper() not in ignored_countries:
                    country_domains.setdefault(cc, set()).add(c.domain)
                
                continent = c.geo_fact.continent
                if continent:
                    continent_domains.setdefault(continent, set()).add(c.domain)
                    
            if c.asn_fact:
                asn = c.asn_fact.asn
                if asn and asn.upper() not in ignored_countries:
                    asn_domains.setdefault(asn, set()).add(c.domain)
                
                org = c.asn_fact.organization
                if org and org.upper() not in ignored_countries:
                    org_domains.setdefault(org, set()).add(c.domain)
        
        # We also need to process domain_geo_records since they deduplicate per IP
        for r in domain_geo_records:
            if not r.domain:
                continue
            cc = r.country_code
            if cc and cc.upper() not in ignored_countries:
                country_domains.setdefault(cc, set()).add(r.domain)
            continent = r.continent
            if continent:
                continent_domains.setdefault(continent, set()).add(r.domain)
            asn = r.asn
            if asn and asn.upper() not in ignored_countries:
                asn_domains.setdefault(asn, set()).add(r.domain)
            org = r.asn_org
            if org and org.upper() not in ignored_countries:
                org_domains.setdefault(org, set()).add(r.domain)
                
        country_counts = Counter({cc: len(doms) for cc, doms in country_domains.items()})
        continent_counts = Counter({c: len(doms) for c, doms in continent_domains.items()})
        asn_counts = Counter({a: len(doms) for a, doms in asn_domains.items()})
        org_counts = Counter({o: len(doms) for o, doms in org_domains.items()})
        
        destination_country_distribution = dict(country_counts)
        destination_continent_distribution = dict(continent_counts)
        destination_asn_distribution = dict(asn_counts)
        
        unique_destination_countries = len(country_counts)
        unique_destination_asns = len(asn_counts)
        top_organizations = [org for org, _ in org_counts.most_common(5)]

        # ── 5. Protocol Distribution (packet count sums) ─────────────────────
        dns_connection_count = sum(c.connection_count for c in connections if c.is_dns)
        http_connection_count = sum(c.connection_count for c in connections if c.is_http)
        tls_connection_count = sum(c.connection_count for c in connections if c.is_tls)
        quic_connection_count = sum(c.connection_count for c in connections if c.is_quic)
        tcp_connection_count = sum(c.connection_count for c in connections if c.protocol == "TCP")
        udp_connection_count = sum(c.connection_count for c in connections if c.protocol == "UDP")

        # ── 6. Transport Flags ────────────────────────────────────────────────
        nonstandard_port_connection_count = sum(c.connection_count for c in connections if c.is_nonstandard_port)
        nonstandard_port_domain_count = len({c.domain for c in connections if c.is_nonstandard_port and c.domain})

        # ── 7. Tracker Statistics ─────────────────────────────────────────────
        tracker_connection_count = sum(c.connection_count for c in connections if c.tracker_matched)
        tracker_domain_count = len({c.domain for c in connections if c.tracker_matched and c.domain})
        tracker_vendor_count = len({c.canonical_vendor for c in connections if c.tracker_matched and c.canonical_vendor})
        tracker_category_count = len({c.sdk_category for c in connections if c.tracker_matched and c.sdk_category})

        # ── 8. Canonical Vendor Statistics (unique domains per vendor) ────────
        vendor_domains = {}
        category_counts = Counter()
        for c in connections:
            if c.tracker_matched and c.canonical_vendor and c.domain:
                vendor_domains.setdefault(c.canonical_vendor, set()).add(c.domain)
            if c.tracker_matched and c.sdk_category:
                category_counts[c.sdk_category] += c.connection_count

        vendor_domain_counts = Counter({vendor: len(doms) for vendor, doms in vendor_domains.items()})
        vendor_total_sum = sum(vendor_domain_counts.values())

        if vendor_domain_counts:
            sorted_vendors = vendor_domain_counts.most_common()
            top_tracker_vendor = sorted_vendors[0][0]
            top_tracker_vendor_pct = sorted_vendors[0][1] / vendor_total_sum if vendor_total_sum > 0 else 0.0
            top_tracker_vendors = [v[0] for v in sorted_vendors[:5]]
        else:
            top_tracker_vendor = ""
            top_tracker_vendor_pct = 0.0
            top_tracker_vendors = []
            
        tracker_vendor_distribution = dict(vendor_domain_counts)
        tracker_category_distribution = dict(category_counts)
        tracker_diversity = len(vendor_domain_counts)

        # ── 9. DNS Statistics ─────────────────────────────────────────────────
        dns_query_count = len(dns_records)
        dns_answer_count = sum(r.response_count for r in dns_records)
        hardcoded_dns_detected = any(r.is_hardcoded_resolver for r in dns_records)
        doh_detected = any(r.is_doh_resolver for r in dns_records)

        # ── 10. DNS Resolution Statistics (unique IPs resolved per domain) ──
        domain_resolved_ips = {}
        for r in dns_records:
            if r.query_name:
                domain_resolved_ips.setdefault(r.query_name, set()).update(r.response_ips)

        if domain_resolved_ips:
            resolved_counts = [len(ips) for ips in domain_resolved_ips.values()]
            avg_dns_response_count = sum(resolved_counts) / len(resolved_counts)
            max_dns_response_count = max(resolved_counts)
        else:
            avg_dns_response_count = 0.0
            max_dns_response_count = 0
            
        # ── 10b. DNS Provider Exposure ───────────────────────────────────────
        dns_provider_counts = Counter()
        for r in dns_records:
            if r.dns_resolver_fact and r.dns_resolver_fact.canonical_provider:
                dns_provider_counts[r.dns_resolver_fact.canonical_provider] += 1
                
        # Count connections that are to known resolvers (e.g. DoH)
        for c in connections:
            # If we connected directly to a resolver IP over TLS, it's likely DoH
            if c.is_tls and c.dns_resolver_fact and c.dns_resolver_fact.canonical_provider:
                dns_provider_counts[c.dns_resolver_fact.canonical_provider] += 1
                
        dns_provider_distribution = dict(dns_provider_counts)
        dns_provider_diversity = len(dns_provider_counts)
        
        if dns_provider_counts:
            sorted_providers = dns_provider_counts.most_common()
            top_dns_providers = [p[0] for p in sorted_providers[:3]]
            top_dns_provider_pct = sorted_providers[0][1] / sum(dns_provider_counts.values()) if sum(dns_provider_counts.values()) > 0 else 0.0
        else:
            top_dns_providers = []
            top_dns_provider_pct = 0.0
            
        # ── 10c. Resolver Capabilities ───────────────────────────────────────
        doh_capable_resolver_count = sum(1 for r in dns_records if r.dns_resolver_fact and r.dns_resolver_fact.supports_doh)
        dot_capable_resolver_count = sum(1 for r in dns_records if r.dns_resolver_fact and r.dns_resolver_fact.supports_dot)

        # ── 11. Anti Analysis ─────────────────────────────────────────────────
        anti_analysis_detected = (
            any(c.is_anti_analysis_probe for c in connections) or
            any(r.is_anti_analysis_probe for r in dns_records)
        )
        anti_analysis_domains = {c.domain for c in connections if c.is_anti_analysis_probe and c.domain}
        for r in dns_records:
            if r.is_anti_analysis_probe and r.query_name:
                anti_analysis_domains.add(r.query_name)
        anti_analysis_domain_count = len(anti_analysis_domains)

        # ── 13. Cloud Provider Exposure ──────────────────────────────────────
        aws_domains = set()
        google_cloud_domains = set()
        alibaba_domains = set()
        tencent_domains = set()

        for r in domain_geo_records:
            if not r.domain or not r.asn_org:
                continue
            org = r.asn_org.lower()
            if "amazon" in org or "aws" in org:
                aws_domains.add(r.domain)
            if "google" in org:
                google_cloud_domains.add(r.domain)
            if "alibaba" in org or "aliyun" in org:
                alibaba_domains.add(r.domain)
            if "tencent" in org or "qcloud" in org:
                tencent_domains.add(r.domain)

        aws_domain_count = len(aws_domains)
        google_cloud_domain_count = len(google_cloud_domains)
        alibaba_domain_count = len(alibaba_domains)
        tencent_domain_count = len(tencent_domains)

        # ── 14. PII Detection ────────────────────────────────────────────────
        pii_category_counts = Counter()
        pii_pattern_counts = Counter()
        total_pii_matches = 0
        
        for c in connections:
            for pii in c.pii_facts:
                pii_category_counts[pii.category] += 1
                pii_pattern_counts[pii.pattern_name] += 1
                total_pii_matches += 1
                
        pii_category_distribution = dict(pii_category_counts)
        pii_pattern_distribution = dict(pii_pattern_counts)
        unique_pii_categories = len(pii_category_counts)
        unique_pii_patterns = len(pii_pattern_counts)

        # Logging stats as required
        logger.info("Domains counted: %d", unique_domains)
        logger.info("Countries counted: %d", unique_destination_countries)
        logger.info("Trackers counted: %d", tracker_domain_count)
        logger.info("Summary generated: sample=%s, session=%s", sample_id, session_id)

        return AppSummary(
            sample_id=sample_id,
            session_id=session_id,
            total_connection_records=total_connection_records,
            total_connection_events=total_connection_events,
            total_payload_bytes=total_payload_bytes,
            session_first_seen=session_first_seen,
            session_last_seen=session_last_seen,
            session_duration_sec=session_duration_sec,
            unique_domains=unique_domains,
            unique_registered_domains=unique_registered_domains,
            unique_ips=unique_ips,
            unique_destination_countries=unique_destination_countries,
            unique_destination_asns=unique_destination_asns,
            destination_country_distribution=destination_country_distribution,
            destination_continent_distribution=destination_continent_distribution,
            destination_asn_distribution=destination_asn_distribution,
            top_organizations=top_organizations,
            dns_connection_count=dns_connection_count,
            http_connection_count=http_connection_count,
            tls_connection_count=tls_connection_count,
            quic_connection_count=quic_connection_count,
            tcp_connection_count=tcp_connection_count,
            udp_connection_count=udp_connection_count,
            nonstandard_port_connection_count=nonstandard_port_connection_count,
            nonstandard_port_domain_count=nonstandard_port_domain_count,
            tracker_connection_count=tracker_connection_count,
            tracker_domain_count=tracker_domain_count,
            tracker_vendor_count=tracker_vendor_count,
            tracker_category_count=tracker_category_count,
            top_tracker_vendor=top_tracker_vendor,
            top_tracker_vendor_pct=top_tracker_vendor_pct,
            tracker_vendor_distribution=tracker_vendor_distribution,
            tracker_category_distribution=tracker_category_distribution,
            top_tracker_vendors=top_tracker_vendors,
            tracker_diversity=tracker_diversity,
            dns_query_count=dns_query_count,
            dns_answer_count=dns_answer_count,
            hardcoded_dns_detected=hardcoded_dns_detected,
            doh_detected=doh_detected,
            avg_dns_response_count=avg_dns_response_count,
            max_dns_response_count=max_dns_response_count,
            dns_provider_distribution=dns_provider_distribution,
            dns_provider_diversity=dns_provider_diversity,
            top_dns_providers=top_dns_providers,
            top_dns_provider_pct=top_dns_provider_pct,
            doh_capable_resolver_count=doh_capable_resolver_count,
            dot_capable_resolver_count=dot_capable_resolver_count,
            anti_analysis_detected=anti_analysis_detected,
            anti_analysis_domain_count=anti_analysis_domain_count,
            aws_domain_count=aws_domain_count,
            google_cloud_domain_count=google_cloud_domain_count,
            alibaba_domain_count=alibaba_domain_count,
            tencent_domain_count=tencent_domain_count,
            pii_category_distribution=pii_category_distribution,
            pii_pattern_distribution=pii_pattern_distribution,
            unique_pii_categories=unique_pii_categories,
            unique_pii_patterns=unique_pii_patterns,
            total_pii_matches=total_pii_matches
        )
