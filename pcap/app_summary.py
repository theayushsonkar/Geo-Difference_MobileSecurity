"""
app_summary.py
──────────────
Computes high-level aggregated network metrics and exposure profiles for a
given mobile app session (sample_id, session_id).
"""

import logging
from dataclasses import dataclass
from collections import Counter

from pcap.connection_builder import ConnectionRecord, DNSRecord, DomainGeoRecord
from pcap.constants import HIGH_RISK_COUNTRIES

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
    unique_countries: int
    unique_asns: int
    
    # Country Distribution
    country_top1_code: str
    country_top1_pct: float
    country_top3_pct: float
    
    # ASN Distribution
    top_asn: str
    top_asn_pct: float
    
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
    
    # DNS Statistics
    dns_query_count: int
    dns_answer_count: int
    hardcoded_dns_detected: bool
    doh_detected: bool
    
    # DNS Resolution Statistics
    avg_dns_response_count: float
    max_dns_response_count: int
    
    # Anti Analysis
    anti_analysis_detected: bool
    anti_analysis_domain_count: int
    
    # Geographic Exposure
    high_risk_country_domain_count: int
    high_risk_country_pct: float
    
    # Cloud Provider Exposure
    aws_domain_count: int
    google_cloud_domain_count: int
    alibaba_domain_count: int
    tencent_domain_count: int


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

        # Combine country/asn references from both connection and geo tables for completeness
        ignored_countries = {"PRIVATE", "LOCAL", "UNKNOWN"}
        unique_countries_set = {
            c.ip_country_code for c in connections 
            if c.ip_country_code and c.ip_country_code.upper() not in ignored_countries
        }
        unique_countries_set.update(
            r.country_code for r in domain_geo_records 
            if r.country_code and r.country_code.upper() not in ignored_countries
        )
        unique_countries = len(unique_countries_set)

        unique_asns_set = {c.ip_asn for c in connections if c.ip_asn}
        unique_asns_set.update(r.asn for r in domain_geo_records if r.asn)
        unique_asns = len(unique_asns_set)

        # ── 3. Country Distribution (unique domains per country) ─────────────
        country_domains = {}
        for r in domain_geo_records:
            if r.domain and r.country_code:
                cc = r.country_code.upper()
                if cc not in ignored_countries:
                    country_domains.setdefault(r.country_code, set()).add(r.domain)

        country_domain_counts = Counter({cc: len(doms) for cc, doms in country_domains.items()})
        country_total_sum = sum(country_domain_counts.values())

        if country_domain_counts:
            sorted_countries = country_domain_counts.most_common()
            country_top1_code = sorted_countries[0][0]
            country_top1_pct = sorted_countries[0][1] / country_total_sum if country_total_sum > 0 else 0.0
            
            top3_sum = sum(count for _, count in sorted_countries[:3])
            country_top3_pct = top3_sum / country_total_sum if country_total_sum > 0 else 0.0
        else:
            country_top1_code = ""
            country_top1_pct = 0.0
            country_top3_pct = 0.0

        # ── 4. ASN Distribution (unique domains per ASN) ──────────────────────
        asn_domains = {}
        for r in domain_geo_records:
            if r.domain and r.asn:
                asn_domains.setdefault(r.asn, set()).add(r.domain)

        asn_domain_counts = Counter({asn: len(doms) for asn, doms in asn_domains.items()})
        asn_total_sum = sum(asn_domain_counts.values())

        if asn_domain_counts:
            sorted_asns = asn_domain_counts.most_common()
            top_asn = sorted_asns[0][0]
            top_asn_pct = sorted_asns[0][1] / asn_total_sum if asn_total_sum > 0 else 0.0
        else:
            top_asn = ""
            top_asn_pct = 0.0

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
        for c in connections:
            if c.tracker_matched and c.canonical_vendor and c.domain:
                vendor_domains.setdefault(c.canonical_vendor, set()).add(c.domain)

        vendor_domain_counts = Counter({vendor: len(doms) for vendor, doms in vendor_domains.items()})
        vendor_total_sum = sum(vendor_domain_counts.values())

        if vendor_domain_counts:
            sorted_vendors = vendor_domain_counts.most_common()
            top_tracker_vendor = sorted_vendors[0][0]
            top_tracker_vendor_pct = sorted_vendors[0][1] / vendor_total_sum if vendor_total_sum > 0 else 0.0
        else:
            top_tracker_vendor = ""
            top_tracker_vendor_pct = 0.0

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

        # ── 12. Geographic Exposure (data sovereignty risk check) ──────────
        high_risk_domains = set()
        for r in domain_geo_records:
            if r.domain and r.country_code in HIGH_RISK_COUNTRIES:
                high_risk_domains.add(r.domain)
        high_risk_country_domain_count = len(high_risk_domains)
        high_risk_country_pct = high_risk_country_domain_count / unique_domains if unique_domains > 0 else 0.0

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

        # Logging stats as required
        logger.info("Domains counted: %d", unique_domains)
        logger.info("Countries counted: %d", unique_countries)
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
            unique_countries=unique_countries,
            unique_asns=unique_asns,
            country_top1_code=country_top1_code,
            country_top1_pct=country_top1_pct,
            country_top3_pct=country_top3_pct,
            top_asn=top_asn,
            top_asn_pct=top_asn_pct,
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
            dns_query_count=dns_query_count,
            dns_answer_count=dns_answer_count,
            hardcoded_dns_detected=hardcoded_dns_detected,
            doh_detected=doh_detected,
            avg_dns_response_count=avg_dns_response_count,
            max_dns_response_count=max_dns_response_count,
            anti_analysis_detected=anti_analysis_detected,
            anti_analysis_domain_count=anti_analysis_domain_count,
            high_risk_country_domain_count=high_risk_country_domain_count,
            high_risk_country_pct=high_risk_country_pct,
            aws_domain_count=aws_domain_count,
            google_cloud_domain_count=google_cloud_domain_count,
            alibaba_domain_count=alibaba_domain_count,
            tencent_domain_count=tencent_domain_count
        )
