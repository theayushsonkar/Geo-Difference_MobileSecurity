"""
run_pcap_analysis.py
────────────────────
Coordinates the PCAP analysis pipeline across a folder of samples.
Generates fact table CSVs and a detailed, reproducible pcap_trace.json metadata report.

V1 Final — All audit fixes applied.
"""

import os
import sys
import csv
import json
import uuid
import time
import datetime
import argparse
import logging
from pathlib import Path
import pandas as pd

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stdout
)
logger = logging.getLogger("run_pcap_analysis")

# Add workspace to path
workspace_dir = Path(__file__).resolve().parent
sys.path.append(str(workspace_dir))

from pcap.pcap_parser import parse_pcap
from pcap.geoip import GeoMapper
from pcap.connection_builder import ConnectionBuilder
from pcap.app_summary import AppSummaryBuilder


# ─────────────────────────────────────────────────────────────────────────────
# SAMPLE INDEX LOADER  (Fix 1)
# ─────────────────────────────────────────────────────────────────────────────

def load_sample_index(index_path: Path) -> dict:
    """
    Loads sample_index.csv and returns a dict keyed by sample_id.
    Each value is a row containing package_name, app_country_code, etc.
    If the file does not exist, returns an empty dict.
    """
    if not index_path.exists():
        logger.warning("sample_index.csv not found at %s — metadata will use defaults", index_path)
        return {}

    try:
        df = pd.read_csv(index_path)
        df.columns = df.columns.str.strip()
        df["sample_id"] = (
            df["sample_id"]
              .astype(str)
              .str.strip()
        )
        sample_lookup = {
            str(row["sample_id"]).strip(): row
            for _, row in df.iterrows()
        }
        logger.info("Loaded sample index with %d entries from %s", len(sample_lookup), index_path)
        return sample_lookup
    except Exception as e:
        logger.error("Failed to load sample index: %s", e)
        return {}


def _get_sample_meta(sample_id: str, sample_index: dict) -> tuple:
    """
    Returns (package_name, app_country_code) for a given sample_id.
    Falls back to sample_id / "" if not found in the index, logging a warning.
    """
    metadata = sample_index.get(sample_id)
    if metadata is not None:
        pkg = metadata.get("package_name")
        cc = metadata.get("app_country_code")
        pkg_str = str(pkg).strip() if pd.notna(pkg) else sample_id
        cc_str = str(cc).strip() if pd.notna(cc) else ""
        return pkg_str, cc_str
    else:
        logger.warning("WARNING:\nNo sample_index entry found for sample_id=%s", sample_id)
        return sample_id, ""


# ─────────────────────────────────────────────────────────────────────────────
# DISCOVERY SOURCE LOGIC  (Fix 3)
# ─────────────────────────────────────────────────────────────────────────────
# Priority:
#   1. dns_query   — domain found via DNS query/response parsing
#   2. http_host   — domain found via cleartext HTTP Host header
#   3. tls_sni     — domain found via TLS ClientHello SNI extension
#   4. quic        — QUIC connection (domain may come from DNS or be absent)
#   5. unknown     — no application-layer protocol identified
# ─────────────────────────────────────────────────────────────────────────────

def _derive_discovery_source(conn) -> str:
    """Derives the discovery_source from the connection's protocol evidence flags."""
    if conn.is_dns:
        return "dns_query"
    if conn.is_http:
        return "http_host"
    if conn.is_tls:
        return "tls_sni"
    if conn.is_quic:
        return "quic"
    return "unknown"


# ─────────────────────────────────────────────────────────────────────────────
# CSV MAPPING FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def map_connection(conn, run_id: str, geoip_version: str, pcap_filename: str,
                   package_name: str, app_country_code: str) -> dict:
    """Maps a ConnectionRecord to a flat dict for CSV export."""
    try:
        first_dt = datetime.datetime.fromtimestamp(conn.first_seen, datetime.timezone.utc).isoformat()
        last_dt = datetime.datetime.fromtimestamp(conn.last_seen, datetime.timezone.utc).isoformat()
    except Exception:
        first_dt = str(conn.first_seen)
        last_dt = str(conn.last_seen)

    return {
        "run_id": run_id,
        "schema_version": "1.0",
        "parser_version": "1.0",
        "sample_id": conn.sample_id,
        "package_name": package_name,                       # Fix 1
        "app_country_code": app_country_code,               # Fix 1
        "session_id": conn.session_id,
        "pcap_file": pcap_filename,
        "session_start": first_dt,
        "session_end": last_dt,
        "session_duration_sec": conn.last_seen - conn.first_seen,
        "domain": conn.domain,
        "registered_domain": conn.registered_domain,
        "tld": conn.tld,
        "subdomain": conn.subdomain,
        "dst_ip": conn.dst_ip,
        "dst_port": str(conn.dst_port),
        "protocol": conn.protocol,
        "discovery_source": _derive_discovery_source(conn), # Fix 3
        "connection_count": conn.connection_count,
        "payload_bytes_total": conn.payload_bytes_total,    # Fix 2
        "first_seen": first_dt,
        "last_seen": last_dt,
        "ip_country_code": conn.ip_country_code,
        "ip_country_name": conn.ip_country_name,
        "ip_asn": conn.ip_asn,
        "ip_asn_org": conn.ip_asn_org,
        "sdk_name": conn.sdk_name,
        "sdk_vendor_country": conn.sdk_vendor_country,
        "sdk_category": conn.sdk_category,
        "canonical_vendor": conn.canonical_vendor,
        "is_known_tracker": conn.tracker_matched,
        "is_cleartext_http": conn.is_http and not conn.is_quic,
        "is_tls": conn.is_tls,                             # Fix 4
        "is_quic": conn.is_quic,
        "is_dns": conn.is_dns,
        "is_nonstandard_port": conn.is_nonstandard_port,    # Use upstream value (Fix 4 audit)
        "is_hardcoded_dns": conn.is_hardcoded_dns,
        "is_anti_analysis_probe": conn.is_anti_analysis_probe,
        "geoip_db_version": geoip_version
    }


def map_dns(dns, run_id: str) -> dict:
    """Maps a DNSRecord to a flat dict for CSV export."""
    try:
        ts_str = datetime.datetime.fromtimestamp(dns.timestamp, datetime.timezone.utc).isoformat()
    except Exception:
        ts_str = str(dns.timestamp)

    return {
        "run_id": run_id,
        "sample_id": dns.sample_id,
        "query_name": dns.query_name,
        "query_type": dns.query_type,
        "resolver_ip": dns.resolver_ip,
        "is_hardcoded_resolver": dns.is_hardcoded_resolver,
        "is_anti_analysis": dns.is_anti_analysis_probe,
        "is_doh_resolver": dns.is_doh_resolver,
        "response_ips": "|".join(dns.response_ips) if isinstance(dns.response_ips, list) else str(dns.response_ips),
        "response_count": dns.response_count,
        "failed": False,
        "timestamp": ts_str
    }


def map_summary(summary, run_id: str, tracker_db_version: str, geoip_version: str,
                package_name: str, app_country_code: str) -> dict:
    """Maps an AppSummary to a flat dict for CSV export.
    
    Fix 5: Uses explicit tls_connection_count instead of incorrect tcp-http derivation.
    Fix 9: Removes permanently-zero placeholder columns that were never implemented.
    """
    try:
        start_str = datetime.datetime.fromtimestamp(summary.session_first_seen, datetime.timezone.utc).isoformat()
        end_str = datetime.datetime.fromtimestamp(summary.session_last_seen, datetime.timezone.utc).isoformat()
    except Exception:
        start_str = str(summary.session_first_seen)
        end_str = str(summary.session_last_seen)

    return {
        "run_id": run_id,
        "sample_id": summary.sample_id,
        "package_name": package_name,                       # Fix 1
        "app_country_code": app_country_code,               # Fix 1
        "session_id": summary.session_id,
        "session_start": start_str,
        "session_end": end_str,
        "session_duration_sec": summary.session_duration_sec,
        # Volume
        "total_connection_records": summary.total_connection_records,
        "total_connection_events": summary.total_connection_events,
        "total_payload_bytes": summary.total_payload_bytes,
        "unique_domains": summary.unique_domains,
        "unique_registered_domains": summary.unique_registered_domains,
        "unique_ips": summary.unique_ips,
        "unique_countries": summary.unique_countries,
        "unique_asns": summary.unique_asns,
        # Protocol
        "tls_connection_count": summary.tls_connection_count,   # Fix 5
        "http_connection_count": summary.http_connection_count,
        "quic_connection_count": summary.quic_connection_count,
        "dns_connection_count": summary.dns_connection_count,
        "tcp_connection_count": summary.tcp_connection_count,
        "udp_connection_count": summary.udp_connection_count,
        "nonstandard_port_connection_count": summary.nonstandard_port_connection_count,
        "nonstandard_port_domain_count": summary.nonstandard_port_domain_count,
        # Country
        "country_top1_code": summary.country_top1_code,
        "country_top1_pct": summary.country_top1_pct,
        "country_top3_pct": summary.country_top3_pct,
        "high_risk_country_domain_count": summary.high_risk_country_domain_count,
        "high_risk_country_pct": summary.high_risk_country_pct,
        # ASN
        "top_asn": summary.top_asn,
        "top_asn_pct": summary.top_asn_pct,
        # Cloud
        "aws_domain_count": summary.aws_domain_count,
        "google_cloud_domain_count": summary.google_cloud_domain_count,
        "alibaba_domain_count": summary.alibaba_domain_count,
        "tencent_domain_count": summary.tencent_domain_count,
        # Tracker
        "tracker_connection_count": summary.tracker_connection_count,
        "tracker_domain_count": summary.tracker_domain_count,
        "tracker_vendor_count": summary.tracker_vendor_count,
        "tracker_category_count": summary.tracker_category_count,
        "top_tracker_vendor": summary.top_tracker_vendor,
        "top_tracker_vendor_pct": summary.top_tracker_vendor_pct,
        # DNS
        "dns_query_count": summary.dns_query_count,
        "dns_answer_count": summary.dns_answer_count,
        "avg_dns_response_count": summary.avg_dns_response_count,
        "max_dns_response_count": summary.max_dns_response_count,
        "hardcoded_dns_detected": summary.hardcoded_dns_detected,
        "doh_detected": summary.doh_detected,
        # Anti-analysis
        "anti_analysis_detected": summary.anti_analysis_detected,
        "anti_analysis_domain_count": summary.anti_analysis_domain_count,
        # Metadata
        "geoip_db_version": geoip_version,
        "tracker_db_version": tracker_db_version,
    }


# ─────────────────────────────────────────────────────────────────────────────
# MAIN PIPELINE
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="PCAP Analysis Pipeline Coordinator")
    parser.add_argument("--input-dir", default="data/pcap", help="Input directory containing PCAP files")
    parser.add_argument("--output-dir", default="output/pcap", help="Output directory for CSVs and trace log")
    parser.add_argument("--sample-index", default="sample_index.csv", help="Path to sample_index.csv for metadata lookup")
    args = parser.parse_args()

    input_path = Path(args.input_dir)
    output_path = Path(args.output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Fix 1: Load sample metadata
    sample_index = load_sample_index(Path(args.sample_index))

    run_id = str(uuid.uuid4())
    run_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    start_time = time.time()

    samples_processed = 0
    samples_failed = 0
    errors = []

    all_conns = []
    all_dns = []
    all_geo = []
    all_summaries = []

    # Initialize enrichment classes
    geo_mapper = GeoMapper()
    conn_builder = ConnectionBuilder(geo_mapper)
    summary_builder = AppSummaryBuilder()

    pcap_files = list(input_path.glob("*.pcap"))
    logger.info("Starting run %s. Found %d PCAP files in %s", run_id, len(pcap_files), input_path)

    for pcap_file in pcap_files:
        sample_id = pcap_file.stem.strip()
        # Fix 7: Deterministic, unique session_id per sample
        session_id = f"{sample_id}_session_1"

        # Fix 1: Resolve metadata from sample index
        package_name, app_country_code = _get_sample_meta(sample_id, sample_index)

        logger.info("Processing sample %s (%s) [pkg=%s, cc=%s]",
                     sample_id, pcap_file.name, package_name, app_country_code)
        try:
            # Validate PCAP or PCAPNG format
            import dpkt
            with open(pcap_file, "rb") as f:
                try:
                    dpkt.pcap.Reader(f)
                except Exception:
                    f.seek(0)
                    try:
                        dpkt.pcapng.Reader(f)
                    except Exception:
                        raise ValueError("Invalid PCAP/PCAPNG format")

            # 1. Parse PCAP
            events = parse_pcap(pcap_file)

            # 2. Build Connection Records
            build_result = conn_builder.build(events, sample_id, session_id)

            # 3. Build App Summary
            summary = summary_builder.build(
                connections=build_result.connections,
                dns_records=build_result.dns_records,
                domain_geo_records=build_result.domain_geo_records
            )

            # 4. Map & Append Connection Records
            for c in build_result.connections:
                all_conns.append(map_connection(
                    c, run_id, geo_mapper.db_version, pcap_file.name,
                    package_name, app_country_code
                ))

            # 5. Map & Append DNS Records
            for d in build_result.dns_records:
                all_dns.append(map_dns(d, run_id))

            # 6. Map & Append Domain Geo Records
            for g in build_result.domain_geo_records:
                all_geo.append({
                    "domain": g.domain,
                    "dst_ip": g.dst_ip,
                    "country_code": g.country_code,
                    "country_name": g.country_name,
                    "asn": g.asn,
                    "asn_org": g.asn_org,
                    "geoip_db_version": g.geoip_db_version
                })

            # 7. Map & Append Summary
            all_summaries.append(map_summary(
                summary, run_id, "1.0", geo_mapper.db_version,
                package_name, app_country_code
            ))

            samples_processed += 1
            logger.info("Successfully processed sample %s", sample_id)

        except Exception as e:
            logger.error("Failed to process sample %s: %s", sample_id, str(e))
            samples_failed += 1
            errors.append({
                "sample_id": sample_id,
                "error": str(e)
            })

    geo_mapper.close()
    end_time = time.time()
    processing_time_sec = end_time - start_time

    # Write CSV Output Files
    if all_conns:
        pd.DataFrame(all_conns).to_csv(output_path / "pcap_connections.csv", index=False)
    if all_dns:
        pd.DataFrame(all_dns).to_csv(output_path / "pcap_dns.csv", index=False)
    if all_geo:
        pd.DataFrame(all_geo).to_csv(output_path / "pcap_domain_geo.csv", index=False)
    if all_summaries:
        pd.DataFrame(all_summaries).to_csv(output_path / "pcap_app_summary.csv", index=False)

    # Compile Trace Report
    trace_data = {
        "run_id": run_id,
        "run_timestamp": run_timestamp,
        "samples_processed": samples_processed,
        "samples_failed": samples_failed,
        "connections_generated": len(all_conns),
        "dns_records_generated": len(all_dns),
        "domain_geo_records_generated": len(all_geo),
        "app_summaries_generated": len(all_summaries),
        "pcap_parser_version": "1.0",
        "tracker_db_version": "1.0",
        "geoip_db_version": geo_mapper.db_version,
        "input_directory": str(input_path.resolve()),
        "output_directory": str(output_path.resolve()),
        "processing_time_sec": float(processing_time_sec),
        "errors": errors
    }

    # Write Trace Report to JSON
    trace_file = output_path / "pcap_trace.json"
    with open(trace_file, "w") as f:
        json.dump(trace_data, f, indent=2)

    logger.info("Run %s complete. Processed=%d, Failed=%d, Time=%.2f sec",
                run_id, samples_processed, samples_failed, processing_time_sec)
    logger.info("Trace log written to %s", trace_file)

if __name__ == "__main__":
    main()
