"""
CVE Pipeline Runner

This module orchestrates the entire CVE matching pipeline, loading NVD data,
matching detected SDKs from manifest_sdks.csv, generating application summaries,
writing CSV results, and writing run trace metadata.
"""

from __future__ import annotations

import csv
import dataclasses
import logging
from datetime import datetime
from pathlib import Path
import pandas as pd

from cve.schemas import CVEMatch, CoverageRecord
from cve.nvd_loader import load_nvd, build_indexes
from cve.matcher import match_sdks_to_cves
from cve.aggregator import generate_app_summary
from cve.trace import write_trace

# Create module logger
logger = logging.getLogger(__name__)


def _write_matches_csv(matches: list[CVEMatch], output_path: Path) -> None:
    """
    Writes CVEMatch objects to a CSV file.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    # Sort matches by sample_id, sdk_identifier, cve_id
    sorted_matches = sorted(
        matches,
        key=lambda m: (m.sample_id or "", m.sdk_identifier or "", m.cve_id or "")
    )
    fieldnames = [f.name for f in dataclasses.fields(CVEMatch)]
    with open(output_path, mode="w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for m in sorted_matches:
            writer.writerow(dataclasses.asdict(m))


def _write_coverage_csv(records: list[CoverageRecord], output_path: Path) -> None:
    """
    Writes CoverageRecord objects to a CSV file.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    # Sort records by sample_id, sdk_identifier
    sorted_records = sorted(
        records,
        key=lambda r: (r.sample_id or "", r.sdk_identifier or "")
    )
    fieldnames = [f.name for f in dataclasses.fields(CoverageRecord)]
    with open(output_path, mode="w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in sorted_records:
            writer.writerow(dataclasses.asdict(r))


def _build_trace_stats(
    matches: list[CVEMatch],
    coverage_records: list[CoverageRecord],
    nvd_snapshot_date: str,
    manifest_sdks_csv: Path,
) -> dict:
    """
    Builds statistics dictionary from matching results.
    """
    sdk_rows_processed = 0
    if manifest_sdks_csv.exists():
        try:
            with open(manifest_sdks_csv, mode="r", encoding="utf-8", newline="") as f:
                reader = csv.reader(f)
                header = next(reader, None)
                if header:
                    sdk_rows_processed = sum(1 for _ in reader)
        except Exception as e:
            logger.warning("Failed to count lines in %s: %s", manifest_sdks_csv, e)

    # Compute unique SDK rows that matched (sample_id, sdk_identifier)
    matched_keys = {(m.sample_id, m.sdk_identifier) for m in matches}
    sdk_rows_matched = len(matched_keys)

    # Compute unique CVE IDs found
    unique_cves = {m.cve_id for m in matches}
    unique_cves_found = len(unique_cves)

    stats = {
        "nvd_snapshot_date": nvd_snapshot_date,
        "sdk_rows_processed": sdk_rows_processed,
        "sdk_rows_skipped": len(coverage_records),
        "sdk_rows_matched": sdk_rows_matched,
        "unique_cves_found": unique_cves_found,
    }
    return stats


def run_pipeline() -> None:
    """
    Orchestrates and executes the complete CVE pipeline:
      1. Load NVD data.
      2. Build search lookup indexes.
      3. Perform SDK-to-CVE matching on manifest_sdks.csv.
      4. Write matching results and coverage records.
      5. Aggregate matches to app summaries.
      6. Write run trace metadata.
    """
    logger.info("Starting CVE pipeline execution...")
    
    # Input/Output paths
    manifest_sdks_csv = Path("output/manifest_sdks.csv")
    sdk_cve_matches_csv = Path("output/sdk_cve_matches.csv")
    cve_coverage_report_csv = Path("output/cve_coverage_report.csv")
    app_cve_summary_csv = Path("output/app_cve_summary.csv")
    cve_trace_json = Path("output/cve_trace.json")

    # Target output dir creation
    cve_trace_json.parent.mkdir(parents=True, exist_ok=True)

    try:
        # Determine current snapshot date
        nvd_snapshot_date = datetime.now().strftime("%Y-%m-%d")

        # Step 1: Load NVD records
        nvd_records = load_nvd("data/nvd")
        logger.info("Loaded %d reference NVD records", len(nvd_records))

        # Step 2: Build NVD search indexes
        indexes = build_indexes(nvd_records)
        vendor_index = indexes.get("vendor", {})
        product_index = indexes.get("product", {})
        logger.info(
            "Built indexes containing %d vendors and %d products",
            len(vendor_index),
            len(product_index)
        )

        # Step 4: Run matcher (Step 3: load sdk is handled inside match_sdks_to_cves)
        logger.info("Matching SDK records from %s to CVE reference index...", manifest_sdks_csv)
        matches, coverage_records = match_sdks_to_cves(
            manifest_sdks_csv=manifest_sdks_csv,
            vendor_index=vendor_index,
            product_index=product_index,
            nvd_snapshot_date=nvd_snapshot_date,
            exclude_androidx=False
        )

        # Step 5: Write output/sdk_cve_matches.csv
        logger.info("Writing matches to %s...", sdk_cve_matches_csv)
        _write_matches_csv(matches, sdk_cve_matches_csv)

        # Step 6: Write output/cve_coverage_report.csv
        logger.info("Writing coverage report to %s...", cve_coverage_report_csv)
        _write_coverage_csv(coverage_records, cve_coverage_report_csv)

        # Step 7: Generate app summary
        logger.info("Generating application-level CVE summary...")
        app_summary_df = generate_app_summary(matches)

        # Step 8: Write output/app_cve_summary.csv
        logger.info("Writing app summary to %s...", app_cve_summary_csv)
        app_summary_df.to_csv(app_cve_summary_csv, index=False)

        # Step 9: Generate trace statistics
        logger.info("Building run trace statistics...")
        stats = _build_trace_stats(
            matches=matches,
            coverage_records=coverage_records,
            nvd_snapshot_date=nvd_snapshot_date,
            manifest_sdks_csv=manifest_sdks_csv
        )

        # Step 10: Write output/cve_trace.json
        logger.info("Writing pipeline run trace file to %s...", cve_trace_json)
        write_trace(stats, cve_trace_json)

        logger.info("CVE analysis pipeline completed successfully.")

    except Exception as e:
        logger.error("CVE pipeline run failed with an unhandled exception: %s", e, exc_info=True)
        raise e


if __name__ == "__main__":
    # Configure logging layout and levels
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    run_pipeline()
