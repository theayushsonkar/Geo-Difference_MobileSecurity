"""
CVE Run Trace Module

This module constructs and writes a metadata file (cve_trace.json) containing
execution statistics and snapshots details for reproducibility and auditing.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

# Create module logger
logger = logging.getLogger(__name__)


def _build_trace_payload(stats: dict) -> dict:
    """
    Constructs the standard JSON trace payload from input statistics.
    
    Args:
        stats: Dictionary containing execution metrics.
        
    Returns:
        A dictionary structured with run timestamp and stats fields.
    """
    # Generate run timestamp in ISO-8601 UTC format (e.g. 2026-06-16T12:30:15Z)
    run_timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    payload = {
        "run_timestamp": run_timestamp,
        "nvd_snapshot_date": stats.get("nvd_snapshot_date", None),
        "sdk_rows_processed": stats.get("sdk_rows_processed", 0),
        "sdk_rows_skipped": stats.get("sdk_rows_skipped", 0),
        "sdk_rows_matched": stats.get("sdk_rows_matched", 0),
        "unique_cves_found": stats.get("unique_cves_found", 0),
    }
    
    return payload


def write_trace(stats: dict, output_path: str | Path) -> None:
    """
    Writes the run metadata trace file to the specified output path.
    
    Args:
        stats: Dictionary containing statistics from the run.
        output_path: Target path to write the JSON trace file.
    """
    path = Path(output_path)
    
    # Construct trace payload
    payload = _build_trace_payload(stats)
    
    try:
        # Create parent directories if they don't exist
        path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write JSON payload
        with open(path, mode="w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
            
        logger.info("Trace file successfully written to %s", path)
        
    except Exception as e:
        logger.error("Failed to write trace file to %s: %s", path, e)
        raise e


if __name__ == "__main__":
    # Configure basic logging for manual test verification
    logging.basicConfig(level=logging.INFO)
    
    # Create example stats dictionary
    example_stats = {
        "nvd_snapshot_date": "2026-06-16",
        "sdk_rows_processed": 1000,
        "sdk_rows_skipped": 50,
        "sdk_rows_matched": 75,
        "unique_cves_found": 30,
    }
    
    # Define test path
    test_path = Path("output/test_cve_trace.json")
    
    print("Writing dummy trace payload to output/test_cve_trace.json...")
    write_trace(example_stats, test_path)
    print("Trace file written successfully")
