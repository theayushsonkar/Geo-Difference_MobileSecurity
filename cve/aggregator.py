"""
CVE Aggregator Module

This module performs application-level aggregation of CVE matches.
It summarizes CVEMatch records into high-level counts per sample application,
including total matches, unique CVEs, and unique affected SDKs.
"""

from __future__ import annotations

import dataclasses
import logging
import pandas as pd

from cve.schemas import CVEMatch

# Create module logger
logger = logging.getLogger(__name__)


def generate_app_summary(matches: list[CVEMatch]) -> pd.DataFrame:
    """
    Summarizes CVEMatch records to application-level rows.
    
    Args:
        matches: A list of CVEMatch records.
        
    Returns:
        A pandas.DataFrame containing the aggregated stats per sample_id.
    """
    columns = [
        "sample_id",
        "total_cve_matches",
        "unique_cve_count",
        "affected_sdk_count",
        "nvd_snapshot_date",
    ]
    
    logger.info("Received %d CVEMatch records for aggregation", len(matches))
    
    if not matches:
        logger.info("Empty matches list received. Returning empty DataFrame.")
        return pd.DataFrame(columns=columns)

    # 1. Convert list[CVEMatch] into a pandas DataFrame using list of dicts
    data = []
    for m in matches:
        data.append({
            "sample_id": m.sample_id,
            "sdk_identifier": m.sdk_identifier,
            "cve_id": m.cve_id,
            "nvd_snapshot_date": m.nvd_snapshot_date,
        })
    df = pd.DataFrame(data)

    # 2. Group by sample_id and compute aggregations
    summary = df.groupby("sample_id").agg(
        total_cve_matches=("cve_id", "count"),
        unique_cve_count=("cve_id", "nunique"),
        affected_sdk_count=("sdk_identifier", "nunique"),
        nvd_snapshot_date=("nvd_snapshot_date", "first")
    ).reset_index()

    # 3. Sort output by sample_id and reset index
    summary = summary.sort_values("sample_id").reset_index(drop=True)
    
    # Reorder columns to match requested output schema exactly
    summary = summary[columns]

    logger.info(
        "Summarized %d unique applications; returning %d rows",
        len(summary),
        len(summary)
    )

    return summary


if __name__ == "__main__":
    # Configure basic logging for manual test verification
    logging.basicConfig(level=logging.INFO)
    
    # Create dummy CVEMatch records matching the specification example
    dummy_matches = [
        CVEMatch(
            sample_id="app1",
            package_name="com.test.app1",
            sdk_name="Firebase",
            sdk_identifier="firebase",
            sdk_version="1.0.0",
            cve_id="CVE-1",
            published_date=None,
            last_modified_date=None,
            cvss_version=None,
            cvss_score=None,
            severity=None,
            cvss_vector=None,
            affected_version_range=None,
            nvd_snapshot_date="2026-06-16",
        ),
        CVEMatch(
            sample_id="app1",
            package_name="com.test.app1",
            sdk_name="Firebase",
            sdk_identifier="firebase",
            sdk_version="1.0.0",
            cve_id="CVE-2",
            published_date=None,
            last_modified_date=None,
            cvss_version=None,
            cvss_score=None,
            severity=None,
            cvss_vector=None,
            affected_version_range=None,
            nvd_snapshot_date="2026-06-16",
        ),
        CVEMatch(
            sample_id="app1",
            package_name="com.test.app1",
            sdk_name="OkHttp",
            sdk_identifier="okhttp",
            sdk_version="3.0.0",
            cve_id="CVE-2",
            published_date=None,
            last_modified_date=None,
            cvss_version=None,
            cvss_score=None,
            severity=None,
            cvss_vector=None,
            affected_version_range=None,
            nvd_snapshot_date="2026-06-16",
        ),
        CVEMatch(
            sample_id="app2",
            package_name="com.test.app2",
            sdk_name="OkHttp",
            sdk_identifier="okhttp",
            sdk_version="3.0.0",
            cve_id="CVE-3",
            published_date=None,
            last_modified_date=None,
            cvss_version=None,
            cvss_score=None,
            severity=None,
            cvss_vector=None,
            affected_version_range=None,
            nvd_snapshot_date="2026-06-16",
        ),
    ]
    
    print("Running generate_app_summary with dummy records...")
    df_summary = generate_app_summary(dummy_matches)
    print("\nResulting DataFrame:")
    print(df_summary)
