"""
CVE Pipeline Schemas

This module defines the canonical, strongly-typed data structures used by the 
CVE analysis pipeline. These structures act as pure data containers (without behavior 
methods) to transition data between NVD parsing, SDK manifest data, matching stages, 
and coverage reporting.

Dataclasses:
1. SDKRecord
   - Represents: One SDK detected inside an Android application.
   - Comes from: Parsed rows of the manifest analysis CSV output ('output/manifest_sdks.csv').
   - Uses in future stages: Used as input to the CVE matching stage to align detected SDKs and versions with known CVE entries.

2. CVERecord
   - Represents: One vulnerability entry loaded and parsed from the NVD JSON dataset.
   - Comes from: NVD CVE JSON archives ('data/nvd/nvdcve-2.0-*.json.zip').
   - Uses in future stages: Used as reference vulnerability data for version constraint matching.

3. CVEMatch
   - Represents: A verified match between a detected SDK's version and a CVE's affected version range.
   - Uses in future stages: Written as output to 'output/sdk_cve_matches.csv' and summarized in 'output/app_cve_summary.csv' / 'output/cve_trace.json'.

4. CoverageRecord
   - Represents: A detected SDK that was skipped during the matching process.
   - Uses in future stages: Written as output to 'output/cve_coverage_report.csv' to report audit/analysis coverage limitations.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class SDKRecord:
    """
    Represents one SDK row from output/manifest_sdks.csv.
    This object is created before CVE matching begins.
    """
    sample_id: str
    package_name: str
    sdk_name: str
    sdk_identifier: str
    sdk_version: str | None
    sdk_version_source: str | None
    sdk_version_confidence: str | None


@dataclass(slots=True)
class CVERecord:
    """
    Represents one vulnerability entry loaded from NVD.
    The version_ranges field will later contain parsed version constraint information.
    """
    cve_id: str
    published_date: str | None
    last_modified_date: str | None
    cvss_version: str | None
    cvss_score: float | None
    severity: str | None
    cvss_vector: str | None
    vendor: str | None
    product: str | None
    version_ranges: list[dict] = field(default_factory=list)


@dataclass(slots=True)
class CVEMatch:
    """
    Represents one successful SDK-to-CVE match.
    Corresponds to one row in output/sdk_cve_matches.csv.
    """
    sample_id: str
    package_name: str
    sdk_name: str
    sdk_identifier: str
    sdk_version: str
    cve_id: str
    published_date: str | None
    last_modified_date: str | None
    cvss_version: str | None
    cvss_score: float | None
    severity: str | None
    cvss_vector: str | None
    affected_version_range: str | None
    nvd_snapshot_date: str


@dataclass(slots=True)
class CoverageRecord:
    """
    Represents one skipped SDK.
    Corresponds to one row in output/cve_coverage_report.csv.
    """
    sample_id: str
    sdk_name: str
    sdk_identifier: str
    sdk_version: str | None
    skip_reason: str
