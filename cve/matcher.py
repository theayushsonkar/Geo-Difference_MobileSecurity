"""
CVE Matcher Module

This module implements the core matching logic between detected SDK records and 
reference CVE records from NVD. It uses token-based indexing to quickly narrow down 
candidate CVEs, validates versions against range constraints, and deduplicates matches.
"""

from __future__ import annotations

import csv
import logging
from pathlib import Path

from cve.schemas import CoverageRecord, CVEMatch, CVERecord, SDKRecord
from cve.versioning import has_real_version_constraints, matches_any_range, parse_version_safe

# Create module logger
logger = logging.getLogger(__name__)


SDK_ALIASES = {
    "com.google.firebase": [
        "firebase",
        "firebase_android_sdk"
    ],
    "com.google.android.gms": [
        "google_play_services",
        "play_services"
    ],
    "com.facebook": [
        "facebook",
        "facebook_android_sdk",
        "android_sdk"
    ],
    "com.squareup.okhttp3": [
        "okhttp"
    ],
    "com.squareup.retrofit2": [
        "retrofit"
    ],
    "com.google.code.gson": [
        "gson"
    ],
    "com.unity3d.ads": [
        "unity",
        "unity_ads"
    ],
    "com.applovin": [
        "applovin"
    ],
    "com.bytedance.sdk": [
        "pangle",
        "bytedance"
    ],
    "com.mbridge": [
        "mbridge",
        "mintegral"
    ]
}


def _load_sdk_records(manifest_sdks_csv: str | Path) -> list[SDKRecord]:
    """
    Loads SDK records from the manifest_sdks.csv file.
    
    Args:
        manifest_sdks_csv: Path to the input CSV file.
        
    Returns:
        A list of SDKRecord objects.
    """
    records = []
    path = Path(manifest_sdks_csv)
    if not path.exists():
        logger.warning("Manifest SDKs CSV file not found: %s", manifest_sdks_csv)
        return records

    try:
        with open(path, mode="r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    record = SDKRecord(
                        sample_id=row.get("sample_id", "").strip(),
                        package_name=row.get("package_name", "").strip(),
                        sdk_name=row.get("sdk_name", "").strip(),
                        sdk_identifier=row.get("sdk_identifier", "").strip(),
                        sdk_version=row.get("sdk_version", "").strip() or None,
                        sdk_version_source=row.get("sdk_version_source", "").strip() or None,
                        sdk_version_confidence=row.get("sdk_version_confidence", "").strip() or None,
                    )
                    records.append(record)
                except Exception as e:
                    logger.warning("Failed to parse row %s in SDK CSV: %s", row, e)
    except Exception as e:
        logger.error("Failed to read SDK CSV file: %s", e)

    return records


def _extract_search_tokens(sdk_identifier: str, sdk_name: str) -> set[str]:
    """
    Generates search lookup tokens from sdk_identifier and sdk_name.
    
    Args:
        sdk_identifier: The identifier of the SDK (e.g. Maven coordinate).
        sdk_name: The human-readable name of the SDK.
        
    Returns:
        A set of clean, lowercase, deduplicated lookup strings.
    """
    tokens = set()
    ignored_prefixes = {"com", "org", "net", "edu", "gov", "mil", "io", "co", "squareup", "unity3d"}
    stopwords = {"google", "android", "play", "sdk", "library", "common", "core", "mobile", "client", "ads"}

    def add_token(t: str) -> None:
        t_clean = t.strip().lower()
        if not t_clean or t_clean in ignored_prefixes or t_clean in stopwords:
            return
        tokens.add(t_clean)
        # Handle hyphens and underscores swapping
        if "-" in t_clean or "_" in t_clean:
            tokens.add(t_clean.replace("-", "_"))
            tokens.add(t_clean.replace("_", "-"))

    # Process sdk_identifier
    if sdk_identifier:
        # Split by major delimiters: colon, dot, space, slash
        delimiters = [":", ".", " ", "/"]
        parts = [sdk_identifier]
        for d in delimiters:
            next_parts = []
            for p in parts:
                next_parts.extend(p.split(d))
            parts = next_parts
            
        for part in parts:
            add_token(part)
            # Also extract sub-components of hyphenated/underscored terms
            if "-" in part or "_" in part:
                sub_parts = part.replace("-", " ").replace("_", " ").split()
                for sp in sub_parts:
                    add_token(sp)

    # Process sdk_name
    if sdk_name:
        delimiters = [":", ".", " ", "/"]
        parts = [sdk_name]
        for d in delimiters:
            next_parts = []
            for p in parts:
                next_parts.extend(p.split(d))
            parts = next_parts
            
        for part in parts:
            add_token(part)
            if "-" in part or "_" in part:
                sub_parts = part.replace("-", " ").replace("_", " ").split()
                for sp in sub_parts:
                    add_token(sp)

    return tokens


def _find_candidate_cves(
    tokens: set[str],
    vendor_index: dict,
    product_index: dict,
) -> list[CVERecord]:
    """
    Looks up candidate CVE records from product_index using generated search tokens.
    Vendor index is not queried to prevent overly broad matching.
    
    Args:
        tokens: Generated search tokens.
        vendor_index: Dictionary mapping vendor tokens to lists of CVERecords (ignored).
        product_index: Dictionary mapping product tokens to lists of CVERecords.
        
    Returns:
        A list of unique candidate CVERecord objects.
    """
    candidates_dict = {}
    for token in tokens:
        product_records = product_index.get(token)
        if product_records:
            for r in product_records:
                key = (r.cve_id, r.vendor, r.product)
                candidates_dict[key] = r

    return list(candidates_dict.values())


def _expand_tokens_with_aliases(sdk_identifier: str | None, tokens: set[str]) -> set[str]:
    """
    Expands search tokens using the SDK_ALIASES mapping.
    
    If the sdk_identifier starts with any key in SDK_ALIASES, all associated
    aliases are added to the token set.
    """
    expanded = set(tokens)
    if not sdk_identifier:
        return expanded
        
    for prefix, aliases in SDK_ALIASES.items():
        if sdk_identifier.startswith(prefix):
            logger.debug("Applied aliases to %s:\n%s", sdk_identifier, aliases)
            expanded.update(aliases)
            
    return expanded


def match_sdks_to_cves(
    manifest_sdks_csv: str | Path,
    vendor_index: dict,
    product_index: dict,
    nvd_snapshot_date: str,
    exclude_androidx: bool = False,
) -> tuple[list[CVEMatch], list[CoverageRecord]]:
    """
    Performs core CVE matching logic on a manifest SDKs CSV file.
    
    Args:
        manifest_sdks_csv: Path to the input CSV file listing detected SDKs.
        vendor_index: Reference NVD vendor lookup index.
        product_index: Reference NVD product lookup index.
        nvd_snapshot_date: Snapshot metadata date string.
        exclude_androidx: If True, filters out AndroidX libraries from matching.
        
    Returns:
        A tuple containing:
          - A list of matching CVEMatch records.
          - A list of CoverageRecord skipped entries.
    """
    sdk_records = _load_sdk_records(manifest_sdks_csv)
    logger.info("Loaded %d SDK records from CSV", len(sdk_records))

    matches: list[CVEMatch] = []
    coverage_records: list[CoverageRecord] = []
    seen_matches = set()
    
    sdks_processed = 0
    total_candidates_found = 0

    for sdk in sdk_records:
        try:
            # Optional AndroidX filtering
            if exclude_androidx:
                if (sdk.sdk_identifier and sdk.sdk_identifier.startswith("androidx.")) or \
                   (sdk.sdk_name and "androidx" in sdk.sdk_name.lower()):
                    logger.debug("Skipping AndroidX SDK record: %s", sdk.sdk_identifier)
                    continue

            sdks_processed += 1

            # STEP 1: Check sdk_version
            if not sdk.sdk_version or not sdk.sdk_version.strip():
                coverage_records.append(
                    CoverageRecord(
                        sample_id=sdk.sample_id,
                        sdk_name=sdk.sdk_name,
                        sdk_identifier=sdk.sdk_identifier,
                        sdk_version=sdk.sdk_version,
                        skip_reason="no_version",
                    )
                )
                continue

            # STEP 2: Validate version
            parsed_ver = parse_version_safe(sdk.sdk_version)
            if parsed_ver is None:
                coverage_records.append(
                    CoverageRecord(
                        sample_id=sdk.sample_id,
                        sdk_name=sdk.sdk_name,
                        sdk_identifier=sdk.sdk_identifier,
                        sdk_version=sdk.sdk_version,
                        skip_reason="parse_error",
                    )
                )
                continue

            # STEP 3: Generate search tokens
            tokens = _extract_search_tokens(sdk.sdk_identifier, sdk.sdk_name)
            tokens = _expand_tokens_with_aliases(sdk.sdk_identifier, tokens)

            # STEP 4: Find candidate CVEs
            candidates = _find_candidate_cves(tokens, vendor_index, product_index)
            logger.debug(
                "SDK (identifier=%s, name=%s): found %d product candidates",
                sdk.sdk_identifier, sdk.sdk_name, len(candidates)
            )
            total_candidates_found += len(candidates)

            # STEP 5 & 6: Apply version filtering and create CVEMatch objects
            matched_any = False
            if candidates:
                for candidate in candidates:
                    if has_real_version_constraints(candidate.version_ranges) and \
                       matches_any_range(sdk.sdk_version, candidate.version_ranges):
                        # Deduplicate using (sample_id, sdk_identifier, cve_id)
                        dedup_key = (sdk.sample_id, sdk.sdk_identifier, candidate.cve_id)
                        if dedup_key not in seen_matches:
                            seen_matches.add(dedup_key)
                            matched_any = True
                            
                            match_obj = CVEMatch(
                                sample_id=sdk.sample_id,
                                package_name=sdk.package_name,
                                sdk_name=sdk.sdk_name,
                                sdk_identifier=sdk.sdk_identifier,
                                sdk_version=sdk.sdk_version,
                                cve_id=candidate.cve_id,
                                published_date=candidate.published_date,
                                last_modified_date=candidate.last_modified_date,
                                cvss_version=candidate.cvss_version,
                                cvss_score=candidate.cvss_score,
                                severity=candidate.severity,
                                cvss_vector=candidate.cvss_vector,
                                affected_version_range=str(candidate.version_ranges),
                                nvd_snapshot_date=nvd_snapshot_date,
                            )
                            matches.append(match_obj)

            if not matched_any:
                coverage_records.append(
                    CoverageRecord(
                        sample_id=sdk.sample_id,
                        sdk_name=sdk.sdk_name,
                        sdk_identifier=sdk.sdk_identifier,
                        sdk_version=sdk.sdk_version,
                        skip_reason="no_nvd_entry",
                    )
                )
                continue

        except Exception as e:
            logger.warning(
                "Error processing SDK record (sample_id=%s, sdk_identifier=%s): %s",
                sdk.sample_id, sdk.sdk_identifier, e, exc_info=True
            )

    logger.info("Processed %d SDK records", sdks_processed)
    logger.info("Found %d candidate CVE matches during processing", total_candidates_found)
    logger.info("Emitted %d CVE matches", len(matches))
    logger.info("Emitted %d coverage records", len(coverage_records))

    return matches, coverage_records


if __name__ == "__main__":
    print("Matcher module loaded successfully")
