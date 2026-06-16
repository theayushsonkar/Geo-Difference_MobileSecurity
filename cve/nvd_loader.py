"""
NVD Loader Module

This module loads NVD vulnerability data from local ZIP archives, parses them 
into strongly-typed CVERecord structures, and constructs lookup indexes for 
subsequent CVE-to-SDK matching stages.
"""

from __future__ import annotations

import collections
import json
import logging
from pathlib import Path
import zipfile

from cve.schemas import CVERecord

# Create module logger
logger = logging.getLogger(__name__)


def _extract_cvss(metrics: dict) -> tuple[str | None, float | None, str | None, str | None]:
    """
    Extracts the highest priority CVSS details from NVD metrics.
    Priority: CVSS 3.1 -> CVSS 3.0 -> CVSS 2.0.
    
    Returns:
        tuple[cvss_version, cvss_score, severity, cvss_vector]
    """
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(key)
        if metric_list and isinstance(metric_list, list):
            # Prefer Primary metric if available, otherwise take the first
            selected_metric = None
            for m in metric_list:
                if m.get("type") == "Primary":
                    selected_metric = m
                    break
            if not selected_metric:
                selected_metric = metric_list[0]
            
            cvss_data = selected_metric.get("cvssData", {})
            
            # Version
            cvss_version = cvss_data.get("version")
            if cvss_version is None:
                if key == "cvssMetricV31":
                    cvss_version = "3.1"
                elif key == "cvssMetricV30":
                    cvss_version = "3.0"
                elif key == "cvssMetricV2":
                    cvss_version = "2.0"
            
            # Score
            cvss_score = cvss_data.get("baseScore")
            if cvss_score is not None:
                try:
                    cvss_score = float(cvss_score)
                except (ValueError, TypeError):
                    cvss_score = None
            
            # Vector
            cvss_vector = cvss_data.get("vectorString")
            
            # Severity (V3.x has it in cvssData, V2.0 has it as sibling to cvssData)
            severity = cvss_data.get("baseSeverity") or selected_metric.get("baseSeverity")
            if severity is not None:
                severity = str(severity).upper()
                
            return cvss_version, cvss_score, severity, cvss_vector
            
    return None, None, None, None


def _parse_cpe_criteria(criteria: str) -> tuple[str | None, str | None]:
    """
    Parses a CPE 2.3 criteria string to extract the vendor and product fields.
    Handles escaped colons ('\\:') safely.
    
    Example:
        "cpe:2.3:a:google:firebase_android_sdk:*" -> ("google", "firebase_android_sdk")
    """
    if not criteria or not isinstance(criteria, str):
        return None, None
        
    # Standardize escaped colons to avoid splitting issues
    normalized = criteria.replace(r"\:", "__COLON__")
    parts = normalized.split(":")
    
    if len(parts) >= 5 and parts[0] == "cpe" and parts[1] == "2.3":
        vendor = parts[3].replace("__COLON__", ":").replace("\\", "")
        product = parts[4].replace("__COLON__", ":").replace("\\", "")
        return vendor, product
        
    return None, None


def _parse_cve(cve_dict: dict) -> list[CVERecord]:
    """
    Parses a single CVE dictionary from NVD JSON.
    Returns a list of CVERecord objects (one per vendor/product combination).
    """
    cve_id = cve_dict.get("id")
    if not cve_id:
        cve_id = "UNKNOWN"
        
    published_date = cve_dict.get("published")
    last_modified_date = cve_dict.get("lastModified")
    
    metrics = cve_dict.get("metrics", {})
    cvss_version, cvss_score, severity, cvss_vector = _extract_cvss(metrics)
    
    # Extract CPE matches from configurations
    cpe_matches = []
    configurations = cve_dict.get("configurations")
    if isinstance(configurations, list):
        for config in configurations:
            if not isinstance(config, dict):
                continue
            nodes = config.get("nodes")
            if not isinstance(nodes, list):
                continue
            for node in nodes:
                if not isinstance(node, dict):
                    continue
                matches = node.get("cpeMatch")
                if not isinstance(matches, list):
                    continue
                for match in matches:
                    if isinstance(match, dict):
                        cpe_matches.append(match)
                        
    # Group range structures by (vendor, product)
    grouped_ranges: dict[tuple[str | None, str | None], list[dict]] = {}
    
    for match in cpe_matches:
        criteria = match.get("criteria")
        vendor, product = _parse_cpe_criteria(criteria)
        
        # Extract only version range keys
        range_dict = {}
        for key in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding"):
            val = match.get(key)
            if val is not None:
                range_dict[key] = val
                
        # Group by (vendor, product) key
        key = (vendor, product)
        if key not in grouped_ranges:
            grouped_ranges[key] = []
        grouped_ranges[key].append(range_dict)
        
    records = []
    if not grouped_ranges:
        # Create a single CVERecord with None for vendor/product if no CPE matches are found
        records.append(
            CVERecord(
                cve_id=cve_id,
                published_date=published_date,
                last_modified_date=last_modified_date,
                cvss_version=cvss_version,
                cvss_score=cvss_score,
                severity=severity,
                cvss_vector=cvss_vector,
                vendor=None,
                product=None,
                version_ranges=[]
            )
        )
    else:
        for (vendor, product), ranges in sorted(grouped_ranges.items(), key=lambda x: (x[0][0] or "", x[0][1] or "")):
            records.append(
                CVERecord(
                    cve_id=cve_id,
                    published_date=published_date,
                    last_modified_date=last_modified_date,
                    cvss_version=cvss_version,
                    cvss_score=cvss_score,
                    severity=severity,
                    cvss_vector=cvss_vector,
                    vendor=vendor,
                    product=product,
                    version_ranges=ranges
                )
            )
            
    return records


def load_nvd(nvd_dir: Path | str = "data/nvd") -> list[CVERecord]:
    """
    Discovers all ZIP archives in the target directory, opens them, loads the 
    contained JSON files, and parses vulnerabilities into CVERecord structures.
    
    Args:
        nvd_dir: Path or directory string containing NVD zip files.
        
    Returns:
        List of parsed CVERecord objects.
    """
    path = Path(nvd_dir)
    if not path.exists():
        logger.warning(f"NVD directory does not exist: {nvd_dir}")
        return []
        
    zip_files = sorted(path.rglob("*.zip"))
    logger.info("Discovered %d ZIP files in %s", len(zip_files), nvd_dir)
    
    records = []
    
    for zip_path in zip_files:
        logger.info("Processing NVD archive: %s", zip_path.name)
        try:
            with zipfile.ZipFile(zip_path) as z:
                # Find JSON files inside the ZIP
                json_files = [name for name in z.namelist() if name.endswith(".json")]
                for json_filename in json_files:
                    try:
                        with z.open(json_filename) as f:
                            data = json.load(f)
                            
                        vulnerabilities = data.get("vulnerabilities")
                        if not isinstance(vulnerabilities, list):
                            logger.warning("No vulnerabilities list found in JSON %s", json_filename)
                            continue
                            
                        cve_parsed_count = 0
                        records_created_count = 0
                        
                        for vuln in vulnerabilities:
                            if not isinstance(vuln, dict):
                                continue
                            try:
                                cve_dict = vuln.get("cve")
                                if not isinstance(cve_dict, dict):
                                    continue
                                cve_records = _parse_cve(cve_dict)
                                records.extend(cve_records)
                                cve_parsed_count += 1
                                records_created_count += len(cve_records)
                            except Exception as e:
                                logger.warning(
                                    "Error parsing individual CVE entry in %s: %s",
                                    json_filename, e, exc_info=True
                                )
                                
                        logger.info(
                            "Parsed %d CVEs generating %d vendor/product records from %s:%s",
                            cve_parsed_count, records_created_count, zip_path.name, json_filename
                        )
                    except Exception as e:
                        logger.warning("Failed to parse JSON file %s from %s: %s", json_filename, zip_path.name, e, exc_info=True)
        except Exception as e:
            logger.warning("Failed to open or process ZIP file %s: %s", zip_path, e, exc_info=True)
            
    logger.info("NVD load complete. Total CVERecords created: %d", len(records))
    return records


def build_indexes(records: list[CVERecord]) -> dict:
    """
    Constructs vendor and product lookup dictionaries from parsed CVERecords.
    
    Args:
        records: List of parsed CVERecord objects.
        
    Returns:
        Dictionary mapping 'vendor' and 'product' keys to their respective lists of CVERecords.
    """
    vendor_idx = collections.defaultdict(list)
    product_idx = collections.defaultdict(list)
    
    for record in records:
        if record.vendor is not None:
            vendor_idx[record.vendor].append(record)
        if record.product is not None:
            product_idx[record.product].append(record)
            
    return {
        "vendor": dict(vendor_idx),
        "product": dict(product_idx),
    }


if __name__ == "__main__":
    # Configure logging for manual test execution
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    
    # Run manual loading test
    logger.info("Starting manual index validation...")
    records_list = load_nvd("data/nvd")
    indexes_dict = build_indexes(records_list)
    
    print(f"Number of CVE records: {len(records_list)}")
    print(f"Number of unique vendors: {len(indexes_dict['vendor'])}")
    print(f"Number of unique products: {len(indexes_dict['product'])}")
