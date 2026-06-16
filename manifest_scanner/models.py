"""
Data classes and deterministic ID generation for the manifest scanner.
"""

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


# ═══════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class SampleRecord:
    sample_id: str
    package_name: str
    app_country_code: str
    source_path: str
    apk_sha256: str
    app_country_name: str = ""
    app_region_group: str = ""
    app_store: str = ""
    collection_batch: str = ""
    notes: str = ""


@dataclass
class SDKRecord:
    run_id: str
    schema_version: str
    parser_version: str
    sample_id: str
    package_name: str
    app_country_code: str
    app_region_group: str
    sdk_id: str
    sdk_name: str
    sdk_prefix: str
    sdk_version: str = ""
    sdk_version_source: str = ""
    sdk_version_confidence: str = "none"
    sdk_ecosystem: str = "custom"
    sdk_identifier: str = ""
    sdk_category: str = ""
    vendor_country_code: str = ""
    vendor_region_group: str = ""
    detected_manifest: bool = False
    detected_smali: bool = False
    detected_native: bool = False
    detected_strings: bool = False
    detection_source_primary: str = ""
    evidence_type: str = ""
    evidence_value: str = ""
    evidence_count: int = 0


@dataclass
class StaticCodeFindingRecord:
    run_id: str
    schema_version: str
    parser_version: str
    sample_id: str
    package_name: str
    app_country_code: str
    app_region_group: str
    finding_id: str
    finding_type: str
    finding_subtype: str
    normalized_value: str
    finding_confidence: str = "low"
    occurrence_count: int = 0
    source_file_count: int = 0
    source_layer: str = ""
    source_file: str = ""
    evidence_snippet: str = ""
    finding_metadata: str = "{}"


@dataclass
class StaticCodeFindingAggregate:
    sample_id: str
    finding_type: str
    normalized_value: str
    finding_subtype: str = ""
    finding_confidence: str = "low"
    occurrence_count: int = 0
    source_files: Set[str] = field(default_factory=set)
    evidence_snippets: List[str] = field(default_factory=list)
    finding_metadata: Dict[str, Any] = field(default_factory=dict)


# ═══════════════════════════════════════════════════════════════════════════════
# DETERMINISTIC ID GENERATION — SHA256[:16] frozen for schema 1.x
# ═══════════════════════════════════════════════════════════════════════════════

def _make_id(*parts: str) -> str:
    raw = "|".join(str(p) for p in parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

def make_sdk_id(sample_id, sdk_name, sdk_prefix, sdk_version, vendor_cc, sdk_cat):
    return _make_id(sample_id, sdk_name, sdk_prefix, sdk_version, vendor_cc, sdk_cat)

def make_component_id(sample_id, component_type, component_name):
    return _make_id(sample_id, component_type, component_name)

def make_permission_id(sample_id, record_type, permission_name):
    return _make_id(sample_id, record_type, permission_name)

def make_network_rule_id(sample_id, config_file, rule_type, domain, cleartext, trust_src):
    return _make_id(sample_id, config_file, rule_type, domain, cleartext, trust_src)

def make_finding_id(sample_id, finding_type, normalized_value):
    return _make_id(sample_id, finding_type, normalized_value)
