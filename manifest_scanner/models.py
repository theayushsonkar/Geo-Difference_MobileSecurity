"""
Data classes and deterministic ID generation for the manifest scanner.
"""

import hashlib
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Set, Any


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
