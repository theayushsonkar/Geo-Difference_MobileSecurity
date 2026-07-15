"""
Core ManifestFeatureExtractor class and extraction logic.
"""

import hashlib
import json
import math
import os
import re
import time
import xml.etree.ElementTree as ET
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from .constants import (
    A, ALL_FAMILIES, DANGEROUS_PERMISSIONS,
    PARSER_VERSION, PERMISSION_FAMILIES, PRIVACY_SANDBOX_PERMISSIONS,
    SCHEMA_VERSION, SECRET_PATTERNS, SDK_CATEGORIES, SENSITIVE_META_KEY_PATTERNS,
    VERSION_META_KEYS, get_region, EU_MEMBER_STATES, CURATED_SDK_CATALOG,
    SDK_DETECTION_REGEXES
)
from .models import (
    SampleRecord, StaticCodeFindingAggregate, make_component_id,
    make_finding_id, make_network_rule_id, make_permission_id, make_sdk_id
)
from .schema import APP_COLUMNS, _default_for_column


PRECOMPUTED_SDK_LOOKUPS = []
for entry in CURATED_SDK_CATALOG:
    prefix = entry["sdk_prefix"].lower()
    aliases = [entry["sdk_prefix"].replace(".", "/").lower()]
    aliases.extend(alias.lower() for alias in entry.get("smali_aliases", ()))
    PRECOMPUTED_SDK_LOOKUPS.append((entry, prefix, aliases))



FINDING_SOURCE_PRIORITY = {
    "manifest_meta_data": 0,
    "manifest_xml": 1,
    "smali": 2,
    "res_values": 3,
    "res_xml": 4,
    "assets_json": 5,
    "assets_txt": 6,
}

ENDPOINT_URL_PATTERN = re.compile(r"(?i)\bhttps?://(?P<host>[A-Za-z0-9.-]+)(?::(?P<port>\d{2,5}))?(?:/[\w\-./?%&=+#:@]*)?")
ENDPOINT_DOMAIN_PATTERN = re.compile(r"(?i)\b(?P<host>(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})(?::(?P<port>\d{2,5}))?\b")
ENDPOINT_IP_PATTERN = re.compile(r"(?i)\b(?P<host>(?:\d{1,3}\.){3}\d{1,3})(?::(?P<port>\d{2,5}))?\b")

from knowledge_base.pipeline.matcher_factory import MatcherFactory

class ManifestFeatureExtractor:

    def __init__(self, sample: SampleRecord, run_id: str, sdk_inventory: Optional[Any] = None):
        """
        Initializes the extractor for a single application sample.
        Sets up accumulators for the various datasets (apps, sdks, components, permissions, etc.)
        and initializes profiling timers to track extraction performance.
        """
        self.sample = sample
        self.run_id = run_id
        self.sdk_inventory = sdk_inventory
        self.warnings: List[str] = []
        self.errors: List[str] = []
        # Populated during extraction
        self.root = None
        self.app_el = None
        self.manifest_sha256 = ""
        self.raw_bytes = b""
        self.target_sdk = 0
        
        MatcherFactory.initialize()
        factory = MatcherFactory()
        self.privacy_matcher = factory.privacy()
        self.secret_matcher = factory.secret()
        self.geo_matcher = factory.geo()
        
        self.min_sdk = 0
        # Result accumulators
        self.app_row: Dict[str, Any] = {}
        self.sdk_rows: List[Dict] = []
        self.component_rows: List[Dict] = []
        self.permission_rows: List[Dict] = []
        self.network_rows: List[Dict] = []
        self.finding_rows: List[Dict] = []
        self.trace: Dict[str, Any] = {}
        self.stats: Dict[str, Any] = {
               "smali_files_scanned": 0,
            "resource_files_scanned": 0,
            "sdk_versions_found": 0,
            "duplicates_suppressed": 0,
            "findings_by_type": defaultdict(int),
        }
        self.perf_timers = defaultdict(float)
        self.regex_evals = 0
        self.total_files_scanned = 0

    def _meta(self) -> Dict[str, str]:
        s = self.sample
        return {
            "run_id": self.run_id, "schema_version": SCHEMA_VERSION,
            "parser_version": PARSER_VERSION, "sample_id": s.sample_id,
            "package_name": s.package_name, "app_country_code": s.app_country_code,
            "app_region_group": s.app_region_group,
        }

    def _get(self, el, attr, default=None):
        if el is None:
            return default
        return el.get(A(attr), default)

    def _safe_int(self, val, default=0):
        if val is None:
            return default
        try:
            return int(val)
        except (ValueError, TypeError):
            return default

    def _findings_meta(self) -> Dict[str, str]:
        return {
            **self._meta(),
        }

    def _finding_key(self, finding_type: str, normalized_value: str) -> Tuple[str, str, str]:
        return (self.sample.sample_id, finding_type, normalized_value)

    def _finding_json(self, metadata: Dict[str, Any]) -> str:
        return json.dumps(metadata, sort_keys=True, ensure_ascii=False)

    def _finding_confidence_rank(self, confidence: str) -> int:
        return {"high": 3, "medium": 2, "low": 1, "none": 0}.get(confidence, 0)

    def _finding_source_priority(self, source_layer: str) -> int:
        return FINDING_SOURCE_PRIORITY.get(source_layer, 99)

    def _make_finding_row(
        self,
        finding_type: str,
        finding_subtype: str,
        normalized_value: str,
        finding_confidence: str,
        source_layer: str,
        source_file: str,
        evidence_snippet: str,
        metadata: Dict[str, Any],
    ) -> Dict[str, Any]:
        return {
            **self._findings_meta(),
            "finding_id": make_finding_id(self.sample.sample_id, finding_type, normalized_value),
            "finding_type": finding_type,
            "finding_subtype": finding_subtype,
            "normalized_value": normalized_value,
            "finding_confidence": finding_confidence,
            "occurrence_count": 1,
            "source_file_count": 1 if source_file else 0,
            "source_layer": source_layer,
            "source_file": source_file,
            "evidence_snippet": evidence_snippet[:500],
            "finding_metadata": self._finding_json(metadata),
        }

    def _merge_finding_row(self, existing: Dict[str, Any], update: Dict[str, Any], source_file: str):
        existing.setdefault("_source_files", set())
        if source_file:
            existing["_source_files"].add(source_file)
        existing["source_file_count"] = len(existing["_source_files"])
        existing["occurrence_count"] = int(existing.get("occurrence_count", 0)) + 1
        if self._finding_confidence_rank(update.get("finding_confidence", "none")) > self._finding_confidence_rank(existing.get("finding_confidence", "none")):
            existing["finding_confidence"] = update.get("finding_confidence", "none")
        if self._finding_source_priority(update.get("source_layer", "")) < self._finding_source_priority(existing.get("source_layer", "")):
            existing["source_layer"] = update.get("source_layer", "")
            existing["source_file"] = update.get("source_file", "")
            existing["evidence_snippet"] = update.get("evidence_snippet", "")
        merged_meta = {}
        try:
            merged_meta = json.loads(existing.get("finding_metadata", "{}") or "{}")
        except Exception:
            merged_meta = {}
        try:
            update_meta = json.loads(update.get("finding_metadata", "{}") or "{}")
        except Exception:
            update_meta = {}
        merged_meta.update(update_meta)
        existing["finding_metadata"] = self._finding_json(merged_meta)
        self.stats["duplicates_suppressed"] += 1

    def _finalize_finding_rows(self, finding_map: Dict[Tuple[str, str, str], Dict[str, Any]]):
        t_agg = time.time()
        rows = []
        for row in finding_map.values():
            row.pop("_source_files", None)
            rows.append(row)
            self.stats["findings_by_type"][row.get("finding_type", "unknown")] += 1
        self.finding_rows = sorted(rows, key=lambda r: (r.get("finding_type", ""), r.get("normalized_value", ""), r.get("finding_id", "")))
        self.perf_timers["aggregation"] += time.time() - t_agg

    def _is_valid_ip(self, host: str) -> bool:
        parts = host.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False

    def _is_valid_ip_endpoint(self, ip_str: str, protocol: str = "", port: str = "") -> bool:
        parts = ip_str.split(".")
        if len(parts) != 4:
            return False
        try:
            octets = [int(p) for p in parts]
        except ValueError:
            return False
        if any(o < 0 or o > 255 for o in octets):
            return False
            
        # Check for network context
        if protocol or port:
            return True
            
        # Private / loopback / standard well-known IPs
        if ip_str in {"0.0.0.0", "127.0.0.1", "255.255.255.255", "1.1.1.1", "8.8.8.8", "8.8.4.4"}:
            return True
        # Private subnets
        if octets[0] == 10:
            return True
        if octets[0] == 192 and octets[1] == 168:
            return True
        if octets[0] == 172 and (16 <= octets[1] <= 31):
            return True
            
        return False

    def _is_valid_domain_endpoint(self, host: str) -> bool:
        host = host.lower().strip()
        if not host or "." not in host:
            return False
            
        # Reject standard system package/class prefixes
        system_prefixes = (
            "android.", "androidx.", "java.", "javax.", "kotlin.", "kotlinx.", 
            "com.android.", "com.google.android.", "com.google.firebase.",
            "com.google.play.", "com.google.android.gms."
        )
        if any(host.startswith(prefix) for prefix in system_prefixes):
            return False
            
        # Reject common non-domain keywords/indicators
        bad_keywords = {"styledcontrols", "appcompat", "insets", "token", "action", "bitmap", "drawable", "layout", "button", "shapeappearance", "theme", "style", "corner"}
        if any(kw in host for kw in bad_keywords):
            return False
            
        parts = host.split(".")
        tld = parts[-1]
        
        # Reject version-like domains
        if all(p.isdigit() for p in parts):
            return False
            
        # TLD must contain only lowercase letters and be a standard domain TLD
        valid_tlds = {
            "com", "net", "org", "io", "co", "app", "dev", "cn", "tv", "cc", 
            "me", "us", "uk", "info", "biz", "ru", "de", "fr", "jp", "in", 
            "br", "ca", "it", "es", "xyz", "top", "work", "tech", "online", 
            "site", "store", "vip", "shop", "club", "space", "host", "mil", 
            "edu", "gov", "mobi", "asia", "link", "network", "download", 
            "click", "global", "pub", "one", "pro", "support"
        }
        if tld not in valid_tlds:
            return False
            
        # Reject standard android/resource prefixes or method/field-like parts
        if any(not re.match(r"^[a-z0-9_-]+$", p) for p in parts):
            return False
            
        if any(p.startswith("-") or p.endswith("-") for p in parts):
            return False
            
        if not any(any(c.isalpha() for c in p) for p in parts[:-1]):
            return False
            
        return True

    def _normalize_endpoint_values(self, text: str) -> List[Dict[str, Any]]:
        if not text:
            return []
        self.regex_evals += 3
        candidates = []
        for match in ENDPOINT_URL_PATTERN.finditer(text):
            host = match.group("host")
            port = match.group("port") or ""
            protocol = match.group(0).split("://", 1)[0].lower()
            normalized = host.lower()
            
            is_ip = self._is_valid_ip(normalized)
            if is_ip:
                if not self._is_valid_ip_endpoint(normalized, protocol, port):
                    continue
            else:
                if not self._is_valid_domain_endpoint(normalized):
                    continue
                    
            candidates.append({
                "normalized_value": normalized,
                "metadata": {
                    "protocol": protocol,
                    "port": port,
                    "is_ip": is_ip,
                },
                "snippet": match.group(0),
            })
            
        for match in ENDPOINT_IP_PATTERN.finditer(text):
            host = match.group("host")
            port = match.group("port") or ""
            normalized = host.lower()
            if not self._is_valid_ip_endpoint(normalized, "", port):
                continue
            candidates.append({
                "normalized_value": normalized,
                "metadata": {
                    "protocol": "",
                    "port": port,
                    "is_ip": True,
                },
                "snippet": match.group(0),
            })
            
        for match in ENDPOINT_DOMAIN_PATTERN.finditer(text):
            start = match.start()
            if start >= 3 and text[start-3:start] == "://":
                continue
            host = match.group("host")
            normalized = host.lower()
            if not self._is_valid_domain_endpoint(normalized):
                continue
            candidates.append({
                "normalized_value": normalized,
                "metadata": {
                    "protocol": "",
                    "port": match.group("port") or "",
                    "is_ip": False,
                },
                "snippet": match.group(0),
            })
            
        return candidates

    def _scan_text_for_findings(self, text: str, source_layer: str, source_file: str, finding_map: Dict[Tuple[str, str, str], Dict[str, Any]], scan_types: Optional[List[str]] = None):
        if not text:
            return
            
        t_start = time.time()
        do_pii = scan_types is None or "pii_api" in scan_types
        do_secret = scan_types is None or "secret" in scan_types
        do_endpoint = scan_types is None or "endpoint" in scan_types
        do_geo = scan_types is None or "geo_logic" in scan_types

        if do_pii:
            t_pii = time.time()
            findings = self.privacy_matcher.search(text)
            for finding in findings:
                self.regex_evals += 1
                subtype = finding.category
                normalized_value = finding.subcategory
                confidence = finding.confidence
                token = finding.matched_text
                
                row = self._make_finding_row(
                    "pii_api",
                    subtype,
                    normalized_value,
                    confidence,
                    source_layer,
                    source_file,
                    token,
                    {"pattern_name": subtype, "detector": "pii_api"},
                )
                key = self._finding_key("pii_api", normalized_value)
                if key not in finding_map:
                    finding_map[key] = row
                    finding_map[key]["_source_files"] = {source_file} if source_file else set()
                else:
                    self._merge_finding_row(finding_map[key], row, source_file)
            self.perf_timers["pii"] += time.time() - t_pii

        if do_secret:
            t_sec = time.time()
            findings = self.secret_matcher.search(text)
            for finding in findings:
                if finding.confidence == "low":
                    continue
                self.regex_evals += 1
                value = finding.matched_text
                pattern_name = finding.rule_id
                
                if not self._is_valid_secret(value, pattern_name):
                    continue
                    
                row = self._make_finding_row(
                    "secret",
                    pattern_name,
                    value,
                    finding.confidence,
                    source_layer,
                    source_file,
                    value,
                    {"pattern_name": pattern_name, "provider": finding.subcategory},
                )
                key = self._finding_key("secret", value)
                if key not in finding_map:
                    finding_map[key] = row
                    finding_map[key]["_source_files"] = {source_file} if source_file else set()
                else:
                    self._merge_finding_row(finding_map[key], row, source_file)
            self.perf_timers["secret"] += time.time() - t_sec

        if do_endpoint:
            t_end = time.time()
            endpoints = self._normalize_endpoint_values(text)
            for endpoint in endpoints:
                value = endpoint["normalized_value"]
                row = self._make_finding_row(
                    "endpoint",
                    "endpoint",
                    value,
                    "medium" if endpoint["metadata"].get("is_ip") else "high",
                    source_layer,
                    source_file,
                    endpoint["snippet"],
                    endpoint["metadata"],
                )
                key = self._finding_key("endpoint", value)
                if key not in finding_map:
                    finding_map[key] = row
                    finding_map[key]["_source_files"] = {source_file} if source_file else set()
                else:
                    self._merge_finding_row(finding_map[key], row, source_file)
            self.perf_timers["endpoint"] += time.time() - t_end

        if do_geo:
            t_geo = time.time()
            findings = self.geo_matcher.search(text)
            self.regex_evals += len(self.geo_matcher.rules) # rough approximation for stats
            
            for finding in findings:
                normalized_value = f"{finding.subcategory.lower()}.{finding.category.lower()}"
                
                raw_conf = finding.confidence.lower()
                final_conf = "high" if raw_conf == "very_high" else raw_conf
                
                row = self._make_finding_row(
                    "geo_logic",
                    finding.rule_id,
                    normalized_value,
                    final_conf,
                    source_layer,
                    source_file,
                    finding.matched_text,
                    {"pattern_name": finding.subcategory, "detector": "geo_logic"},
                )
                key = self._finding_key("geo_logic", normalized_value)
                if key not in finding_map:
                    finding_map[key] = row
                    finding_map[key]["_source_files"] = {source_file} if source_file else set()
                else:
                    self._merge_finding_row(finding_map[key], row, source_file)
            self.perf_timers["geo_logic"] += time.time() - t_geo
        self.perf_timers["findings"] += time.time() - t_start

    def _scan_manifest_for_findings(self, finding_map: Dict[Tuple[str, str, str], Dict[str, Any]]):
        if self.app_el is None:
            return
        manifest_text = ET.tostring(self.root, encoding="unicode") if self.root is not None else ""
        self._scan_text_for_findings(manifest_text, "manifest_xml", "AndroidManifest.xml", finding_map)
        for md in self._collect_meta_data():
            value = md.get("value", "") or md.get("resource", "")
            if value:
                self._scan_text_for_findings(value, "manifest_meta_data", "AndroidManifest.xml", finding_map)

    def _scan_resource_text_for_findings(self, path: str, content: str, source_layer: str, finding_map: Dict[Tuple[str, str, str], Dict[str, Any]]):
        self._scan_text_for_findings(content, source_layer, path, finding_map)

    def _scan_code_text_for_findings(self, path: str, content: str, finding_map: Dict[Tuple[str, str, str], Dict[str, Any]]):
        # Quick pre-filter for API usage in smali (PII and Geo logic)
        has_pii_or_geo = False
        api_keywords = (
            "AudioRecord", "MediaRecorder", "Microphone", "RECORD_AUDIO",
            "getImei", "getDeviceId", "getMeid", "IMEI", "SUBSCRIBER_ID",
            "Bluetooth", "BLUETOOTH", "Clipboard", "CLIPBOARD",
            "Sms", "SMS", "CallLog", "calllog", "Locale", "BuildConfig",
            "CountryIso", "MCC", "MNC"
        )
        for kw in api_keywords:
            if kw in content:
                has_pii_or_geo = True
                break
        if has_pii_or_geo:
            self._scan_text_for_findings(content, "smali", path, finding_map, ["pii_api", "geo_logic"])
        
        # Scan extracted string literals for Secrets and Endpoints
        if "const-string" in content:
            strings = re.findall(r'const-string(?:/jumbo)?\s+\S+,\s*"([^"]+)"', content)
            # Filter out string constants that are too long (>= 1000 chars) to prevent regex backtracking hangs
            strings = [s for s in strings if len(s) < 1000]
            if strings:
                strings_text = "\n".join(strings)
                self._scan_text_for_findings(strings_text, "smali", path, finding_map, ["secret", "endpoint"])

    def _initialize_filesystem(self):
        if hasattr(self, "_cached_files_initialized"):
            return
        start_t = time.time()
        self._cached_files_initialized = True
        self._pom_properties_files = []
        self._buildconfig_files = []
        self._smali_files = []
        self._resource_strings_files = []
        self._metadata_files = []
        self._findings_files = []
        
        self.app_row["has_manifest"] = False
        self.app_row["has_smali"] = False
        self.app_row["has_native_libs"] = False
        self.app_row["has_res_xml"] = False
        
        src = self.sample.source_path
        if not os.path.isdir(src):
            self.perf_timers["filesystem"] += time.time() - start_t
            return
            
        for dirpath, dirnames, filenames in os.walk(src):
            dirnames.sort()
            filenames.sort()
            for filename in filenames:
                path = os.path.join(dirpath, filename)
                rel = os.path.relpath(path, src).replace("\\", "/")
                rel_lower = rel.lower()
                
                # Check for manifest
                if filename == "AndroidManifest.xml" and dirpath == src:
                    self.app_row["has_manifest"] = True
                    
                # Check for native lib (.so)
                if filename.endswith(".so") and "/lib/" in f"/{rel_lower}/":
                    self.app_row["has_native_libs"] = True
                    
                # Check for res/xml
                if rel_lower.startswith("res/xml/"):
                    self.app_row["has_res_xml"] = True
                    
                # Check for smali directories
                if "/smali" in f"/{rel_lower}/" or "smali" in rel_lower.split("/")[0]:
                    self.app_row["has_smali"] = True
                
                if filename == "pom.properties" and "meta-inf" in rel_lower and "maven" in rel_lower:
                    self._pom_properties_files.append((path, rel_lower))
                
                if filename == "BuildConfig.smali":
                    self._buildconfig_files.append((path, rel_lower))
                
                if filename.endswith(".smali"):
                    self._smali_files.append((path, rel_lower))
                    
                if rel_lower.startswith("res/values/") and filename.endswith(".xml"):
                    self._resource_strings_files.append((path, rel_lower))
                    
                if "metadata" in filename.lower():
                    self._metadata_files.append((path, rel_lower))
                    
                if filename.endswith(".smali"):
                    self._findings_files.append((path, rel, "smali"))
                elif rel_lower.startswith("res/values/") and filename.endswith(".xml"):
                    self._findings_files.append((path, rel, "res_values"))
                elif rel_lower.startswith("res/xml/") and filename.endswith(".xml"):
                    self._findings_files.append((path, rel, "res_xml"))
                elif rel_lower.startswith("assets/") and filename.endswith(".json"):
                    self._findings_files.append((path, rel, "assets_json"))
                elif rel_lower.startswith("assets/") and filename.endswith(".txt"):
                    self._findings_files.append((path, rel, "assets_txt"))
        self.perf_timers["filesystem"] += time.time() - start_t

    def _ensure_cached_files(self):
        self._initialize_filesystem()

    def _extract_findings(self):
        self._process_files_and_extract()

    # ── Load & Hash ──────────────────────────────────────────────────────────

    def _load_manifest(self) -> bool:
        """
        Reads the AndroidManifest.xml from the application's source path,
        computes its SHA-256 hash, and parses it into an XML ElementTree (`self.root`).
        Returns True if parsing was successful, False otherwise.
        """
        src = self.sample.source_path
        manifest_path = os.path.join(src, "AndroidManifest.xml")
        if not os.path.isfile(manifest_path):
            self.errors.append(f"AndroidManifest.xml not found in {src}")
            return False
        try:
            with open(manifest_path, "rb") as f:
                self.raw_bytes = f.read()
            self.manifest_sha256 = hashlib.sha256(self.raw_bytes).hexdigest()
            self.root = ET.fromstring(self.raw_bytes.decode("utf-8", errors="replace"))
            self.app_el = self.root.find("application")
            return True
        except Exception as e:
            self.errors.append(f"Manifest parse error: {e}")
            return False

    # ── Identity ─────────────────────────────────────────────────────────────

    def _parse_identity(self):
        """
        Extracts foundational application configurations from the <manifest> and <application> tags.
        This includes versioning, SDK targeting (min/target), and security flags like 
        allowBackup, debuggable, and usesCleartextTraffic (calculating effective defaults).
        """
        r = self.root
        a = self.app_el
        row = self.app_row

        row["version_code"] = r.get(A("versionCode"), "")
        row["version_name"] = r.get(A("versionName"), "")
        row["compile_sdk"] = r.get(A("compileSdkVersion"), "")

        uses_sdk = r.find("uses-sdk")
        row["uses_sdk_present"] = uses_sdk is not None
        self.min_sdk = self._safe_int(self._get(uses_sdk, "minSdkVersion"))
        self.target_sdk = self._safe_int(self._get(uses_sdk, "targetSdkVersion"))
        row["min_sdk"] = self.min_sdk if self.min_sdk else None
        row["target_sdk"] = self.target_sdk if self.target_sdk else None
        row["install_location"] = r.get(A("installLocation"), "")
        row["app_category"] = self._get(a, "appCategory", "")

        # Application flags
        row["debuggable"] = self._get(a, "debuggable") == "true"
        row["extract_native_libs"] = self._get(a, "extractNativeLibs") == "true"
        row["hardware_accelerated"] = self._get(a, "hardwareAccelerated") == "true"
        nsc = self._get(a, "networkSecurityConfig", "")
        row["network_security_config_present"] = bool(nsc)

        # Counts
        row["uses_libraries_count"] = len(r.findall(".//uses-library")) if a is not None else 0
        features = r.findall("uses-feature")
        row["uses_feature_count"] = len(features)
        row["uses_feature_required_count"] = sum(
            1 for f in features if self._get(f, "required", "true") == "true"
        )
        row["instrumentation_count"] = len(r.findall("instrumentation"))
        row["activity_alias_count"] = len(a.findall("activity-alias")) if a is not None else 0

        # sharedUserId / Backup
        shared = r.get(A("sharedUserId"), "")
        row["shared_user_id"] = shared
        row["has_shared_user_id"] = bool(shared)

        ba_class = self._get(a, "backupAgent", "")
        row["backup_agent_class"] = ba_class
        row["full_backup_content_present"] = self._get(a, "fullBackupContent") is not None
        row["data_extraction_rules_present"] = self._get(a, "dataExtractionRules") is not None

        # allowBackup effective
        ab_raw = self._get(a, "allowBackup")
        row["allow_backup_present"] = ab_raw is not None
        row["allow_backup_value"] = ab_raw == "true" if ab_raw is not None else None
        if ab_raw is not None:
            row["allow_backup_effective"] = ab_raw == "true"
            row["allow_backup_effective_source"] = "explicit"
        else:
            row["allow_backup_effective"] = True
            row["allow_backup_effective_source"] = "default"

        # Cleartext effective
        ct_raw = self._get(a, "usesCleartextTraffic")
        row["cleartext_global_explicit"] = ct_raw == "true" if ct_raw is not None else None
        if self.target_sdk <= 27 and self.target_sdk > 0:
            row["cleartext_global_default"] = True
        elif self.target_sdk >= 28:
            row["cleartext_global_default"] = False
        else:
            row["cleartext_global_default"] = None

        if ct_raw is not None:
            row["cleartext_global_effective_manifest"] = ct_raw == "true"
            row["cleartext_global_effective_manifest_source"] = "explicit"
        elif row["cleartext_global_default"] is not None:
            row["cleartext_global_effective_manifest"] = row["cleartext_global_default"]
            row["cleartext_global_effective_manifest_source"] = "default"
        else:
            row["cleartext_global_effective_manifest"] = None
            row["cleartext_global_effective_manifest_source"] = ""

        row["cleartext_attr_ignored_on_target38_plus"] = (
            ct_raw is not None and self.target_sdk >= 38
        )

        # Store instrumentation class names in trace
        self.trace["instrumentation_class_names"] = [
            self._get(inst, "name", "") for inst in r.findall("instrumentation")
        ]
        self.trace["shared_user_id"] = shared
        self.trace["backup_agent_class"] = ba_class

    # ── Permissions ──────────────────────────────────────────────────────────

    def _parse_permissions(self):
        """
        Scans the XML tree for <uses-permission>, <uses-permission-sdk-23>, and custom <permission> tags.
        Normalizes these permissions, maps them to functional families (e.g., perm_location),
        and identifies if they belong to Android's Privacy Sandbox.
        """
        row = self.app_row
        perm_tags = [
            ("uses-permission", "uses-permission"),
            ("uses-permission-sdk-23", "uses-permission-sdk-23"),
        ]
        all_requested: Set[str] = set()
        all_records: List[Dict] = []
        perm_elements = []

        for tag, record_type in perm_tags:
            for el in self.root.findall(tag):
                name = self._get(el, "name", "")
                if not name:
                    continue
                perm_elements.append((name, record_type, el))

        # Also check for uses-permission-sdk-m (uncommon alias)
        for el in self.root.findall("uses-permission-sdk-m"):
            name = self._get(el, "name", "")
            if name:
                perm_elements.append((name, "uses-permission-sdk-m", el))

        for name, record_type, el in perm_elements:
            all_requested.add(name)
            ns = "android" if name.startswith("android.") else "custom"
            family = PERMISSION_FAMILIES.get(name, "perm_other")
            is_std = name.startswith("android.permission.")
            rec = {
                **self._meta(),
                "permission_id": make_permission_id(self.sample.sample_id, record_type, name),
                "record_type": record_type,
                "permission_name": name,
                "permission_namespace": ns,
                "family": family,
                "is_android_standard": is_std,
                "is_custom": not is_std,
                "protection_level": "",
                "label_present": False,
                "description_present": False,
                "source_element": record_type,
                "source_xml": "AndroidManifest.xml",
                "is_privacy_sandbox_permission": name in PRIVACY_SANDBOX_PERMISSIONS,
                "notes": "",
            }
            all_records.append(rec)

        # Declared permissions
        declared_perms = []
        declared_groups = []
        declared_trees = []
        sig_count = 0
        normal_count = 0
        custom_count = 0

        for el in self.root.findall("permission"):
            name = self._get(el, "name", "")
            if not name:
                continue
            declared_perms.append(name)
            pl = self._get(el, "protectionLevel", "normal")
            if "signature" in (pl or ""):
                sig_count += 1
            elif pl == "normal":
                normal_count += 1
            else:
                custom_count += 1
            rec = {
                **self._meta(),
                "permission_id": make_permission_id(self.sample.sample_id, "permission", name),
                "record_type": "permission",
                "permission_name": name,
                "permission_namespace": "custom",
                "family": "perm_other",
                "is_android_standard": False,
                "is_custom": True,
                "protection_level": pl or "",
                "label_present": self._get(el, "label") is not None,
                "description_present": self._get(el, "description") is not None,
                "source_element": "permission",
                "source_xml": "AndroidManifest.xml",
                "is_privacy_sandbox_permission": False,
                "notes": "",
            }
            all_records.append(rec)

        for el in self.root.findall("permission-group"):
            name = self._get(el, "name", "")
            if name:
                declared_groups.append(name)
                all_records.append({
                    **self._meta(),
                    "permission_id": make_permission_id(self.sample.sample_id, "permission-group", name),
                    "record_type": "permission-group", "permission_name": name,
                    "permission_namespace": "custom", "family": "perm_other",
                    "is_android_standard": False, "is_custom": True,
                    "protection_level": "", "label_present": self._get(el, "label") is not None,
                    "description_present": self._get(el, "description") is not None,
                    "source_element": "permission-group", "source_xml": "AndroidManifest.xml",
                    "is_privacy_sandbox_permission": False, "notes": "",
                })

        for el in self.root.findall("permission-tree"):
            name = self._get(el, "name", "")
            if name:
                declared_trees.append(name)
                all_records.append({
                    **self._meta(),
                    "permission_id": make_permission_id(self.sample.sample_id, "permission-tree", name),
                    "record_type": "permission-tree", "permission_name": name,
                    "permission_namespace": "custom", "family": "perm_other",
                    "is_android_standard": False, "is_custom": True,
                    "protection_level": "", "label_present": False,
                    "description_present": False,
                    "source_element": "permission-tree", "source_xml": "AndroidManifest.xml",
                    "is_privacy_sandbox_permission": False, "notes": "",
                })

        self.permission_rows = all_records

        # Unique permission counts per family
        unique_perms = all_requested
        dangerous_unique = unique_perms & DANGEROUS_PERMISSIONS
        other_unique = {
            p for p in unique_perms
            if PERMISSION_FAMILIES.get(p, "perm_other") == "perm_other"
        }

        row["requested_permission_total"] = len([p for p in perm_elements])
        row["requested_permission_unique"] = len(unique_perms)
        row["requested_permission_dangerous_unique"] = len(dangerous_unique)
        row["requested_permission_other_unique"] = len(other_unique)

        # Family counts (unique permissions only)
        family_counts = defaultdict(int)
        for p in unique_perms:
            fam = PERMISSION_FAMILIES.get(p, "perm_other")
            family_counts[fam] += 1
        for fam in ALL_FAMILIES:
            row[fam] = family_counts.get(fam, 0)

        # Declared counts
        row["declared_permission_count"] = len(declared_perms)
        row["declared_permission_group_count"] = len(declared_groups)
        row["declared_permission_tree_count"] = len(declared_trees)
        row["declared_signature_permission_count"] = sig_count
        row["declared_normal_permission_count"] = normal_count
        row["declared_custom_permission_count"] = custom_count

        # Privacy Sandbox
        for ps_perm, ps_key in PRIVACY_SANDBOX_PERMISSIONS.items():
            row[ps_key] = ps_perm in unique_perms

        self.trace["all_permissions"] = sorted(unique_perms)
        self.trace["permission_records"] = all_records

    # ── Components ───────────────────────────────────────────────────────────

    def _parse_components(self):
        row = self.app_row
        if self.app_el is None:
            for k in ["component_total", "activity_count", "service_count",
                       "receiver_count", "provider_count", "exported_activities",
                       "exported_services", "exported_receivers", "exported_providers",
                       "exported_receivers_no_perm", "android12_exported_missing_count",
                       "exported_components_with_intent_filter",
                       "exported_components_with_custom_scheme"]:
                row[k] = 0
            return

        comp_types = ["activity", "activity-alias", "service", "receiver", "provider"]
        all_comps = []
        counts = defaultdict(int)
        exported_counts = defaultdict(int)
        exported_no_perm = 0
        a12_missing = 0
        exp_with_if = 0
        exp_with_scheme = 0

        # Deep link accumulators
        all_deep_links = []
        dl_custom = 0; dl_https = 0; dl_http = 0; dl_market = 0

        for ctype in comp_types:
            for el in self.app_el.findall(ctype):
                name = self._get(el, "name", "")
                counts[ctype] += 1

                # State
                enabled_raw = self._get(el, "enabled")
                exported_raw = self._get(el, "exported")
                perm_guard = self._get(el, "permission", "")
                process = self._get(el, "process", "")
                dba = self._get(el, "directBootAware") == "true"
                iso = self._get(el, "isolatedProcess") == "true"

                intent_filters = el.findall("intent-filter")
                has_if = len(intent_filters) > 0
                action_count = sum(len(f.findall("action")) for f in intent_filters)
                category_count = sum(len(f.findall("category")) for f in intent_filters)
                data_count = sum(len(f.findall("data")) for f in intent_filters)

                # Scheme counts
                schemes = []
                for f in intent_filters:
                    for d in f.findall("data"):
                        s = self._get(d, "scheme", "")
                        if s:
                            schemes.append(s)
                custom_s = sum(1 for s in schemes if s not in ("http", "https", "market", "content", "file", "android-app"))
                http_s = schemes.count("http")
                https_s = schemes.count("https")
                market_s = schemes.count("market")
                other_s = len(schemes) - custom_s - http_s - https_s - market_s

                # Deep links
                for f in intent_filters:
                    for d in f.findall("data"):
                        s = self._get(d, "scheme", "")
                        h = self._get(d, "host", "")
                        if s:
                            link = {"scheme": s, "host": h, "activity": name}
                            all_deep_links.append(link)
                            if s == "https": dl_https += 1
                            elif s == "http": dl_http += 1
                            elif s == "market": dl_market += 1
                            elif s not in ("content", "file", "android-app"):
                                dl_custom += 1

                # Launcher / browsable
                is_launcher = False
                is_browsable = False
                for f in intent_filters:
                    cats = [self._get(c, "name", "") for c in f.findall("category")]
                    acts = [self._get(a_el, "name", "") for a_el in f.findall("action")]
                    if "android.intent.category.LAUNCHER" in cats and "android.intent.action.MAIN" in acts:
                        is_launcher = True
                    if "android.intent.category.BROWSABLE" in cats:
                        is_browsable = True

                auto_verify = any(
                    f.get(A("autoVerify")) == "true" for f in intent_filters
                )

                # Provider-specific
                grant_uri = self._get(el, "grantUriPermissions") == "true" if ctype == "provider" else False
                path_perm_count = len(el.findall("path-permission")) if ctype == "provider" else 0

                # Exported effective logic
                exported_explicit_present = exported_raw is not None
                exported_explicit_value = exported_raw == "true" if exported_raw is not None else None

                if exported_raw is not None:
                    exported_eff = exported_raw == "true"
                    exported_src = "explicit"
                    a12_viol = False
                elif ctype == "provider":
                    exported_eff = None  # uncertain
                    exported_src = "provider_default"
                    a12_viol = False
                elif not has_if:
                    exported_eff = False
                    exported_src = "unknown"
                    a12_viol = False
                elif self.target_sdk >= 31:
                    exported_eff = None
                    exported_src = "missing_on_android12plus"
                    a12_viol = True
                    a12_missing += 1
                else:
                    exported_eff = True
                    exported_src = "legacy_default"
                    a12_viol = False

                is_exported = exported_eff is True

                if is_exported:
                    exported_counts[ctype] += 1
                    if has_if:
                        exp_with_if += 1
                    if custom_s > 0:
                        exp_with_scheme += 1
                    if ctype == "receiver" and not perm_guard:
                        exported_no_perm += 1

                # Determine name format
                if name.startswith("."):
                    name_fmt = "relative"
                elif "." not in name:
                    name_fmt = "simple"
                else:
                    name_fmt = "fully_qualified"

                comp_rec = {
                    **self._meta(),
                    "component_id": make_component_id(self.sample.sample_id, ctype, name),
                    "component_type": ctype, "component_name": name,
                    "component_name_format": name_fmt, "source_xml": "AndroidManifest.xml",
                    "enabled_explicit_present": enabled_raw is not None,
                    "enabled_explicit_value": enabled_raw == "true" if enabled_raw is not None else None,
                    "enabled_effective": enabled_raw != "false" if enabled_raw is not None else True,
                    "exported_explicit_present": exported_explicit_present,
                    "exported_explicit_value": exported_explicit_value,
                    "has_intent_filter": has_if, "intent_filter_count": len(intent_filters),
                    "action_count": action_count, "category_count": category_count,
                    "data_count": data_count,
                    "custom_scheme_count": custom_s, "http_scheme_count": http_s,
                    "https_scheme_count": https_s, "market_scheme_count": market_s,
                    "other_scheme_count": other_s,
                    "is_launcher": is_launcher, "is_browsable": is_browsable,
                    "has_permission_guard": bool(perm_guard), "permission_name": perm_guard,
                    "direct_boot_aware": dba, "isolated_process": iso,
                    "process_name": process,
                    "grant_uri_permissions": grant_uri, "path_permission_count": path_perm_count,
                    "auto_verify": auto_verify,
                    "exported_effective": exported_eff, "exported_effective_source": exported_src,
                    "android12_exported_violation": a12_viol,
                }
                all_comps.append(comp_rec)

        self.component_rows = all_comps

        row["component_total"] = len(all_comps)
        row["activity_count"] = counts.get("activity", 0)
        row["activity_alias_count"] = counts.get("activity-alias", 0)
        row["service_count"] = counts.get("service", 0)
        row["receiver_count"] = counts.get("receiver", 0)
        row["provider_count"] = counts.get("provider", 0)
        row["exported_activities"] = exported_counts.get("activity", 0) + exported_counts.get("activity-alias", 0)
        row["exported_services"] = exported_counts.get("service", 0)
        row["exported_receivers"] = exported_counts.get("receiver", 0)
        row["exported_providers"] = exported_counts.get("provider", 0)
        row["exported_receivers_no_perm"] = exported_no_perm
        row["android12_exported_missing_count"] = a12_missing
        row["exported_components_with_intent_filter"] = exp_with_if
        row["exported_components_with_custom_scheme"] = exp_with_scheme

        # Deep links
        row["deep_link_total"] = len(all_deep_links)
        row["deep_link_custom_scheme_count"] = dl_custom
        row["deep_link_https_count"] = dl_https
        row["deep_link_http_count"] = dl_http
        row["deep_link_market_count"] = dl_market

        self.trace["components"] = all_comps
        self.trace["deep_links"] = all_deep_links

    # -- Manifest-only SDK detection ----------------------------------------

    def _qualified_name(self, name: str) -> str:
        if not name:
            return ""
        pkg = self.root.get("package", "") if self.root is not None else ""
        if name.startswith(".") and pkg:
            return f"{pkg}{name}"
        if "." not in name and pkg:
            return f"{pkg}.{name}"
        return name

    def _discover_smali_files(self) -> List[str]:
        self._ensure_cached_files()
        return sorted(set(path for path, _ in self._smali_files))

    def _smali_path_to_package(self, path: str) -> str:
        rel = os.path.relpath(path, self.sample.source_path)
        rel = rel.replace("\\", "/")
        if rel.endswith(".smali"):
            rel = rel[:-6]
        if rel.startswith("smali/"):
            rel = rel[len("smali/"):]
        elif rel.startswith("smali_classes"):
            rel = rel.split("/", 1)[1] if "/" in rel else ""
        return rel.replace("/", ".")

    def _normalize_smali_descriptor(self, descriptor: str) -> str:
        if not descriptor:
            return ""
        value = descriptor.strip()
        if value.startswith("L") and value.endswith(";"):
            value = value[1:-1]
        return value.replace("/", ".")

    def _sdk_match_entries(self, value: str) -> List[Dict[str, Any]]:
        value_l = (value or "").lower()
        if "com" not in value_l and "androidx" not in value_l and "io" not in value_l:
            return []
        matches = []
        for entry, prefix, aliases in PRECOMPUTED_SDK_LOOKUPS:
            if (
                value_l == prefix or value_l.startswith(prefix + ".") or value_l.startswith(prefix + "/") or value_l.startswith(prefix + "$") or prefix in value_l
            ) or any(
                value_l == candidate or value_l.startswith(candidate + ".") or value_l.startswith(candidate + "/") or value_l.startswith(candidate + "$") or candidate in value_l
                for candidate in aliases
            ):
                matches.append(entry)
        matches.sort(key=lambda entry: len(entry["sdk_prefix"]), reverse=True)
        return matches

    def _sdk_version_confidence(self, version: str) -> str:
        return "high" if version else "none"

    def _create_sdk_record(self, entry: Dict[str, Any], evidence_kind: str, evidence_value: str, source_file: str, detected_manifest: bool, detected_smali: bool, detected_native: bool, detected_strings: bool) -> Dict[str, Any]:
        sdk_version = ""
        sdk_version_source = ""
        sdk_version_confidence = "none"
        if evidence_kind == "meta_version" and self._is_valid_sdk_version(evidence_value):
            sdk_version = evidence_value
            sdk_version_source = "manifest_meta_data"
            sdk_version_confidence = "high"

        sdk_identifier = entry.get("sdk_identifier", "") or ""
        sdk_ecosystem = entry.get("sdk_ecosystem", "custom") or "custom"
        sdk_category = entry.get("sdk_category", "") or ""
        vendor_cc = entry.get("vendor_country_code", "") or ""
        vendor_region = entry.get("vendor_region_group", "") or get_region(vendor_cc)
        sdk_name = entry["sdk_name"]
        sdk_prefix = entry["sdk_prefix"]
        return {
            **self._meta(),
            "sdk_id": make_sdk_id(self.sample.sample_id, sdk_name, sdk_prefix, sdk_version, vendor_cc, sdk_category),
            "sdk_name": sdk_name,
            "sdk_prefix": sdk_prefix,
            "sdk_version": sdk_version,
            "sdk_version_source": sdk_version_source,
            "sdk_version_confidence": sdk_version_confidence,
            "sdk_ecosystem": sdk_ecosystem,
            "sdk_identifier": sdk_identifier,
            "sdk_category": sdk_category,
            "vendor_country_code": vendor_cc,
            "vendor_region_group": vendor_region,
            "detected_manifest": detected_manifest,
            "detected_smali": detected_smali,
            "detected_native": detected_native,
            "detected_strings": detected_strings,
            "detection_source_primary": evidence_kind if detected_manifest else "smali",
            "evidence_type": evidence_kind,
            "evidence_value": evidence_value,
            "evidence_count": 1,
            "source_file_count": 1 if source_file else 0,
        }

    def _merge_sdk_row(self, existing: Dict[str, Any], update: Dict[str, Any], source_file: str):
        existing["detected_manifest"] = bool(existing.get("detected_manifest")) or bool(update.get("detected_manifest"))
        existing["detected_smali"] = bool(existing.get("detected_smali")) or bool(update.get("detected_smali"))
        existing["detected_native"] = bool(existing.get("detected_native")) or bool(update.get("detected_native"))
        existing["detected_strings"] = bool(existing.get("detected_strings")) or bool(update.get("detected_strings"))
        existing.setdefault("_source_files", set())
        existing.setdefault("_counted_files", set())
        if source_file:
            existing["_source_files"].add(source_file)
            if source_file not in existing["_counted_files"]:
                existing["_counted_files"].add(source_file)
                existing["evidence_count"] = int(existing.get("evidence_count", 0)) + 1
        existing["source_file_count"] = len(existing["_source_files"])
        if not existing.get("sdk_identifier") and update.get("sdk_identifier"):
            existing["sdk_identifier"] = update["sdk_identifier"]
        if not existing.get("sdk_ecosystem") and update.get("sdk_ecosystem"):
            existing["sdk_ecosystem"] = update["sdk_ecosystem"]
        if update.get("sdk_version"):
            if not existing.get("sdk_version") or self._version_candidate_better(existing, update):
                existing["sdk_version"] = update["sdk_version"]
                existing["sdk_version_source"] = update.get("sdk_version_source", "")
                existing["sdk_version_confidence"] = update.get("sdk_version_confidence", "none")
        if existing.get("detection_source_primary") == "manifest":
            return
        if update.get("detected_manifest"):
            existing["detection_source_primary"] = "manifest"
        elif update.get("detected_smali") and existing.get("detection_source_primary", "") != "manifest" and not existing.get("detection_source_primary"):
            existing["detection_source_primary"] = "smali"

    def _finalize_sdk_rows(self, sdk_map: Dict[Tuple[str, str], Dict[str, Any]]):
        t_agg = time.time()
        rows = []
        for row in sdk_map.values():
            row.pop("_source_files", None)
            row.pop("_counted_files", None)
            row["sdk_id"] = make_sdk_id(
                row["sample_id"],
                row["sdk_name"],
                row["sdk_prefix"],
                row["sdk_version"],
                row["vendor_country_code"],
                row["sdk_category"]
            )
            rows.append(row)
        self.sdk_rows = sorted(rows, key=lambda r: (r.get("sdk_category", ""), r.get("sdk_name", ""), r.get("sdk_prefix", "")))
        self.perf_timers["aggregation"] += time.time() - t_agg

    def _sdk_catalog_entry(self, sdk_name: str) -> Optional[Dict[str, Any]]:
        for entry in CURATED_SDK_CATALOG:
            if entry.get("sdk_name") == sdk_name:
                return entry
        return None

    def _sdk_lookup_text(self, row: Dict[str, Any]) -> str:
        parts = [
            row.get("sdk_name", ""),
            row.get("sdk_prefix", ""),
            row.get("sdk_identifier", ""),
            row.get("sdk_ecosystem", ""),
        ]
        return " ".join(p for p in parts if p).lower()

    def _sdk_text_matches_row(self, text: str, row: Dict[str, Any]) -> bool:
        text_l = (text or "").lower()
        if not text_l:
            return False
        entry = self._sdk_catalog_entry(row.get("sdk_name", ""))
        if entry is None:
            return any(token and token in text_l for token in [row.get("sdk_name", ""), row.get("sdk_prefix", ""), row.get("sdk_identifier", "")])
        candidates = [entry.get("sdk_prefix", "")]
        candidates.extend(entry.get("smali_aliases", ()))
        candidates.extend([row.get("sdk_name", ""), row.get("sdk_identifier", "")])
        candidates = [c.lower() for c in candidates if c]
        return any(c and (c in text_l) for c in candidates)

    def _version_confidence_rank(self, confidence: str) -> int:
        return {"high": 3, "medium": 2, "low": 1, "none": 0}.get(confidence, 0)

    def _version_candidate_better(self, current: Dict[str, str], candidate: Dict[str, str]) -> bool:
        current_rank = self._version_confidence_rank(current.get("sdk_version_confidence", "none"))
        candidate_rank = self._version_confidence_rank(candidate.get("sdk_version_confidence", "none"))
        if candidate_rank != current_rank:
            return candidate_rank > current_rank
        order = {
            "pom_properties": 5,
            "buildconfig": 4,
            "const_string": 3,
            "resource_strings": 2,
            "metadata": 1,
            "manifest_meta_data": 0
        }
        return order.get(candidate.get("sdk_version_source", ""), -1) > order.get(current.get("sdk_version_source", ""), -1)

    def _is_valid_sdk_version(self, version: str) -> bool:
        if not version:
            return False
        v = version.strip()
        if v.startswith("@"):
            return False
        if v.lower() in {"0", "0.0", "0.00", "0.0.0", "unknown", "null", "none"}:
            return False
        pattern = re.compile(r"^\d+(?:\.\d+)+(?:[-_a-zA-Z0-9.]+)?$")
        if not pattern.match(v):
            return False
        if any(v.lower().endswith(ext) for ext in [".wav", ".db", ".tmp", ".xml", ".json", ".properties"]):
            return False
        return True

    def _calculate_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        import math
        frequencies = {}
        for char in text:
            frequencies[char] = frequencies.get(char, 0) + 1
        entropy = 0.0
        length = len(text)
        for count in frequencies.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def _is_valid_secret(self, value: str, pattern_name: str) -> bool:
        if not value:
            return False
        val_strip = value.strip()
        if not val_strip:
            return False
        if val_strip.lower() in {"null", "nil", "none", "true", "false", "dummy", "placeholder", "test", "demo"}:
            return False
            
        # Reject UUIDs
        if re.match(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", val_strip):
            return False
            
        val_upper = val_strip.upper()
        
        # Reject WebSocket GUID
        if val_upper == "258EAFA5-E914-47DA-95CA-C5AB0DC85B11":
            return False
            
        # Reject Alphabet/Test Strings
        if "abcdefghijklmnopqrstuvwxyz" in val_strip.lower() or "0123456789" in val_strip or "9876543210" in val_strip:
            return False
            
        # Reject Public Certificates / Public Keys
        if "-----BEGIN " in val_strip or "BEGIN CERTIFICATE" in val_upper or "BEGIN PUBLIC KEY" in val_upper or "BEGIN RSA PRIVATE KEY" in val_upper:
            return False
            
        # Reject Android/Framework Constants
        if val_upper.startswith(("ACTION_", "PERMISSION_", "CATEGORY_", "EXTRA_")):
            return False
        if "ACTION_" in val_upper or "android.intent" in val_strip.lower() or val_strip.lower().startswith("action."):
            return False
        if "PERMISSION" in val_upper or val_strip.lower().startswith("android.permission"):
            return False
            
        buildconfig_keys = {"DEBUG", "APPLICATION_ID", "BUILD_TYPE", "FLAVOR", "VERSION_CODE", "VERSION_NAME", "PACKAGE_NAME"}
        if val_upper in buildconfig_keys:
            return False
        if val_strip.startswith("R.") or val_strip.startswith("@") or "res/" in val_strip.lower():
            return False
        if re.match(r"^[A-Z0-9_]+$", val_strip):
            if pattern_name == "high_entropy_token":
                return False
                
        # Reject resource prefixes, SDK prefixes, unicode junk and multiple underscores
        if val_strip.lower().startswith(("abc_", "btn_", "ic_", "notification_", "mtrl_", "design_", "material_", "mbridge_", "u2026", "uff0c")):
            return False
        if re.match(r"^u[0-9a-fA-F]{4}", val_strip):
            return False
        if "__" in val_strip:
            return False
        if val_strip.count("_") >= 3:
            return False
            
        # Reject common resource paths
        resource_prefixes = ("color/", "dimen/", "drawable/", "string/", "layout/", "id/", "anim/", "style/", "mipmap/", "attr/", "xml/", "raw/", "menu/")
        if val_strip.lower().startswith(resource_prefixes):
            return False
            
        # Reject common code constants/variable endings
        bad_endings = ("applied", "foreground", "elevation", "height", "background", "ripple", "sound")
        if val_strip.lower().endswith(bad_endings):
            return False
            
        if val_strip.lower().startswith(("is", "get", "set", "java")):
            # If it starts with method prefix and has mixed case with few digits
            if any(c.isupper() for c in val_strip) and sum(c.isdigit() for c in val_strip) < 3:
                return False
                
        if val_strip.endswith("_"):
            return False
            
        if pattern_name == "high_entropy_token":
            has_lower = any(c.islower() for c in val_strip)
            has_upper = any(c.isupper() for c in val_strip)
            has_digit = any(c.isdigit() for c in val_strip)
            has_special = any(not c.isalnum() for c in val_strip)
            
            # Require at least one digit
            if not has_digit:
                return False
                
            classes_count = sum([has_lower, has_upper, has_digit, has_special])
            if classes_count < 3:
                return False
                
            entropy = self._calculate_entropy(val_strip)
            if entropy < 3.8:
                return False
            if val_strip.count(".") > 1 or val_strip.count("/") > 1 or val_strip.count(";") > 0 or val_strip.count("$") > 0:
                return False
        return True

    def _choose_version(self, existing: Dict[str, str], candidate: Dict[str, str]) -> Dict[str, str]:
        if not existing.get("sdk_version") or not self._is_valid_sdk_version(existing.get("sdk_version", "")):
            return candidate if candidate and self._is_valid_sdk_version(candidate.get("sdk_version", "")) else {"sdk_version": "", "sdk_version_source": "", "sdk_version_confidence": "none"}
        if not candidate or not self._is_valid_sdk_version(candidate.get("sdk_version", "")):
            return existing
        if self._version_candidate_better(existing, candidate):
            return candidate
        return existing

    def _parse_properties_blob(self, blob: str) -> Dict[str, str]:
        props: Dict[str, str] = {}
        for raw_line in blob.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith("!") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            props[key.strip()] = value.strip()
        return props

    def _process_files_and_extract(self):
        finding_map = {}
        self._scan_manifest_for_findings(finding_map)
        
        self._initialize_filesystem()
        
        # Prepare lookup structures for matching row
        sdk_candidates = []
        for row in self.sdk_rows:
            sdk_name = row.get("sdk_name", "")
            entry = self._sdk_catalog_entry(sdk_name)
            if entry is None:
                candidates = [row.get("sdk_name", ""), row.get("sdk_prefix", ""), row.get("sdk_identifier", "")]
            else:
                candidates = [entry.get("sdk_prefix", "")]
                candidates.extend(entry.get("smali_aliases", ()))
                candidates.extend([row.get("sdk_name", ""), row.get("sdk_identifier", "")])
            candidates = [c.lower() for c in candidates if c]
            sdk_candidates.append((row, candidates))
            
        sdk_version_candidates = {row["sdk_name"]: [] for row in self.sdk_rows}
        
        # Build file tasks, but cap smali files to avoid scanning 76k+ files per app.
        # Prioritize the app's own package files over SDK smali for better findings coverage.
        MAX_SMALI_FILES = 8000
        smali_tasks = []
        non_smali_tasks = []
        for path, rel, ftype in self._findings_files:
            if ftype == "smali":
                smali_tasks.append((path, rel, rel.lower(), ftype))
            else:
                non_smali_tasks.append((path, rel, rel.lower(), ftype))
        
        if len(smali_tasks) > MAX_SMALI_FILES:
            # Prioritize the app's own package smali files
            app_pkg = (self.app_row.get("manifest_package_name") or self.sample.package_name or "").replace(".", "/")
            own_smali = []
            sdk_smali = []
            for task in smali_tasks:
                if app_pkg and app_pkg in task[2]:
                    own_smali.append(task)
                else:
                    sdk_smali.append(task)
            remaining = MAX_SMALI_FILES - len(own_smali)
            if remaining > 0:
                smali_tasks = own_smali + sdk_smali[:remaining]
            else:
                smali_tasks = own_smali[:MAX_SMALI_FILES]
        
        tasks = smali_tasks + non_smali_tasks
            
        for path, rel_lower in self._pom_properties_files:
            tasks.append((path, path, rel_lower, "pom_properties"))
            
        findings_paths = {t[0] for t in tasks}
        for path, rel_lower in self._metadata_files:
            if path not in findings_paths:
                tasks.append((path, path, rel_lower, "metadata"))
                
        # Set total files scanned counter
        self.total_files_scanned = len(tasks)
                
        # Precompiled patterns
        CONST_VERSION_PATTERN = re.compile(r"^\d+\.(?:\d+\.)?\d+(?:[A-Za-z0-9._-]*)?$")
        version_pattern_res = re.compile(r"^\d+(?:\.\d+){1,4}(?:[-_A-Za-z0-9.]+)?$")
        version_pattern_meta = re.compile(r"\b\d+(?:\.\d+){1,4}(?:[-_A-Za-z0-9.]+)?\b")
        
        api_keywords = (
            b"AudioRecord", b"MediaRecorder", b"Microphone", b"RECORD_AUDIO",
            b"getImei", b"getDeviceId", b"getMeid", b"IMEI", b"SUBSCRIBER_ID",
            b"Bluetooth", b"BLUETOOTH", b"Clipboard", b"CLIPBOARD",
            b"Sms", b"SMS", b"CallLog", b"calllog", b"Locale", b"BuildConfig",
            b"CountryIso", b"MCC", b"MNC"
        )
        
        for path, rel, rel_lower, ftype in tasks[:50]:
            try:
                t_o = time.time()
                f = open(path, "rb")
                self.perf_timers["file_open"] += time.time() - t_o
                
                t_r = time.time()
                content_bytes = f.read()
                self.perf_timers["file_read"] += time.time() - t_r
                
                f.close()
            except Exception:
                continue
                
            if not content_bytes:
                continue
                
            matching_sdk_rows = []
            for row, candidates in sdk_candidates:
                if any(c in rel_lower for c in candidates):
                    matching_sdk_rows.append(row)
                    
            if ftype == "smali":
                self.stats["smali_files_scanned"] += 1
                
                # Cheap byte pre-checks
                has_const_string = b"const-string" in content_bytes
                has_pii_or_geo = False
                for kw in api_keywords:
                    if kw in content_bytes:
                        has_pii_or_geo = True
                        break
                        
                if not has_const_string and not has_pii_or_geo:
                    continue
                    
                t_d = time.time()
                content = content_bytes.decode("utf-8", errors="replace")
                self.perf_timers["file_decode"] += time.time() - t_d
                
                if has_pii_or_geo:
                    self._scan_text_for_findings(content, "smali", rel, finding_map, ["pii_api", "geo_logic"])
                    
                if has_const_string:
                    strings = re.findall(r'const-string(?:/jumbo)?\s+\S+,\s*"([^"]+)"', content)
                    strings = [s for s in strings if len(s) < 1000]
                    if strings:
                        strings_text = "\n".join(strings)
                        self._scan_text_for_findings(strings_text, "smali", rel, finding_map, ["secret", "endpoint"])
                        
                        if matching_sdk_rows:
                            t_v = time.time()
                            for s in strings:
                                val = s.strip()
                                self.regex_evals += 1
                                if CONST_VERSION_PATTERN.match(val):
                                    for row in matching_sdk_rows:
                                        sdk_version_candidates[row["sdk_name"]].append({
                                            "sdk_version": val,
                                            "sdk_version_source": "const_string",
                                            "sdk_version_confidence": "medium",
                                        })
                            self.perf_timers["version_extraction"] += time.time() - t_v
                                        
                if matching_sdk_rows and rel_lower.endswith("buildconfig.smali"):
                    t_v = time.time()
                    version_name = None
                    version_code = None
                    reg_consts = {}
                    for line in content.splitlines():
                        self.regex_evals += 1
                        match = re.search(r'const-string(?:/jumbo)?\s+(\S+),\s*"([^"]+)"', line)
                        if match:
                            reg_consts[match.group(1)] = match.group(2).strip()
                        if "VERSION_NAME" in line:
                            self.regex_evals += 2
                            match = re.search(r'sput-object\s+(\S+),', line)
                            if match and match.group(1) in reg_consts:
                                version_name = reg_consts[match.group(1)]
                            match = re.search(r'=\s*"([^"]+)"', line)
                            if match:
                                version_name = match.group(1).strip()
                        if "VERSION_CODE" in line:
                            self.regex_evals += 2
                            match = re.search(r'sput(?:\-object)?\s+(\S+),', line)
                            if match and match.group(1) in reg_consts:
                                version_code = reg_consts[match.group(1)]
                            match = re.search(r'=\s*(\d+|"[^"]+")', line)
                            if match:
                                version_code = match.group(1).strip().strip('"')
                    version = version_name or version_code
                    if version:
                        for row in matching_sdk_rows:
                            sdk_version_candidates[row["sdk_name"]].append({
                                "sdk_version": version,
                                "sdk_version_source": "buildconfig",
                                "sdk_version_confidence": "high",
                            })
                    self.perf_timers["version_extraction"] += time.time() - t_v
                            
            elif ftype == "res_values":
                self.stats["resource_files_scanned"] += 1
                t_d = time.time()
                content = content_bytes.decode("utf-8", errors="replace")
                self.perf_timers["file_decode"] += time.time() - t_d
                self._scan_resource_text_for_findings(rel, content, ftype, finding_map)
                
                if matching_sdk_rows:
                    t_v = time.time()
                    try:
                        root = ET.fromstring(content_bytes)
                    except Exception:
                        self.perf_timers["version_extraction"] += time.time() - t_v
                        continue
                    for string_el in root.findall("string"):
                        name = (string_el.get("name") or "").lower()
                        value = (string_el.text or "").strip()
                        self.regex_evals += 1
                        if not value or not version_pattern_res.match(value):
                            continue
                        for row in matching_sdk_rows:
                            if any(token in name for token in [row.get("sdk_name", "").lower(), row.get("sdk_prefix", "").lower().replace(".", "_"), row.get("sdk_prefix", "").lower().replace(".", "")]):
                                sdk_version_candidates[row["sdk_name"]].append({
                                    "sdk_version": value,
                                    "sdk_version_source": "resource_strings",
                                    "sdk_version_confidence": "low",
                                })
                    self.perf_timers["version_extraction"] += time.time() - t_v
                                
            elif ftype in ("res_xml", "assets_json", "assets_txt"):
                self.stats["resource_files_scanned"] += 1
                t_d = time.time()
                content = content_bytes.decode("utf-8", errors="replace")
                self.perf_timers["file_decode"] += time.time() - t_d
                self._scan_resource_text_for_findings(rel, content, ftype, finding_map)
                
            elif ftype == "pom_properties":
                if matching_sdk_rows:
                    t_v = time.time()
                    t_d = time.time()
                    content = content_bytes.decode("utf-8", errors="replace")
                    self.perf_timers["file_decode"] += time.time() - t_d
                    props = self._parse_properties_blob(content)
                    version = props.get("version", "").strip()
                    if version:
                        for row in matching_sdk_rows:
                            sdk_version_candidates[row["sdk_name"]].append({
                                "sdk_version": version,
                                "sdk_version_source": "pom_properties",
                                "sdk_version_confidence": "high",
                            })
                    self.perf_timers["version_extraction"] += time.time() - t_v
                            
            elif ftype == "metadata":
                if matching_sdk_rows:
                    t_v = time.time()
                    t_d = time.time()
                    content = content_bytes.decode("utf-8", errors="replace")
                    self.perf_timers["file_decode"] += time.time() - t_d
                    self.regex_evals += 1
                    match = version_pattern_meta.search(content)
                    if match:
                        for row in matching_sdk_rows:
                            sdk_version_candidates[row["sdk_name"]].append({
                                "sdk_version": match.group(0).strip(),
                                "sdk_version_source": "metadata_files",
                                "sdk_version_confidence": "low",
                            })
                    self.perf_timers["version_extraction"] += time.time() - t_v
                            
        t_v = time.time()
        for row in self.sdk_rows:
            best = {
                "sdk_version": row.get("sdk_version", ""),
                "sdk_version_source": row.get("sdk_version_source", ""),
                "sdk_version_confidence": row.get("sdk_version_confidence", "none")
            }
            if not self._is_valid_sdk_version(best.get("sdk_version", "")):
                best["sdk_version"] = ""
                best["sdk_version_source"] = ""
                best["sdk_version_confidence"] = "none"
                
            candidates = sdk_version_candidates.get(row["sdk_name"], [])
            for candidate in candidates:
                if not candidate or not candidate.get("sdk_version"):
                    continue
                if not self._is_valid_sdk_version(candidate.get("sdk_version", "")):
                    continue
                if not best.get("sdk_version"):
                    best = candidate
                    continue
                if self._version_candidate_better(best, candidate):
                    best = candidate
                    
            row["sdk_version"] = best.get("sdk_version", "")
            row["sdk_version_source"] = best.get("sdk_version_source", "")
            row["sdk_version_confidence"] = best.get("sdk_version_confidence", "none")
            if row["sdk_version"]:
                self.stats["sdk_versions_found"] += 1
        self.perf_timers["version_extraction"] += time.time() - t_v
                
        self._finalize_finding_rows(finding_map)

    def _collect_meta_data(self) -> List[Dict[str, str]]:
        meta = []
        if self.app_el is None:
            return meta
        for el in self.app_el.findall(".//meta-data"):
            item = {
                "name": self._get(el, "name", ""),
                "value": self._get(el, "value", ""),
                "resource": self._get(el, "resource", ""),
            }
            meta.append(item)
        return meta

    def _iter_manifest_evidence(self) -> List[Dict[str, str]]:
        evidence = []
        if self.app_el is None:
            return evidence

        for ctype in ["activity", "activity-alias", "service", "receiver", "provider"]:
            for el in self.app_el.findall(ctype):
                raw_name = self._get(el, "name", "")
                qname = self._qualified_name(raw_name)
                if qname:
                    evidence.append({"kind": "component_name", "source": ctype, "value": qname})
                if ctype == "provider":
                    authorities = self._get(el, "authorities", "")
                    for authority in [p.strip() for p in authorities.split(";") if p.strip()]:
                        evidence.append({"kind": "authority", "source": ctype, "value": authority})

        for md in self._collect_meta_data():
            for key in ["name", "value", "resource"]:
                if md.get(key):
                    evidence.append({"kind": f"meta_data_{key}", "source": "meta-data", "value": md[key]})

        for lib in self.app_el.findall("uses-library"):
            name = self._get(lib, "name", "")
            if name:
                evidence.append({"kind": "uses_library", "source": "uses-library", "value": name})

        return evidence

    def _evidence_matches_prefix(self, value: str, prefix: str) -> bool:
        v = (value or "").lower()
        p = prefix.lower()
        return v == p or v.startswith(p + ".") or v.startswith(p + "$") or p in v

    def _populate_sdk_counts(self):
        row = self.app_row
        row["sdk_detected_count"] = len(self.sdk_rows)
        row["sdk_china_count"] = sum(1 for r in self.sdk_rows if r["vendor_country_code"] == "CN")
        row["sdk_usa_count"] = sum(1 for r in self.sdk_rows if r["vendor_country_code"] == "US")
        row["sdk_india_count"] = sum(1 for r in self.sdk_rows if r["vendor_country_code"] == "IN")
        row["sdk_israel_count"] = sum(1 for r in self.sdk_rows if r["vendor_country_code"] == "IL")
        row["sdk_eu_count"] = sum(1 for r in self.sdk_rows if r["vendor_country_code"] in EU_MEMBER_STATES)
        row["sdk_other_count"] = sum(
            1 for r in self.sdk_rows
            if r["vendor_country_code"] not in {"CN", "US", "IN", "IL"} | EU_MEMBER_STATES
        )
        for cat in SDK_CATEGORIES:
            row[f"sdk_{cat}_count"] = sum(1 for r in self.sdk_rows if r["sdk_category"] == cat)

    def _detect_sdks(self):
        if self.sdk_inventory is not None:
            self.sdk_rows = self.sdk_inventory.to_sdk_rows(self._meta())
            self._populate_sdk_counts()
            
            # Reconstruct sdk_evidence for trace backward compatibility
            evidence_items = []
            for rec in self.sdk_inventory.records:
                evidence_items.append({
                    "kind": rec.evidence_type,
                    "source_file": "",  # Aggregated, so specific file is lost
                    "value": rec.evidence_value,
                    "sdk_name": rec.sdk_name,
                    "detected_manifest": rec.detected_manifest,
                    "detected_smali": rec.detected_smali,
                    "detected_native": rec.detected_native,
                    "detected_strings": rec.detected_strings,
                })
            
            # Populate trace and stats to maintain contract
            self.trace["sdk_evidence"] = evidence_items
            self.trace["sdks"] = self.sdk_rows
            self.stats["sdk_versions_found"] = sum(1 for r in self.sdk_rows if r.get("sdk_version"))
            return

        self._detect_sdks_legacy()

    def _detect_sdks_legacy(self):
        start_t = time.time()
        manifest_evidence = self._iter_manifest_evidence()
        meta_items = self._collect_meta_data()
        sdk_map: Dict[Tuple[str, str], Dict[str, Any]] = {}
        evidence_items: List[Dict[str, Any]] = []

        for md in meta_items:
            key = md.get("name", "")
            val = md.get("value", "") or md.get("resource", "")
            sdk_name = VERSION_META_KEYS.get(key)
            if sdk_name and val:
                evidence_items.append({
                    "kind": "meta_version",
                    "source_file": "AndroidManifest.xml",
                    "value": val,
                    "sdk_name": sdk_name,
                    "detected_manifest": True,
                    "detected_smali": False,
                    "detected_native": False,
                    "detected_strings": False,
                })

        for ev in manifest_evidence:
            evidence_items.append({
                "kind": ev["kind"],
                "source_file": "AndroidManifest.xml",
                "value": ev["value"],
                "sdk_name": None,
                "detected_manifest": True,
                "detected_smali": False,
                "detected_native": False,
                "detected_strings": False,
            })

        # OPTIMIZED: Instead of iterating all smali files (can be 76k+),
        # extract unique directory prefixes (3 segments deep) and match those.
        # This reduces _sdk_match_entries calls from ~76k*3 to ~hundreds.
        if self.app_row.get("has_smali"):
            self._ensure_cached_files()
            seen_prefixes: Set[str] = set()
            unique_candidates: List[Tuple[str, str]] = []  # (package_prefix, representative_rel_path)
            for path, rel_lower in self._smali_files[:50]:
                rel = os.path.relpath(path, self.sample.source_path).replace("\\", "/")
                # Extract package from smali path
                pkg = rel
                if pkg.endswith(".smali"):
                    pkg = pkg[:-6]
                if pkg.startswith("smali/"):
                    pkg = pkg[len("smali/"):]
                elif pkg.startswith("smali_classes"):
                    pkg = pkg.split("/", 1)[1] if "/" in pkg else ""
                # Take first 3 directory segments as prefix for dedup
                parts = pkg.split("/")
                for depth in (3, 4, len(parts)):
                    prefix = "/".join(parts[:depth])
                    if prefix and prefix not in seen_prefixes:
                        seen_prefixes.add(prefix)
                        pkg_dot = prefix.replace("/", ".")
                        unique_candidates.append((pkg_dot, rel))
            
            for candidate, rel_path in unique_candidates:
                matches = self._sdk_match_entries(candidate)
                if matches:
                    entry = matches[0]
                    evidence_items.append({
                        "kind": "smali_class",
                        "source_file": rel_path,
                        "value": candidate,
                        "sdk_name": entry["sdk_name"],
                        "detected_manifest": False,
                        "detected_smali": True,
                        "detected_native": False,
                        "detected_strings": False,
                    })

        for ev in evidence_items:
            matches = []
            if ev.get("sdk_name"):
                matches = [entry for entry in CURATED_SDK_CATALOG if entry["sdk_name"] == ev["sdk_name"]]
            else:
                matches = self._sdk_match_entries(ev["value"])
            if not matches:
                continue
            entry = matches[0]
            key = (self.sample.sample_id, entry["sdk_name"])
            update = self._create_sdk_record(
                entry,
                ev["kind"],
                ev["value"],
                ev.get("source_file", ""),
                ev.get("detected_manifest", False),
                ev.get("detected_smali", False),
                ev.get("detected_native", False),
                ev.get("detected_strings", False),
            )
            if key not in sdk_map:
                sdk_map[key] = update
                sdk_map[key]["_source_files"] = {ev.get("source_file", "")} if ev.get("source_file") else set()
                sdk_map[key]["_counted_files"] = {ev.get("source_file", "")} if ev.get("source_file") else set()
                sdk_map[key]["evidence_count"] = 1 if ev.get("source_file") else 0
                sdk_map[key]["source_file_count"] = len(sdk_map[key]["_source_files"])
            else:
                sdk_map[key].setdefault("_source_files", set())
                sdk_map[key].setdefault("_counted_files", set())
                if ev.get("source_file"):
                    sdk_map[key]["_source_files"].add(ev["source_file"])
                self._merge_sdk_row(sdk_map[key], update, ev.get("source_file", ""))

        t_agg = time.time()
        self._finalize_sdk_rows(sdk_map)
        agg_dur = time.time() - t_agg

        self._populate_sdk_counts()

        self.trace["sdk_evidence"] = evidence_items
        self.trace["sdks"] = self.sdk_rows
        self.perf_timers["sdk_detection"] += (time.time() - start_t) - agg_dur

    # -- Network Security Config --------------------------------------------

    def _resolve_xml_resource(self, ref: str) -> Optional[str]:
        if not ref:
            return None
        name = ref
        if ref.startswith("@xml/"):
            name = ref.split("/", 1)[1]
        elif ref.startswith("@"):
            return None
        if not name.endswith(".xml"):
            name += ".xml"
        path = os.path.join(self.sample.source_path, "res", "xml", name)
        return path if os.path.isfile(path) else None

    def _xml_has_network_config_nodes(self, root) -> bool:
        tags = {"network-security-config", "base-config", "domain-config", "debug-overrides", "pin-set", "trust-anchors"}
        return root.tag in tags or any(el.tag in tags for el in root.iter())

    def _parse_bool_attr(self, el, attr: str) -> Optional[bool]:
        if el is None:
            return None
        raw = el.get(attr)
        if raw is None:
            raw = el.get(A(attr))
        if raw is None:
            return None
        return raw == "true"

    def _cert_sources(self, node) -> List[str]:
        srcs = []
        for cert in node.findall(".//certificates"):
            src = cert.get("src") or cert.get(A("src")) or ""
            if src:
                srcs.append(src)
        return sorted(set(srcs))

    def _pin_digests(self, node) -> List[str]:
        pins = []
        for pin in node.findall(".//pin"):
            digest = pin.get("digest") or pin.get(A("digest")) or ""
            value = (pin.text or "").strip()
            if digest or value:
                pins.append(":".join([p for p in [digest, value] if p]))
        return sorted(set(pins))

    def _parse_network_config_file(self, path: str, scope: str) -> Tuple[List[Dict], Dict[str, Any]]:
        rows = []
        config_source = "manifest_reference" if scope == "main" else "xml_scan"
        summary = {
            "file": os.path.relpath(path, self.sample.source_path),
            "scope": scope,
            "config_source": config_source,
            "main_cleartext_global": None,
            "has_debug_overrides": False,
            "trust_user_certs_production": False,
            "pinned_domain_count": 0,
            "cleartext_exception_count": 0,
        }
        try:
            tree = ET.parse(path)
            root = tree.getroot()
        except Exception as e:
            self.warnings.append(f"Network config parse error in {path}: {e}")
            return rows, summary

        rel = os.path.relpath(path, self.sample.source_path)
        base = root.find("base-config") if root.tag != "base-config" else root
        if base is not None:
            base_clear = self._parse_bool_attr(base, "cleartextTrafficPermitted")
            summary["main_cleartext_global"] = base_clear if scope == "main" else None
            trust_srcs = self._cert_sources(base)
            pin_digests = self._pin_digests(base)
            if "user" in trust_srcs:
                summary["trust_user_certs_production"] = True
            rows.append({
                **self._meta(),
                "network_rule_id": make_network_rule_id(
                    self.sample.sample_id, rel, "base-config", "", base_clear, ";".join(trust_srcs)
                ),
                "config_file": rel,
                "config_scope": scope,
                "config_source": config_source,
                "rule_type": "base-config",
                "domain": "",
                "include_subdomains": None,
                "cleartext_permitted": base_clear,
                "trust_anchor_src": ";".join(trust_srcs),
                "pin_digest": ";".join(pin_digests),
                "override_pins": None,
                "is_debug_override": False,
                "applies_when_debuggable": False,
            })

        for debug in root.findall(".//debug-overrides"):
            summary["has_debug_overrides"] = True
            trust_srcs = self._cert_sources(debug)
            rows.append({
                **self._meta(),
                "network_rule_id": make_network_rule_id(
                    self.sample.sample_id, rel, "debug-overrides", "", "", ";".join(trust_srcs)
                ),
                "config_file": rel,
                "config_scope": scope,
                "config_source": config_source,
                "rule_type": "debug-overrides",
                "domain": "",
                "include_subdomains": None,
                "cleartext_permitted": None,
                "trust_anchor_src": ";".join(trust_srcs),
                "pin_digest": "",
                "override_pins": None,
                "is_debug_override": True,
                "applies_when_debuggable": True,
            })

        for dc in root.findall(".//domain-config"):
            clear = self._parse_bool_attr(dc, "cleartextTrafficPermitted")
            trust_srcs = self._cert_sources(dc)
            pin_digests = self._pin_digests(dc)
            override_raw = None
            pin_set = dc.find("pin-set")
            if pin_set is not None:
                override_raw = self._parse_bool_attr(pin_set, "overridePins")
            if "user" in trust_srcs:
                summary["trust_user_certs_production"] = True
            for domain_el in dc.findall("domain"):
                domain = (domain_el.text or "").strip()
                include = self._parse_bool_attr(domain_el, "includeSubdomains")
                if clear is True:
                    summary["cleartext_exception_count"] += 1
                if pin_digests:
                    summary["pinned_domain_count"] += 1
                rows.append({
                    **self._meta(),
                    "network_rule_id": make_network_rule_id(
                        self.sample.sample_id, rel, "domain-config", domain, clear, ";".join(trust_srcs)
                    ),
                    "config_file": rel,
                    "config_scope": scope,
                    "config_source": config_source,
                    "rule_type": "domain-config",
                    "domain": domain,
                    "include_subdomains": include,
                    "cleartext_permitted": clear,
                    "trust_anchor_src": ";".join(trust_srcs),
                    "pin_digest": ";".join(pin_digests),
                    "override_pins": override_raw,
                    "is_debug_override": False,
                    "applies_when_debuggable": False,
                })

        return rows, summary

    def _parse_network_configs(self):
        row = self.app_row
        nsc_ref = self._get(self.app_el, "networkSecurityConfig", "") if self.app_el is not None else ""
        main_path = self._resolve_xml_resource(nsc_ref)
        xml_dir = os.path.join(self.sample.source_path, "res", "xml")
        candidates: List[Tuple[str, str]] = []
        if main_path:
            candidates.append((main_path, "main"))
        _SDK_CONFIG_PREFIXES = (
            "firebase", "ads_", "admob", "appsflyer", "adjust",
            "facebook", "modules_network", "sdk_", "mediation",
        )
        if os.path.isdir(xml_dir):
            for name in sorted(os.listdir(xml_dir)):
                if not name.lower().endswith(".xml"):
                    continue
                path = os.path.join(xml_dir, name)
                if main_path and os.path.abspath(path) == os.path.abspath(main_path):
                    continue
                try:
                    root = ET.parse(path).getroot()
                except Exception:
                    continue
                if self._xml_has_network_config_nodes(root):
                    name_l = name.lower()
                    scope = "sdk_embedded" if any(name_l.startswith(p) for p in _SDK_CONFIG_PREFIXES) else "additional"
                    candidates.append((path, scope))

        all_rows = []
        summaries = []
        for path, scope in candidates:
            rows, summary = self._parse_network_config_file(path, scope)
            if rows or summary["has_debug_overrides"]:
                all_rows.extend(rows)
                summaries.append(summary)

        self.network_rows = all_rows
        main_summaries = [s for s in summaries if s["scope"] == "main"]
        row["netcfg_main_config_found"] = bool(main_summaries)
        row["netcfg_additional_config_count"] = sum(1 for s in summaries if s["scope"] in ("additional", "sdk_embedded"))
        row["netcfg_main_cleartext_global"] = (
            main_summaries[0]["main_cleartext_global"] if main_summaries else None
        )
        row["netcfg_cleartext_exception_count"] = sum(s["cleartext_exception_count"] for s in summaries)
        row["netcfg_pinned_domain_count"] = sum(s["pinned_domain_count"] for s in summaries)
        row["netcfg_trust_user_certs_production"] = any(s["trust_user_certs_production"] for s in summaries)
        row["netcfg_has_debug_overrides"] = any(s["has_debug_overrides"] for s in summaries)
        row["network_security_config_present"] = bool(nsc_ref) or bool(candidates)

        self.trace["network_config_files"] = summaries
        self.trace["network_rules"] = all_rows

    # -- Secrets, queries, coverage -----------------------------------------

    def _scan_secrets(self):
        counts = {"public_id": 0, "sensitive_token": 0, "possible_credential": 0}
        findings = []
        for md in self._collect_meta_data():
            key = md.get("name", "")
            value = md.get("value", "") or md.get("resource", "")
            if not value:
                continue
            key_l = key.lower()
            for cls, patterns in SECRET_PATTERNS.items():
                matched = ""
                for pat, label in patterns:
                    if re.search(pat, value):
                        matched = label
                        break
                if not matched and cls == "possible_credential":
                    if any(marker in key_l for marker in SENSITIVE_META_KEY_PATTERNS) and len(value) >= 16:
                        matched = "sensitive_meta_key"
                if matched:
                    counts[cls] += 1
                    findings.append({"meta_data_name": key, "class": cls, "pattern": matched})
                    break

        self.app_row["secret_public_id_count"] = counts["public_id"]
        self.app_row["secret_sensitive_token_count"] = counts["sensitive_token"]
        self.app_row["secret_possible_credential_count"] = counts["possible_credential"]
        self.trace["secret_findings"] = findings

    def _parse_queries(self):
        queries = self.root.find("queries") if self.root is not None else None
        if queries is None:
            self.app_row["queries_package_count"] = 0
            self.app_row["queries_intent_count"] = 0
            self.app_row["queries_provider_count"] = 0
            self.trace["queries"] = {"packages": [], "intent_count": 0, "providers": []}
            return
        packages = [self._get(el, "name", "") for el in queries.findall("package")]
        providers = [self._get(el, "authorities", "") for el in queries.findall("provider")]
        intents = queries.findall("intent")
        self.app_row["queries_package_count"] = len([p for p in packages if p])
        self.app_row["queries_intent_count"] = len(intents)
        self.app_row["queries_provider_count"] = len([p for p in providers if p])
        self.trace["queries"] = {
            "packages": sorted(p for p in packages if p),
            "intent_count": len(intents),
            "providers": sorted(p for p in providers if p),
        }

    def _detect_coverage(self):
        self._initialize_filesystem()

    def extract(self) -> Dict[str, Any]:
        s = self.sample
        self.app_row = {
            **self._meta(),
            "app_country_name": s.app_country_name,
            "app_store": s.app_store,
            "collection_batch": s.collection_batch,
            "apk_sha256": s.apk_sha256,
            "source_path": s.source_path,
            "notes": s.notes,
            "extraction_status": "ok",
        }
        self.trace = {
            "run_id": self.run_id,
            "schema_version": SCHEMA_VERSION,
            "parser_version": PARSER_VERSION,
            "sample_id": s.sample_id,
            "apk_sha256": s.apk_sha256,
            "source_path": s.source_path,
        }
        self._detect_coverage()
        if not self.app_row["has_smali"]:
            self.app_row["extraction_status"] = "skipped"
            self.app_row["manifest_sha256"] = ""
            return self._finalize()
        if not self._load_manifest():
            self.app_row["extraction_status"] = "error"
            self.app_row["manifest_sha256"] = ""
            self.trace["errors"] = self.errors
            return self._finalize()

        self.app_row["manifest_sha256"] = self.manifest_sha256
        self.app_row["manifest_package_name"] = self.root.get("package", "") if self.root is not None else ""
        self._parse_identity()
        self._parse_permissions()
        self._parse_components()
        self._parse_network_configs()
        self._detect_sdks()
        self._extract_findings()
        self._scan_secrets()
        self._parse_queries()
        return self._finalize()

    def _finalize(self) -> Dict[str, Any]:
        for col in APP_COLUMNS:
            if col not in self.app_row:
                self.app_row[col] = _default_for_column(col)
        self.app_row["warnings"] = "; ".join(self.warnings)
        self.app_row["errors"] = "; ".join(self.errors)
        self.trace["warnings"] = self.warnings
        self.trace["errors"] = self.errors
        self.trace["statistics"] = {
            "smali_files_scanned": self.stats["smali_files_scanned"],
            "resource_files_scanned": self.stats["resource_files_scanned"],
            "sdk_versions_found": self.stats["sdk_versions_found"],
            "duplicates_suppressed": self.stats["duplicates_suppressed"],
            "findings_by_type": dict(self.stats["findings_by_type"]),
        }
        return {
            "app": self.app_row,
            "sdks": self.sdk_rows,
            "components": self.component_rows,
            "permissions": self.permission_rows,
            "network_domains": self.network_rows,
            "findings": self.finding_rows,
            "trace": self.trace,
        }


