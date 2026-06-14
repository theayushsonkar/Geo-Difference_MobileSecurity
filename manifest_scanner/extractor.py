"""
Core ManifestFeatureExtractor class and extraction logic.
"""

import hashlib
import os
import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from .constants import (
    A, ALL_FAMILIES, DANGEROUS_PERMISSIONS, KNOWN_SDK_DATABASE,
    PARSER_VERSION, PERMISSION_FAMILIES, PRIVACY_SANDBOX_PERMISSIONS,
    SCHEMA_VERSION, SECRET_PATTERNS, SDK_CATEGORIES, SENSITIVE_META_KEY_PATTERNS,
    VERSION_META_KEYS, get_region, EU_MEMBER_STATES
)
from .models import (
    SampleRecord, make_component_id, make_network_rule_id,
    make_permission_id, make_sdk_id
)
from .schema import APP_COLUMNS, _default_for_column

class ManifestFeatureExtractor:

    def __init__(self, sample: SampleRecord, run_id: str):
        self.sample = sample
        self.run_id = run_id
        self.warnings: List[str] = []
        self.errors: List[str] = []
        # Populated during extraction
        self.root = None
        self.app_el = None
        self.manifest_sha256 = ""
        self.raw_bytes = b""
        self.target_sdk = 0
        self.min_sdk = 0
        # Result accumulators
        self.app_row: Dict[str, Any] = {}
        self.sdk_rows: List[Dict] = []
        self.component_rows: List[Dict] = []
        self.permission_rows: List[Dict] = []
        self.network_rows: List[Dict] = []
        self.trace: Dict[str, Any] = {}

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

    # ── Load & Hash ──────────────────────────────────────────────────────────

    def _load_manifest(self) -> bool:
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

    def _detect_sdks(self):
        evidence = self._iter_manifest_evidence()
        meta_items = self._collect_meta_data()
        detected: Dict[Tuple[str, str], Dict[str, Any]] = {}

        versions_by_sdk: Dict[str, str] = {}
        for md in meta_items:
            key = md.get("name", "")
            val = md.get("value", "") or md.get("resource", "")
            sdk_name = VERSION_META_KEYS.get(key)
            if sdk_name and val:
                versions_by_sdk[sdk_name] = val

        for prefix, (sdk_name, vendor_cc, sdk_cat) in sorted(KNOWN_SDK_DATABASE.items()):
            matches = [ev for ev in evidence if self._evidence_matches_prefix(ev["value"], prefix)]
            if not matches:
                continue
            sdk_version = versions_by_sdk.get(sdk_name, "")
            first = matches[0]
            key = (sdk_name, prefix)
            detected[key] = {
                **self._meta(),
                "sdk_id": make_sdk_id(
                    self.sample.sample_id, sdk_name, prefix, sdk_version, vendor_cc, sdk_cat
                ),
                "sdk_name": sdk_name,
                "sdk_prefix": prefix,
                "sdk_version": sdk_version,
                "sdk_category": sdk_cat,
                "vendor_country_code": vendor_cc,
                "vendor_region_group": get_region(vendor_cc),
                "detected_manifest": True,
                "detected_smali": False,
                "detected_native": False,
                "detected_strings": False,
                "detection_source_primary": "manifest",
                "evidence_type": first["kind"],
                "evidence_value": first["value"],
                "evidence_count": len(matches),
            }

        self.sdk_rows = sorted(
            detected.values(),
            key=lambda r: (r["sdk_category"], r["sdk_name"], r["sdk_prefix"]),
        )

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

        self.trace["sdk_evidence"] = evidence
        self.trace["sdks"] = self.sdk_rows

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
        src = self.sample.source_path
        self.app_row["has_manifest"] = os.path.isfile(os.path.join(src, "AndroidManifest.xml"))
        self.app_row["has_smali"] = any(
            os.path.isdir(os.path.join(src, name)) and name.startswith("smali")
            for name in os.listdir(src)
        ) if os.path.isdir(src) else False
        lib_dir = os.path.join(src, "lib")
        self.app_row["has_native_libs"] = False
        if os.path.isdir(lib_dir):
            for _, _, files in os.walk(lib_dir):
                if any(f.endswith(".so") for f in files):
                    self.app_row["has_native_libs"] = True
                    break
        self.app_row["has_res_xml"] = os.path.isdir(os.path.join(src, "res", "xml"))

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
        return {
            "app": self.app_row,
            "sdks": self.sdk_rows,
            "components": self.component_rows,
            "permissions": self.permission_rows,
            "network_domains": self.network_rows,
            "trace": self.trace,
        }


