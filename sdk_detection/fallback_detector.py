"""
FallbackDetector — permanent prefix-based SDK detector.

This is a direct port of the detection logic in
manifest_scanner/extractor.py (_detect_sdks, _sdk_match_entries).
It is NOT a transitional component — it remains the always-available
baseline even after LibScan is integrated.

Detection knowledge (sdk_prefix, smali_aliases) is loaded exclusively
from sdk_metadata.csv. No internal catalog is maintained here.

Output: List[DetectedLibrary], one entry per detected SDK per APK.
"""

from __future__ import annotations

import csv
import logging
import os
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from sdk_detection.interfaces import BaseDetector
from sdk_detection.models import DetectedLibrary, DetectionContext

logger = logging.getLogger(__name__)

_DEFAULT_CSV = Path(__file__).parent / "metadata" / "sdk_metadata.csv"

# Android manifest namespace helper
_ANDROID_NS = "http://schemas.android.com/apk/res/android"

def _A(attr: str) -> str:
    return f"{{{_ANDROID_NS}}}{attr}"

# Meta-data keys that carry SDK version values (parallel to manifest_scanner VERSION_META_KEYS)
_VERSION_META_KEYS: Dict[str, str] = {
    "com.google.android.gms.version": "Google Play Services",
    "com.facebook.sdk.ApplicationId": "Facebook SDK",
    "com.bytedance.sdk.pangle.version": "ByteDance/Pangle",
    "com.appsflyer.api_version": "AppsFlyer",
    "com.google.android.play.billingclient.version": "Play Billing",
    "applovin.sdk.key": "AppLovin MAX",
    "ironsource.sdk.key": "ironSource/LevelPlay",
}


# ─────────────────────────────────────────────────────────────────────────────
# Internal catalog entry
# ─────────────────────────────────────────────────────────────────────────────

class _CatalogEntry:
    __slots__ = ("sdk_name", "sdk_prefix", "smali_aliases", "prefix_l", "alias_patterns")

    def __init__(self, sdk_name: str, sdk_prefix: str, smali_aliases: List[str]) -> None:
        self.sdk_name = sdk_name
        self.sdk_prefix = sdk_prefix
        self.smali_aliases = smali_aliases
        self.prefix_l = sdk_prefix.lower()
        # All patterns: dotted prefix + each smali alias
        self.alias_patterns: List[str] = [self.prefix_l]
        self.alias_patterns.extend(a.lower() for a in smali_aliases)


# ─────────────────────────────────────────────────────────────────────────────
# FallbackDetector
# ─────────────────────────────────────────────────────────────────────────────

class FallbackDetector(BaseDetector):
    """
    Prefix-based SDK detector. Reads detection columns from sdk_metadata.csv.
    Implements the same matching algorithm as extractor._sdk_match_entries().
    """

    def __init__(self, csv_path: Path = _DEFAULT_CSV) -> None:
        self._catalog: List[_CatalogEntry] = []
        self._load_catalog(csv_path)

    def _load_catalog(self, path: Path) -> None:
        if not path.exists():
            logger.error("sdk_metadata.csv not found at %s", path)
            return
        try:
            with open(path, newline="", encoding="utf-8") as fh:
                reader = csv.DictReader(fh)
                seen: Set[str] = set()
                for row in reader:
                    name = (row.get("sdk_name") or "").strip()
                    prefix = (row.get("sdk_prefix") or "").strip()
                    if not name or not prefix:
                        continue
                    if name in seen:
                        continue
                    seen.add(name)
                    raw_smali = (row.get("smali_aliases") or "").strip()
                    smali_aliases = [s.strip() for s in raw_smali.split(";") if s.strip()]
                    self._catalog.append(_CatalogEntry(name, prefix, smali_aliases))
            # Sort longest prefix first for accurate longest-prefix matching
            self._catalog.sort(key=lambda e: len(e.sdk_prefix), reverse=True)
            logger.debug("FallbackDetector: loaded %d catalog entries", len(self._catalog))
        except Exception as exc:
            logger.error("FallbackDetector: failed to load catalog: %s", exc)

    # ── Matching ─────────────────────────────────────────────────────────────

    def _match_value(self, value: str) -> List[_CatalogEntry]:
        """
        Return catalog entries that match `value` (a package name, smali path,
        component name, or authority string).
        Mirrors extractor._sdk_match_entries() exactly.
        """
        if not value:
            return []
        v = value.lower()
        # Fast reject: most values don't contain any known root
        if "com" not in v and "androidx" not in v and "io" not in v and "net" not in v and "ly" not in v and "org" not in v:
            return []
        matches = []
        for entry in self._catalog:
            p = entry.prefix_l
            matched = (
                v == p
                or v.startswith(p + ".")
                or v.startswith(p + "/")
                or v.startswith(p + "$")
                or p in v
            )
            if not matched:
                for alias in entry.alias_patterns:
                    if v == alias or v.startswith(alias + ".") or v.startswith(alias + "/") or v.startswith(alias + "$") or alias in v:
                        matched = True
                        break
            if matched:
                matches.append(entry)
        return matches

    def _best_match(self, value: str) -> Optional[_CatalogEntry]:
        """Return the most specific (longest-prefix) match for value."""
        matches = self._match_value(value)
        return matches[0] if matches else None  # already sorted longest-first

    # ── Manifest helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _collect_manifest_evidence(apk_dir: Path) -> Tuple[List[dict], List[dict]]:
        """
        Parse AndroidManifest.xml and return:
            manifest_evidence: list of {kind, value} dicts
            meta_items:        list of {name, value, resource} dicts
        Returns ([], []) if manifest is missing or unparseable.
        """
        manifest_path = apk_dir / "AndroidManifest.xml"
        if not manifest_path.exists():
            return [], []
        try:
            tree = ET.parse(str(manifest_path))
            root = tree.getroot()
        except Exception as exc:
            logger.warning("FallbackDetector: cannot parse manifest: %s", exc)
            return [], []

        app_el = root.find("application")
        if app_el is None:
            return [], []

        pkg = root.get("package", "")
        evidence = []
        meta_items = []

        def qualified(name: str) -> str:
            if not name:
                return ""
            if name.startswith(".") and pkg:
                return f"{pkg}{name}"
            if "." not in name and pkg:
                return f"{pkg}.{name}"
            return name

        comp_types = ["activity", "activity-alias", "service", "receiver", "provider"]
        for ctype in comp_types:
            for el in app_el.findall(ctype):
                raw = el.get(_A("name"), "")
                qname = qualified(raw)
                if qname:
                    evidence.append({"kind": "component_name", "value": qname})
                if ctype == "provider":
                    auths = el.get(_A("authorities"), "")
                    for auth in [a.strip() for a in auths.split(";") if a.strip()]:
                        evidence.append({"kind": "authority", "value": auth})

        for lib in app_el.findall("uses-library"):
            name = lib.get(_A("name"), "")
            if name:
                evidence.append({"kind": "uses_library", "value": name})

        for md in app_el.findall(".//meta-data"):
            item = {
                "name": md.get(_A("name"), ""),
                "value": md.get(_A("value"), ""),
                "resource": md.get(_A("resource"), ""),
            }
            meta_items.append(item)
            for key in ("name", "value", "resource"):
                v = item.get(key, "")
                if v:
                    evidence.append({"kind": f"meta_data_{key}", "value": v})

        return evidence, meta_items

    # ── Smali helpers ─────────────────────────────────────────────────────────

    @staticmethod
    def _collect_smali_prefixes(apk_dir: Path) -> List[str]:
        """
        Walk the decoded APK directory and extract unique dotted package
        prefixes from smali file paths (3–4 directory segments deep).
        Mirrors the optimized deduplication in extractor._detect_sdks().
        """
        seen: Set[str] = set()
        prefixes: List[str] = []

        for dirpath, dirnames, filenames in os.walk(str(apk_dir)):
            dirnames.sort()
            rel_dir = os.path.relpath(dirpath, str(apk_dir)).replace("\\", "/")
            rel_l = rel_dir.lower()
            # Only descend into smali directories
            if not (rel_l == "." or rel_l.startswith("smali") or "/smali" in rel_l):
                continue
            for fname in filenames:
                if not fname.endswith(".smali"):
                    continue
                rel_file = os.path.join(rel_dir, fname).replace("\\", "/")
                if rel_file.endswith(".smali"):
                    rel_file = rel_file[:-6]
                # Strip leading smali dir component
                parts = rel_file.split("/")
                if parts and parts[0].startswith("smali"):
                    parts = parts[1:]
                if not parts:
                    continue
                # Emit prefixes at depth 3 and 4
                for depth in (3, 4, len(parts)):
                    if depth > len(parts):
                        break
                    prefix_slash = "/".join(parts[:depth])
                    if prefix_slash not in seen:
                        seen.add(prefix_slash)
                        prefixes.append(prefix_slash.replace("/", "."))
        return prefixes

    # ── Core detection ────────────────────────────────────────────────────────

    def detect(self, context: DetectionContext) -> List[DetectedLibrary]:
        """
        Detect SDKs using prefix matching on manifest evidence + smali prefixes.
        Returns one DetectedLibrary per distinct SDK; never raises.
        """
        try:
            return self._detect(context)
        except Exception as exc:
            logger.error("FallbackDetector.detect() error: %s", exc, exc_info=True)
            return []

    def _detect(self, context: DetectionContext) -> List[DetectedLibrary]:
        # sdk_name → DetectedLibrary accumulator
        sdk_map: Dict[str, DetectedLibrary] = {}

        def _upsert(
            entry: _CatalogEntry,
            detected_manifest: bool,
            detected_smali: bool,
            evidence_type: str,
            evidence_value: str,
            source_file: str = "",
        ) -> None:
            name = entry.sdk_name
            if name not in sdk_map:
                sdk_map[name] = DetectedLibrary(
                    sdk_name=name,
                    package=entry.sdk_prefix,
                    detection_source="fallback",
                    detected_manifest=detected_manifest,
                    detected_smali=detected_smali,
                    detection_source_primary="manifest" if detected_manifest else "smali",
                    evidence_type=evidence_type,
                    evidence_value=evidence_value,
                    evidence_count=1,
                    source_file_count=1 if source_file else 0,
                )
            else:
                rec = sdk_map[name]
                rec.detected_manifest = rec.detected_manifest or detected_manifest
                rec.detected_smali = rec.detected_smali or detected_smali
                rec.evidence_count += 1
                if source_file:
                    rec.source_file_count += 1
                if detected_manifest and rec.detection_source_primary != "manifest":
                    rec.detection_source_primary = "manifest"

        # 1. Manifest evidence
        for ev in context.manifest_evidence:
            entry = self._best_match(ev["value"])
            if entry:
                _upsert(entry, True, False, ev["kind"], ev["value"])

        # 2. Version meta-data keys
        for md in context.meta_items:
            key = md.get("name", "")
            val = md.get("value", "") or md.get("resource", "")
            sdk_name = _VERSION_META_KEYS.get(key)
            if sdk_name and val:
                # Find the catalog entry by sdk_name
                for ce in self._catalog:
                    if ce.sdk_name == sdk_name:
                        rec = sdk_map.get(sdk_name)
                        if rec is None:
                            sdk_map[sdk_name] = DetectedLibrary(
                                sdk_name=sdk_name,
                                package=ce.sdk_prefix,
                                detection_source="fallback",
                                detected_manifest=True,
                                detection_source_primary="manifest",
                                evidence_type="meta_version",
                                evidence_value=val,
                                evidence_count=1,
                                version_hint=val,
                                version_source="manifest_meta_data",
                                version_confidence="high",
                            )
                        else:
                            if not rec.version_hint:
                                rec.version_hint = val
                                rec.version_source = "manifest_meta_data"
                                rec.version_confidence = "high"
                        break

        # 3. Smali prefixes
        for pkg_dot in context.smali_prefixes:
            entry = self._best_match(pkg_dot)
            if entry:
                _upsert(entry, False, True, "smali_class", pkg_dot)

        return list(sdk_map.values())
