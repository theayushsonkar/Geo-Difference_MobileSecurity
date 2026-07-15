"""
Data models for the SDK detection pipeline.

Hierarchy:
    DetectedLibrary   — raw output from any BaseDetector
    TrackerInfo       — output from any BaseClassifier
    SDKMeta           — enrichment row from sdk_metadata.csv
    SDKRecord         — fully enriched record; maps 1-to-1 to SDK_COLUMNS rows
    SDKInventory      — immutable container passed to all downstream modules
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ─────────────────────────────────────────────────────────────────────────────
# Context
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class DetectionContext:
    """Encapsulates all inputs required by detectors."""
    apk_path: str
    decoded_dir: str
    run_id: str
    manifest_evidence: List[dict] = field(default_factory=list)
    smali_prefixes: List[str] = field(default_factory=list)
    meta_items: List[dict] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Detector output
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class DetectedLibrary:
    """Raw detection result from one detector before canonicalization or enrichment."""

    sdk_name: str                    # Name as emitted by the detector (may be raw/aliased)
    package: str                     # Matched package prefix (e.g. "com.google.firebase")
    detection_source: str            # "libscan" | "fallback"
    detector_name: str = ""          # Original library name from the detector
    raw_detector_output: Optional[Any] = None # Original detector evidence (e.g. text line)

    detected_manifest: bool = False
    detected_smali: bool = False
    detected_native: bool = False
    detected_strings: bool = False
    detection_source_primary: str = ""
    evidence_type: str = ""          # e.g. "component_name", "smali_class", "meta_version"
    evidence_value: str = ""
    evidence_count: int = 1
    source_file_count: int = 0

    # Version hint, if the detector found one (e.g. from meta-data version keys)
    version_hint: Optional[str] = None
    version_source: str = ""
    version_confidence: str = "none"





# ─────────────────────────────────────────────────────────────────────────────
# Metadata loader output
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SDKMeta:
    """One row from sdk_metadata.csv (metadata columns only)."""
    sdk_name: str
    vendor: str = ""
    vendor_country_code: str = ""
    vendor_region_group: str = ""
    sdk_category: str = ""
    sdk_identifier: str = ""        # Maven coordinate or stable ID
    sdk_ecosystem: str = "custom"   # "maven" | "custom"
    cpe: str = ""


# ─────────────────────────────────────────────────────────────────────────────
# Final enriched record
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SDKRecord:
    """
    Fully enriched SDK record.

    This is the unit that ManifestFeatureExtractor consumes via
    SDKInventory.to_sdk_rows(). All fields map directly to SDK_COLUMNS.
    No downstream module should access SDKRecord internals directly —
    they should go through to_sdk_rows() or SDKInventory helpers.
    """

    # ── Detection ─────────────────────────────────────────────────────────
    sdk_name: str
    sdk_prefix: str                  # canonical package prefix (for SDK_COLUMNS compat)
    package: str                     # matched package prefix

    # ── Provenance ────────────────────────────────────────────────────────
    detection_source: str = "fallback"
    # "libscan" | "fallback" | "both"

    # ── Version (populated separately, always Optional) ───────────────────
    sdk_version: str = ""
    sdk_version_source: str = ""
    sdk_version_confidence: str = "none"

    # ── Tracker classification (Exodus, optional) ─────────────────────────
    is_tracker: bool = False
    tracker_name: str = ""
    tracker_categories: str = ""
    network_signature: str = ""
    website: str = ""

    # ── Enrichment metadata (MetadataLoader) ──────────────────────────────
    vendor: str = ""
    vendor_country_code: str = ""
    vendor_region_group: str = ""
    sdk_category: str = ""
    sdk_identifier: str = ""
    sdk_ecosystem: str = "custom"
    cpe: str = ""

    # ── Detection flags (SDK_COLUMNS backward compat) ─────────────────────
    detected_manifest: bool = False
    detected_smali: bool = False
    detected_native: bool = False
    detected_strings: bool = False
    detection_source_primary: str = ""
    evidence_type: str = ""
    evidence_value: str = ""
    evidence_count: int = 1
    source_file_count: int = 0

    def to_row(self, meta: Dict[str, Any]) -> Dict[str, Any]:
        """
        Produce a dict compatible with manifest_scanner/schema.py:SDK_COLUMNS.

        Args:
            meta: The _meta() dict from ManifestFeatureExtractor
                  (run_id, schema_version, parser_version, sample_id,
                   package_name, app_country_code, app_region_group).
        """
        from manifest_scanner.models import make_sdk_id
        sdk_id = make_sdk_id(
            meta.get("sample_id", ""),
            self.sdk_name,
            self.sdk_prefix,
            self.sdk_version,
            self.vendor_country_code,
            self.sdk_category,
        )
        return {
            **meta,
            "sdk_id": sdk_id,
            "sdk_name": self.sdk_name,
            "sdk_prefix": self.sdk_prefix,
            "sdk_version": self.sdk_version,
            "sdk_version_source": self.sdk_version_source,
            "sdk_version_confidence": self.sdk_version_confidence,
            "sdk_ecosystem": self.sdk_ecosystem,
            "sdk_identifier": self.sdk_identifier,
            "sdk_category": self.sdk_category,
            "vendor_country_code": self.vendor_country_code,
            "vendor_region_group": self.vendor_region_group,
            "is_tracker": self.is_tracker,
            "tracker_name": self.tracker_name,
            "tracker_categories": self.tracker_categories,
            "network_signature": self.network_signature,
            "website": self.website,
            "detected_manifest": self.detected_manifest,
            "detected_smali": self.detected_smali,
            "detected_native": self.detected_native,
            "detected_strings": self.detected_strings,
            "detection_source_primary": self.detection_source_primary,
            "evidence_type": self.evidence_type,
            "evidence_value": self.evidence_value,
            "evidence_count": self.evidence_count,
            "source_file_count": self.source_file_count,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Inventory container
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SDKInventory:
    """
    Immutable SDK inventory for one APK.
    Passed to ManifestFeatureExtractor, StaticAnalyzer, etc.
    Never modified after build_inventory() returns.
    """

    records: List[SDKRecord]
    raw_evidence: Dict[str, List[DetectedLibrary]]
    context: DetectionContext
    detector_info: Dict[str, Any]
    exodus_available: bool = False

    def by_name(self, name: str) -> Optional[SDKRecord]:
        """Return the first SDKRecord matching sdk_name, or None."""
        for rec in self.records:
            if rec.sdk_name == name:
                return rec
        return None

    def to_sdk_rows(self, meta: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Produce a list of dicts compatible with SDK_COLUMNS.
        This is the sole compatibility bridge between SDKInventory and the
        existing CSV / trace / statistics pipeline.
        """
        return [rec.to_row(meta) for rec in self.records]

    @classmethod
    def empty(cls, context: DetectionContext) -> "SDKInventory":
        """Return an empty inventory (used when all detection fails)."""
        return cls(
            records=[],
            raw_evidence={},
            context=context,
            detector_info={"fallback": {"available": True, "runtime_ms": 0}},
            exodus_available=False,
        )
