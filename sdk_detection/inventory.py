"""
inventory.py — build_inventory() orchestrates the full SDK detection pipeline.

Pipeline (Phase 3):
    LibScan (Primary) + FallbackDetector (Secondary)  →  Canonicalizer  →  NullClassifier  →  MetadataLoader
                                                                                           ↓
                                                                                    SDKInventory

The merged SDKInventory is the authoritative representation used by downstream modules.
LibScan is the primary signature-based detector.
FallbackDetector complements LibScan by detecting SDKs absent from the LibScan reference database.

Phase 4 will replace NullClassifier with ExodusClassifier.
No downstream code changes required for either phase.

Usage (from run_full_pipeline.py):
    inventory = build_inventory(apk_dir=sample.source_path, run_id=run_id)
    extractor = ManifestFeatureExtractor(sample, run_id, sdk_inventory=inventory)
"""

from __future__ import annotations

import copy
import logging
from pathlib import Path
from typing import List, Optional

from sdk_detection.canonicalizer import Canonicalizer
from sdk_detection.fallback_detector import FallbackDetector
from sdk_detection.metadata_loader import MetadataLoader
from sdk_detection.models import (
    DetectedLibrary,
    SDKInventory,
    SDKRecord,
    DetectionContext,
)

import importlib
import time

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Detector Configuration
# ─────────────────────────────────────────────────────────────────────────────
# Order defines execution precedence. Future detectors (e.g., LibScoutRunner)
# can be added to this list without modifying pipeline code.
SDK_DETECTORS = [
    "sdk_detection.libscan_runner.LibScanRunner",
    "sdk_detection.fallback_detector.FallbackDetector",
]

_canonicalizer: Optional[Canonicalizer] = None
_metadata_loader: Optional[MetadataLoader] = None
_detector_instances = {}


def _get_core_singletons() -> tuple:
    global _canonicalizer, _metadata_loader
    if _canonicalizer is None:
        _canonicalizer = Canonicalizer()
    if _metadata_loader is None:
        _metadata_loader = MetadataLoader()
    return _canonicalizer, _metadata_loader


def _get_detector(classpath: str):
    global _detector_instances
    if classpath not in _detector_instances:
        try:
            module_name, class_name = classpath.rsplit(".", 1)
            module = importlib.import_module(module_name)
            cls = getattr(module, class_name)
            _detector_instances[classpath] = cls()
        except Exception as exc:
            logger.error("build_inventory: Failed to initialize %s: %s", classpath, exc)
            _detector_instances[classpath] = None
    return _detector_instances[classpath]


# ─────────────────────────────────────────────────────────────────────────────
# Canonicalize raw library names
# ─────────────────────────────────────────────────────────────────────────────

def _canonicalize(
    libraries: List[DetectedLibrary],
    canon: Canonicalizer,
) -> tuple[List[DetectedLibrary], dict[str, List[DetectedLibrary]]]:
    """
    Resolve each raw sdk_name to its canonical name.
    Merge duplicates that resolve to the same canonical name.
    """
    merged: dict = {}
    raw_evidence: dict = {}
    
    for lib in libraries:
        canonical_name = canon.resolve(lib.sdk_name)
        
        if canonical_name not in raw_evidence:
            raw_evidence[canonical_name] = []
        raw_evidence[canonical_name].append(lib)
        
        merged_lib = copy.copy(lib)
        merged_lib.sdk_name = canonical_name
        
        if canonical_name not in merged:
            merged[canonical_name] = merged_lib
        else:
            existing = merged[canonical_name]
            existing.detected_manifest = existing.detected_manifest or merged_lib.detected_manifest
            existing.detected_smali = existing.detected_smali or merged_lib.detected_smali
            existing.detected_native = existing.detected_native or merged_lib.detected_native
            existing.detected_strings = existing.detected_strings or merged_lib.detected_strings
            existing.evidence_count += merged_lib.evidence_count
            existing.source_file_count += merged_lib.source_file_count
            if not existing.version_hint and merged_lib.version_hint:
                existing.version_hint = merged_lib.version_hint
                existing.version_source = merged_lib.version_source
                existing.version_confidence = merged_lib.version_confidence
            if existing.detection_source != merged_lib.detection_source:
                existing.detection_source = "both"
                
    return list(merged.values()), raw_evidence


# ─────────────────────────────────────────────────────────────────────────────
# Convert DetectedLibrary → SDKRecord
# ─────────────────────────────────────────────────────────────────────────────

def _to_sdk_record(lib: DetectedLibrary) -> SDKRecord:
    return SDKRecord(
        sdk_name=lib.sdk_name,
        sdk_prefix=lib.package,
        package=lib.package,
        detection_source=lib.detection_source,
        sdk_version=lib.version_hint or "",
        sdk_version_source=lib.version_source,
        sdk_version_confidence=lib.version_confidence,
        detected_manifest=lib.detected_manifest,
        detected_smali=lib.detected_smali,
        detected_native=lib.detected_native,
        detected_strings=lib.detected_strings,
        detection_source_primary=lib.detection_source_primary,
        evidence_type=lib.evidence_type,
        evidence_value=lib.evidence_value,
        evidence_count=lib.evidence_count,
        source_file_count=lib.source_file_count,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def build_inventory(
    apk_dir: str,
    run_id: str,
    *,
    apk_path: str = "",
    manifest_evidence: Optional[List[dict]] = None,
    smali_prefixes: Optional[List[str]] = None,
    meta_items: Optional[List[dict]] = None,
) -> SDKInventory:
    """
    Build an SDKInventory for the decoded APK at `apk_dir`.

    Args:
        apk_dir:           Path string to the decoded APK root directory.
        run_id:            Pipeline run identifier (for tracing).
        manifest_evidence: Pre-parsed manifest evidence (optional). If None,
                           the function scans AndroidManifest.xml itself.
        smali_prefixes:    Pre-extracted smali package prefixes (optional).
                           If None, the function walks smali dirs itself.
        meta_items:        Pre-parsed meta-data items (optional). If None,
                           extracted during manifest parsing.

    Returns:
        SDKInventory — immutable, ready to pass to ManifestFeatureExtractor.
        On any unrecoverable error, returns SDKInventory.empty().
    """
    canon, loader = _get_core_singletons()
    decoded_path = Path(apk_dir)

    # ── Step 0: collect APK inputs if not provided ────────────────────────────
    if manifest_evidence is None or meta_items is None:
        # We temporarily use FallbackDetector's static methods here to extract
        # common manifest details without depending on a specific detector run.
        from sdk_detection.fallback_detector import FallbackDetector
        scanned_evidence, scanned_meta = FallbackDetector._collect_manifest_evidence(decoded_path)
        if manifest_evidence is None:
            manifest_evidence = scanned_evidence
        if meta_items is None:
            meta_items = scanned_meta

    if smali_prefixes is None:
        from sdk_detection.fallback_detector import FallbackDetector
        smali_prefixes = FallbackDetector._collect_smali_prefixes(decoded_path)

    context = DetectionContext(
        apk_path=apk_path,
        decoded_dir=str(decoded_path),
        run_id=run_id,
        manifest_evidence=manifest_evidence or [],
        smali_prefixes=smali_prefixes or [],
        meta_items=meta_items or []
    )

    # ── Step 1: Detection ─────────────────────────────────────────────────────
    # The merged SDKInventory is the authoritative representation.
    # Primary detectors (like LibScan) and secondary detectors (like Fallback)
    # produce raw lists of DetectedLibrary objects that are later canonicalized
    # and merged.
    libraries = []
    detector_info = {}

    for classpath in SDK_DETECTORS:
        det_name = classpath.rsplit(".", 1)[-1].lower().replace("runner", "").replace("detector", "")
        
        # Initialize default metadata layout for reproducibility
        detector_info[det_name] = {
            "enabled": True,
            "available": False,
            "runtime_ms": 0,
            "cache_hit": False,
            "libraries_detected": 0,
            "repository_hash": "",
            "reference_database_hash": "",
            "failure_reason": ""
        }
        
        det_instance = _get_detector(classpath)
        if not det_instance:
            detector_info[det_name]["failure_reason"] = "Failed to instantiate"
            continue
            
        try:
            t0 = time.time()
            results = det_instance.detect(context)
            rt = int((time.time() - t0) * 1000)
            libraries.extend(results)
            
            # Check if detector provided its own rich metadata
            meta = getattr(det_instance, "last_metadata", {})
            if meta:
                detector_info[det_name].update({
                    "available": meta.get("available", False),
                    "runtime_ms": meta.get("runtime_ms", rt),
                    "cache_hit": meta.get("cache_hit", False),
                    "libraries_detected": meta.get("libraries_detected", len(results)),
                    "repository_hash": meta.get("repository_hash", ""),
                    "reference_database_hash": meta.get("reference_database_hash", ""),
                    "failure_reason": meta.get("failure_reason", "")
                })
                # Capture optional Python/Environment metadata if provided
                for k in ["python_version", "execution_environment", "jar_count", "dex_count"]:
                    if k in meta:
                        detector_info[det_name][k] = meta[k]
            else:
                # Basic metadata for detectors that don't emit last_metadata
                detector_info[det_name].update({
                    "available": True,
                    "runtime_ms": rt,
                    "libraries_detected": len(results)
                })
        except Exception as exc:
            logger.error("build_inventory: %s failed during detect: %s", classpath, exc)
            detector_info[det_name]["failure_reason"] = str(exc)

    logger.info(
        "build_inventory [%s]: Detected %d raw libraries across all detectors",
        run_id, len(libraries),
    )

    # ── Step 2: Canonicalize ──────────────────────────────────────────────────
    libraries, raw_evidence = _canonicalize(libraries, canon)
    logger.debug("build_inventory [%s]: %d SDKs after canonicalization", run_id, len(libraries))

    # ── Step 3: Build SDKRecord list ──────────────────────────────────────────
    records = [
        _to_sdk_record(lib)
        for lib in libraries
    ]

    # ── Step 4: Classify (Phase 4 = TrackerEnricher) ──────────────────────────
    from sdk_detection.tracker_enricher import TrackerEnricher
    enricher = TrackerEnricher.get_instance()
    enricher.enrich(records)
    exodus_available = enricher.is_available

    # ── Step 5: Enrich with metadata ──────────────────────────────────────────
    loader.enrich_all(records)

    logger.info(
        "build_inventory [%s]: inventory complete — %d SDKs (exodus=%s)",
        run_id, len(records), exodus_available,
    )

    return SDKInventory(
        records=records,
        raw_evidence=raw_evidence,
        context=context,
        detector_info=detector_info,
        exodus_available=exodus_available,
    )
