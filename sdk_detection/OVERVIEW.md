# SDK Detection Engine

This module implements a hybrid, multi-stage architecture for third-party SDK and privacy tracker identification within compiled Android packages. It operates as the authoritative SDK pipeline for the Geo-Difference Mobile Security analyzer, identifying libraries via Smali bytecode structures and AndroidManifest.xml components, resolving them to canonical identities, and enriching them with privacy tracker metadata.

---

## 1. Architectural Overview

The detection engine implements a composable pipeline orchestrated by the `build_inventory()` method. It follows a strict four-stage process:

1.  **Multi-Detector Extraction**: Pluggable detectors execute against a shared `DetectionContext`.
2.  **Canonicalization**: Raw findings are mapped to unified identity namespaces.
3.  **Tracker Enrichment**: Detected libraries are cross-referenced with the Exodus Privacy database.
4.  **Metadata Merging**: Final descriptive fields (vendor, category) are injected into the output `SDKInventory`.

```text
┌───────────────────────────┐
│       Compiled APK        │ (AndroidManifest.xml + smali/ + classes.jar)
└─────────────┬─────────────┘
              │
      ┌───────▼───────┐
      │   Detectors   │
      │  (LibScan)    │ ──► Bytecode Signature Matching
      │  (Fallback)   │ ──► Longest-Prefix String Matching
      └───────┬───────┘
              │
      ┌───────▼───────┐
      │ Canonicalizer │ ──► Resolves raw names to Canonical IDs
      └───────┬───────┘
              │
    ┌─────────▼─────────┐
    │ Tracker Enricher  │ ──► deterministic longest-prefix Exodus match
    └─────────┬─────────┘
              │
      ┌───────▼───────┐
      │   Metadata    │ ──► Vendor, country code, categories
      └───────┬───────┘
              │
     SDKInventory (Frozen)
```

---

## 2. Detection Strategies

### 2.1 Primary Bytecode Analysis (`LibScanRunner`)
The primary detection capability is provided by `LibScanRunner`, an isolated wrapper for the LibScan framework. 
LibScan performs fuzzy graph-based matching of compiled methods against a curated reference database of compiled Android libraries (`.jar` and `.dex`).

**Algorithmic Isolation:**
To prevent the IPC buffer exhaustion (MemoryError) inherent in the original LibScan implementation when processing large reference databases (e.g., 400+ libraries), `LibScanRunner` executes in a persistent chunked-execution mode. It automatically chunks the `ground_truth_libs_dex` database into segments, executes isolated detection passes, and deterministically merges the similarities. Execution occurs in `embedded` mode for runtime efficiency, relying on an LRU memory cache for preloaded `ThirdLib` structures.

### 2.2 Heuristic String Matching (`FallbackDetector`)
The `FallbackDetector` provides robust secondary detection for SDKs not present in the LibScan reference graph. It utilizes a deterministic longest-prefix matching algorithm operating on two extraction surfaces:

*   **Manifest Surface**: Exact matching of `activity`, `service`, `receiver`, and `provider` class names, as well as `uses-library` and `meta-data` values.
*   **Smali Namespace Surface**: Iterative depth-bounded extraction of the decompiled filesystem (`smali*/...`). It maps relative directory paths (e.g., `com/google/android/gms`) into dotted packages and evaluates them against the canonical `sdk_metadata.csv` catalog.

Because package namespaces can overlap, the engine guarantees correctness by sorting rules in descending length order, ensuring the most specific namespace (e.g., `com.google.android.gms.maps`) intercepts the match before a generic parent namespace (`com.google.android.gms`).

---

## 3. Data Normalization and Enrichment

### 3.1 Canonicalization
Detectors often yield disjoint string representations for the same underlying library (e.g., `"Facebook Ads Internal"`, `"com.facebook.ads"`, `"Facebook Audience Network"`). The `Canonicalizer` resolves all raw detection artifacts to a single unified string using `sdk_metadata.csv`. Identical canonical matches detected by multiple engines are merged into a single `SDKRecord`, aggregating their evidence counts and provenance flags (`detected_manifest`, `detected_smali`).

### 3.2 Exodus Privacy Tracker Enrichment
To distinguish benign functionality from invasive tracking, the `TrackerEnricher` component implements a deterministic integration with the Exodus Privacy tracker dataset. 

Using the `exodus_trackers.csv` knowledge base (generated via flattening complex RE2 regexes into exact package prefixes), the Enricher evaluates every canonicalized `SDKRecord`. If a longest-prefix match is found, the SDK is irreversibly flagged via the `is_tracker=True` attribute, and its `tracker_categories` and `network_signature` (IoCs) are appended.

---

## 4. Output Schema: `SDKInventory`

The pipeline terminates by producing an immutable `SDKInventory` object containing a list of `SDKRecord` instances. This inventory guarantees the following invariants for downstream architectural consumption:

1.  **Deduplication**: No two `SDKRecord` objects share the same canonical `sdk_name`.
2.  **Evidence Integrity**: Every record strictly preserves the exact string (`evidence_value`) and mechanism (`evidence_type`) responsible for its detection.
3.  **Traceability**: Every record carries the `detection_source` (e.g., `libscan`, `fallback`, or `both`), ensuring manual auditability of the analyzer's heuristic logic.

The complete database design and schema specification for the resulting CSV artifact is documented in `manifest_scanner/dataset_details/SDK_Dataset_Overview.md`.
