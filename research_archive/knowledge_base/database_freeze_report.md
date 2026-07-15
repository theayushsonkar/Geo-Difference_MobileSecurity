# Database Merger Freeze Report

## Project Overview
The Database Merger consolidates strictly parsed datasets (Axplorer, PScout, and Google Play Services) into a single, highly canonical, and deterministic Privacy-Sensitive API Knowledge Base (`privacy_apis.csv`). This milestone confirms that the merging pipeline is deterministic, lossless, and ready to act as the strict foundational schema for the subsequent Privacy Classifier layer.

## Input Datasets
1. **Axplorer** (`axplorer_import.csv`): Provides highly granular Android internal frameworks and hidden APIs mapped chronologically across API versions.
2. **PScout** (`pscout_import.csv`): Contributes semantic call-graph analyses, mapping deep Java/Kotlin object invocations and `ContentProvider` operations.
3. **Google Play Services** (`gms_import.csv`): An offline mapping of official Google Maven `.aar` bytecode extracting deterministic endpoints (e.g., `FusedLocationProviderClient`, `AdvertisingIdClient`).

## Merge Strategy
The merger uses a strict 5-part composite key constraint to align the APIs:
`[framework, package_name, class_name, method_name, api_type]`

- **Array Merging**: All chronological versions (`source_versions`, `supported_android_versions`), permission requirements, and provenance sources are deduplicated using disjoint Set Unions, then strictly sorted.
- **Timestamp Provenance**: Original import timestamps are preserved exactly as ingested to ensure zero non-determinism during subsequent re-compilations.
- **Confidence Computation**: Dynamically assigned based solely on the length of the provenance `sources` array (1 = Medium, 2 = High, 3 = Very High).

## Conflict Resolution Strategy
The merger NEVER guesses or infers semantic metadata.
- If two datasets provide `Unknown` categories, the result remains `Unknown`.
- If one dataset asserts a semantic category (`Known`) and the other is `Unknown`, the `Known` label is preserved.
- If a hard conflict occurs (e.g., Dataset A asserts `Location`, Dataset B asserts `Identity`), the pre-existing label is locked in and a `WARNING` is safely propagated into the standard logger for future triage by the downstream classifier.

## Validation Summary
The pipeline successfully navigated stringent data integrity checks:
- **Total Canonical Records Processed**: 9,336
- **Determinism Check**: SUCCESS (SHA-256 Hashes identically match across arbitrary multi-runs).
- **Duplicate Permissions/Versions**: 0 (Fully Deduped).
- **Invalid Chronological Bounds (Min > Max)**: 0.
- **Missing Required Identifiers**: 0.

## Performance Summary
- **Execution Time**: ~0.80 seconds per run on standard infrastructure.
- **Memory Footprint**: Strict $O(n)$ iteration ensures peak memory remains completely nominal (< 5 MB peak variance).
- **Complexity**: The deterministic tracking index correctly isolated and coalesced 268 overlapping composite structures down to unique elements with lossless provenance preservation.

## Known Limitations
- The overlap between Axplorer and PScout remains relatively small (only 3 perfectly overlapping composite boundaries). This underlines the project's strategy to merge disjoint datasets to maximize breadth rather than overlap.

## Freeze Statement
**The Database Merger is officially FROZEN.** 
No further structural or semantic adjustments shall be applied to the canonical ingestion layer. From this point forward, `knowledge_base/processed/privacy_apis.csv` is the SINGLE, IMMUTABLE SOURCE OF TRUTH for all downstream classification and signature compilation milestones.
