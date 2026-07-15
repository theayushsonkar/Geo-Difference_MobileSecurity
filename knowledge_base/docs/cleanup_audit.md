# Knowledge Base & Static Analyzer Production Cleanup Audit

This document serves as an engineering audit report detailing the systematic verification and cleanup of the `knowledge_base` module and `manifest_scanner`. It separates verified facts (production execution, actual deletions) from future architectural proposals.

## 1. Production Runtime
*(Components experimentally verified as strictly required during active APK analysis)*

*   `manifest_scanner/` (Core extractor, models, output, runner, sample index)
*   `sdk_detection/` (LibScan runner, canonicalizer, fallback detector, metadata loader)
*   `cve/` (Vulnerability matching pipeline)
*   `knowledge_base/pipeline/matcher_factory.py` (Singleton Factory Orchestrator)
*   `knowledge_base/pipeline/base_matcher.py` (Interface)
*   `knowledge_base/pipeline/cache_manager.py` (Instance caching for matchers)
*   `knowledge_base/pipeline/aho_matcher.py` (Aho-Corasick Privacy API Scanner)
*   `knowledge_base/pipeline/secret_matcher.py` (TruffleHog Regex Matching)
*   `knowledge_base/pipeline/geo_matcher.py` (FlowDroid Geo-logic Matching)
*   `knowledge_base/pipeline/knowledge_enrichment.py` (API Heuristics, verified as executed by `aho_matcher.py` during initialization)
*   `knowledge_base/pipeline/geo_rule_loader.py` (Smali Rule Loading for geo matcher)
*   `knowledge_base/schemas/` (Finding Schema, Geo Schema, Privacy Schema, Secret Schema)
*   `knowledge_base/metadata/` (Canonical CSV Databases consumed by matchers)
*   `pipeline/` (APK Downloading, Decoding, and Indexing Orchestration)

## 2. Dataset Build Pipeline
*(Components required for offline dataset generation, importers, and metadata building)*

*   `knowledge_base/importers/` (Axplorer, PScout, GMS)
*   `knowledge_base/pipeline/importers/` (FlowDroid, TruffleHog)
*   `knowledge_base/pipeline/merge_database.py` (Verified offline consolidation script)
*   `knowledge_base/dataset_manager.py` (Offline DB Management)
*   `knowledge_base/logger.py` & `knowledge_base/config.py`
*   `knowledge_base/utils/csv_utils.py`

## 3. Validation & QA
*(Validation scripts, benchmarks, and dataset verification tools)*

*   `knowledge_base/pipeline/benchmark_matchers.py`
*   `knowledge_base/pipeline/validate_database.py`
*   `knowledge_base/pipeline/validate_enrichment.py`
*   `knowledge_base/pipeline/validate_geo_logic.py`
*   `knowledge_base/pipeline/validate_matchers.py`
*   `knowledge_base/pipeline/validate_trufflehog.py`
*   `knowledge_base/validate_gms.py`
*   `knowledge_base/validate_pscout.py`

## 4. Removed Components
*(Files experimentally verified as dead code and successfully removed)*

The following files were removed after repository-wide searches confirmed zero active production or build pipeline callers:
*   `knowledge_base/pipeline/regex_generator.py` (Superseded by `aho_matcher.py`)
*   `knowledge_base/pipeline/validate_regex_generator.py` (Validator for dead code)
*   `knowledge_base/pipeline/build_database.py` (Unused empty stub)
*   `knowledge_base/pipeline/generate_regex.py` (Unused empty stub)
*   `knowledge_base/pipeline/merge_databases.py` (Duplicate empty stub)

## 5. Components Investigated and Intentionally Retained
*(Components considered for cleanup but retained based on verified dependencies)*

*   `knowledge_base/pipeline/knowledge_enrichment.py`: Initially suspected to be an offline dataset builder, but repository execution tracing proved it is actively invoked by `aho_matcher.py` at runtime to populate the Aho-Corasick automaton.
*   `manifest_scanner/extractor.py::_scan_secrets()`: Investigated for potential removal/refactor, but retained as it actively bridges the `ManifestFeatureExtractor` with the `MatcherFactory`.
*   `sdk_detection/fallback_detector.py::_detect_sdks_legacy()`: Kept because experimental evidence showed it is still required to detect SDKs not covered by the LibScan engine.

## 6. Future Refactoring Opportunities
*(Architectural proposals and cleanup candidates pending experimental verification)*

### Structural Proposals
*   **Isolate Matchers (Runtime):** Rename `knowledge_base/pipeline/` to `knowledge_base/matchers/` to contain only production logic (`matcher_factory.py`, `aho_matcher.py`, etc.).
*   **Isolate Validation:** Move all `validate_*.py` and `benchmark_*.py` into a new `knowledge_base/validation/` folder.
*   **Consolidate Importers:** Move `knowledge_base/pipeline/importers/*` into `knowledge_base/importers/` for domain cohesion.
*   **Archive Research Data:** Move `knowledge_base/processed/` to a project-root `research_archive/` folder.

### Requires Verification (Potential Dead Code)
The following files are suspected to be dead code but **must be experimentally verified** before removal:
*   `knowledge_base/schemas/category_schema.py`
*   `knowledge_base/utils/normalization.py`
*   `knowledge_base/provenance.py`
*   `scratch/` directory contents (`audit.py`, `inventory.py`)

## 7. Validated Production Dependency Chain
*(The CURRENT verifiable production execution flow)*

1. **Raw Sources** (External Repositories)
2. **Importers** (`knowledge_base/importers/`)
3. **Canonical Metadata** (`knowledge_base/metadata/` CSVs)
4. **Knowledge Enrichment** (`knowledge_base/pipeline/knowledge_enrichment.py` dynamically loaded at runtime)
5. **Matchers** (`aho_matcher.py`, `secret_matcher.py`, `geo_matcher.py` orchestrated by `matcher_factory.py`)
6. **ManifestFeatureExtractor** (`manifest_scanner/extractor.py`)
7. **CSV Output** (`manifest_scanner/output.py`)

## 8. Verification Summary
*(Evidence of system stability post-cleanup)*

*   **Manifest Scanner Baseline:** Executed `python scan_manifest.py -i scratch/sample_index.csv -o output_test`.
*   **Knowledge Base Validation:** `python -m knowledge_base.pipeline.validate_matchers` passed with 1266 privacy nodes, 931 secret patterns, and 24 geo rules.
*   **Benchmark Execution:** `python -m knowledge_base.pipeline.benchmark_matchers` confirmed zero performance degradation across 1000 iterations.
*   **Output Comparisons:** A rigorous dataframe diff against `output/baseline/` confirmed 100% data integrity for all 6 core datasets (ignoring dynamic `run_id` and `scan_timestamp` fields).

## 9. Cleanup Metrics

*   **Files Removed:** 5
*   **Commits Created:** 1 (`11c390b: Remove obsolete Knowledge Base pipeline stubs`)
*   **Approximate Lines Removed:** ~200 LOC
*   **Regressions Found:** 0
*   **Regressions Prevented:** 1 (Retained `knowledge_enrichment.py` preventing runtime crash in `aho_matcher.py`)
