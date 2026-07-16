# Repository Structure Guide

Welcome to the Geo-Difference Mobile Security project. This repository is strictly organized to separate production analysis pipelines from validation tools, setup utilities, and research history. 

This structure ensures the project remains a clean, maintainable, and mature open-source research framework.

---

## 1. Production Pipeline (Root)
The core modules and execution engines live at the repository root to ensure import paths remain clean, stable, and Pythonic.

- **`cve/`, `manifest_scanner/`, `pcap/`, `sdk_detection/`, `pipeline/`**: The core static, dynamic, and data ingestion analysis engines.
- **`knowledge_base/`**: Synthesized datasets and Aho-Corasick matching pipelines. Left fully intact as a unified subsystem.
- **`run_full_pipeline.py` & CLI Wrappers**: The primary end-user orchestrators (`scrapper.py`, `collect_pcap.py`, `scan_manifest.py`, etc.).
- **`data/` & `third_party/`**: Reference databases (NVD, GeoIP) and required external dependencies (LibScan).
- **`sample_index.csv`**: The master state tracking file for pipeline executions.

## 2. Validation & Quality Assurance
All scripts used to test, profile, and validate the logic of the production engines.

- **`tests/`**: Standard Pytest regression and unit test suite (located at root).
- **`tools/validation/`**: Robust audit scripts, performance benchmarks, and matcher accuracy comparisons (`audit_*.py`, `validate_*.py`, `benchmark_*.py`, `bench_*.py`, `compare_*.py`). Keeping all non-production verification in one place makes navigation simpler.

## 3. Operations & Setup
Scripts useful for setting up the environment.

- **`tools/setup/` & `tools/utilities/`**: Bootstrapping scripts for dependencies and one-off debugging wrappers.

## 4. Research Archive
An immutable history of the project's development. **Do not execute scripts against this directory.**

- **`research_archive/historical_reports/`**: Markdown write-ups of past experiments.
- **`research_archive/benchmark_results/`**: Frozen outputs, logs, and dummy APKs used during original performance testing.
- **`research_archive/legacy/`**: Obsolete wrappers and test files safely preserved for context.
- **`research_archive/cleanup_history/`**: Scattered execution logs and outputs from early development.

## 5. Generated Runtime Outputs
Pipelines execution state.

- **`apks/`, `decoded/`, `normalized/`, `output/`, `logs/`**: Keep these folders. Replace contents with a `.gitkeep` (or equivalent placeholder) when releasing a clean repository. This makes it obvious how to maintain the directory structure in Git without committing dynamic outputs.

---

## 6. Repository Organization Rules

1. Production modules stay at the repository root.
2. Production code must never import from `docs/`, `tools/`, or `research_archive/`.
3. Validation, benchmarking, and audit scripts belong under `tools/validation/`.
4. Historical reports and generated benchmark outputs belong under `research_archive/`.
5. Temporary outputs (`output_test/`, `__pycache__`, `scratch/`) must never be committed.
6. New documentation belongs in `docs/` unless it is the main `README.md`.

This prevents future clutter and ensures long-term reproducibility.
