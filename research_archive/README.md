# Research & Validation Archive

This directory serves as the immutable **historical paper trail** for the Geo-Difference Mobile Security project. It houses all generation logs, benchmarking results, validation reports, and statistical summaries produced during the curation and execution of the static analysis knowledge base.

To uphold strict academic rigor and reproducibility, the outputs of the data engineering pipeline — specifically those involving dataset ingestion, cross-referencing, and algorithmic optimization — are frozen here rather than silently overwritten.

---

## 1. Architectural Purpose

While the `knowledge_base/` and `data/` directories serve as live, runtime dependencies for the pipeline, the `research_archive/` is an offline auditing mechanism. It proves *how* the runtime data was synthesized and validates the integrity of the underlying algorithms.

```text
research_archive/
└── knowledge_base/
    ├── Algorithm Benchmarks    (e.g., aho_benchmark_report.md)
    ├── Dataset Synthesis       (e.g., axplorer_pscout_overlap.csv)
    ├── Pipeline Validation     (e.g., system_validation_report.md)
    └── Statistical Summaries   (e.g., tracker_enricher_report.md)
```

---

## 2. Core Archive Components

The artifacts within this archive are categorized into four critical domains of the research methodology:

### 2.1 Dataset Integration & Synthesis
The project relies on merging multiple disjoint cybersecurity datasets. These reports validate how external intelligence was deduplicated and unified:
- **`axplorer_pscout_overlap.csv` & Reports:** Documents the specific overlaps and disparities between the Axplorer and PScout Android API permission mappings.
- **`exodus_import_report.md`:** Validates the ingestion of the Exodus Privacy tracker dataset.
- **`trufflehog_import_report.md`:** Details the normalization of TruffleHog regular expressions into the static analysis engine.
- **`gms_validation_report.md`:** Records the manual and automated validation of Google Mobile Services (GMS) module mappings.

### 2.2 Algorithmic Benchmarking
To analyze thousands of APKs at scale, the pipeline utilizes optimized text-search algorithms. 
- **`aho_benchmark_report.md`:** Proves the efficacy of migrating from standard regex to the Aho-Corasick automaton for bulk API and tracker matching, detailing exact speedup multipliers and memory consumption constraints.

### 2.3 System Pipeline Validation
These reports provide end-to-end assurance that the scanner components function as intended against edge cases:
- **`system_validation_report.md` & `scanner_integration_report.md`:** High-level audit logs confirming that the manifest scanner, SDK detector, and secret matcher integrate properly without data loss.
- **`tracker_enricher_report.md` & `sdk_pipeline_final_report.md`:** Verifies the longest-suffix domain matching logic used to map network traffic to parent tracker organizations.

### 2.4 Statistical Artifacts
CSV summaries that freeze the numerical state of the knowledge base at the time of publication:
- **`trufflehog_statistics.csv` / `secret_loader_statistics.csv`:** Quantitative breakdown of secret signatures by provider and category.
- **`permission_group_statistics.csv`:** The distribution of dangerous vs. normal permissions analyzed.
- **`category_statistics.csv`:** Distribution of trackers across functional categories (Analytics, Advertising, Crash Reporting, etc.).

---

## 3. Academic Reproducibility

For peer review and future research extension:
1. **No runtime dependencies:** No active python scripts read from this directory. You may delete it without breaking the pipeline.
2. **Deterministic output:** If a researcher re-runs the importer scripts (e.g., rebuilding the `knowledge_base` from scratch), the resulting validation reports generated will cryptographically and statistically match the frozen versions in this archive.
3. **Transparency:** Artifacts like `unknown_permissions.csv` and `axplorer_only.csv` explicitly document the blind spots and limitations of the datasets used, preventing confirmation bias in the final paper.
