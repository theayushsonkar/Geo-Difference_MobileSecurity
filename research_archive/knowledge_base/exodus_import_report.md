# Exodus Privacy Dataset Import Report

**Dataset Source:** `reports.exodus-privacy.eu.org/api/trackers`
**Total Trackers Evaluated:** 432
**Total Clean Prefixes Extracted:** 588

## Methodology
The importer flattens the complex JSON structure by splitting the `code_signature` regular expression on the pipe `|` character. Escaped periods (`\.`) are normalized to standard periods, and trailing dots or anchors (`^`, `$`) are stripped. The result is a deterministic list of exact Java package prefixes.

## Statistics
* Trackers with multiple prefixes: 101
* Duplicate internal permutations removed: 0
* Trackers skipped due to missing signatures: 4
* Trackers skipped due to complex regex: 0

## Unsupported Patterns
The following 0 trackers used unsupported complex regex operators (`()`, `[]`, `*`, `+`, `?`) and were safely skipped to ensure strict deterministic longest-prefix matching at runtime:


## Final Schema
The output is written to `knowledge_base/metadata/exodus_trackers.csv` with the following columns:
1. `tracker_name`
2. `package_prefix`
3. `categories` (pipe-separated)
4. `network_signature`
5. `website`
6. `source`
7. `code_signature` (for provenance)
