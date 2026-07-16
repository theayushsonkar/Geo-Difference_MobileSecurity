# Contributing to Geo-Difference Mobile Security

Thank you for your interest in contributing to the Geo-Difference Mobile Security project! 

To maintain the architectural integrity and research reproducibility of this repository, please adhere to the following directory layout and guidelines when submitting pull requests or making modifications.

## Repository Layout Overview

To help you understand the architecture immediately, the repository is strictly divided into the following categories:

**Production code:**
- `cve/`
- `manifest_scanner/`
- `sdk_detection/`
- `pcap/`
- `pipeline/`
- `knowledge_base/`

**Developer tools:**
- `tools/`

**Historical artifacts:**
- `research_archive/`

**Documentation:**
- `docs/`

### Contribution Guidelines

1. **Production Isolation:** Core logic must remain at the repository root. Do not introduce dependencies from production code into `tools/`, `docs/`, or `research_archive/`.
2. **Tooling & Setup:** If you write a new benchmark, validation script, or developer utility, place it in the appropriate subdirectory under `tools/`. **Do not place new scripts in the root directory.**
3. **Historical Data:** Do not commit generated CSVs, dummy APKs, PCAP traces, or performance logs to the root directory. Save them appropriately in the `research_archive/`.
4. **Testing:** Please ensure all modifications pass the existing `pytest` suite located in the `tests/` directory.

We look forward to your contributions to improving cross-jurisdictional mobile security!
