# PCAP Analysis Engine: Engineering Architecture Specification

This document serves as the **SINGLE SOURCE OF TRUTH** for the PCAP Analysis Engine redesign. It provides a production-grade engineering specification that governs all implementation decisions.

The system is a **GENERAL PURPOSE**, **FACTS-ONLY** network analysis pipeline. It strictly enriches deterministic network observations (e.g., DNS queries, TLS SNI) with offline contextual datasets without mutating the underlying packet extraction logic, and strictly avoiding subjective security or privacy risk scoring.

---

## 1. Core Architectural Separation

The system is strictly divided into two permanently independent subsystems to guarantee extraction integrity and prevent circular dependencies.

### Subsystem 1: Packet Processing
* **Purpose:** Translates raw bytes into structural network events.
* **Responsibilities:**
  * Reading PCAP buffers.
  * Protocol parsing via `dpkt` (IPv4, TCP, UDP, DNS, TLS, HTTP, QUIC).
  * Tolerating protocol fragmentation (e.g., GREASE TLS extensions).
  * Packet normalization and `RawEvent` generation.
* **Isolation Rule:** This subsystem must **NEVER** know that trackers, cloud providers, GeoIP, PII, or DNS Knowledge Bases exist. It does not perform domain suffix matching or IP lookups.

### Subsystem 2: Network Enrichment
* **Purpose:** Translates structural network events into enriched, semantic fact tables.
* **Responsibilities:**
  * Consuming streams of `RawEvent` objects.
  * Triggering Knowledge Base lookups via `NetworkContext`.
  * Aggregating packets into semantic 6-tuple `ConnectionRecord` objects.
  * Computing application-level metrics via `AppSummaryBuilder`.
* **Isolation Rule:** This subsystem never touches raw bytes or `dpkt` structures.

**WHY:** Decoupling parsing from enrichment ensures that a crash in a PII regex or a missing Tracker CSV never breaks the foundational ability to decode TLS handshakes. It allows the packet parser to be heavily optimized independently from the dataset schemas.

---

## 2. Canonical Domain Models

To eliminate ambiguity, all data passing between components must use explicit, strictly-typed canonical domain models (e.g., Python `dataclasses` with `frozen=True`). Dictionaries are forbidden for domain modeling.

### 2.1 Fact Models (`TrackerFact`, `CloudFact`, `GeoFact`, `DNSFact`, `PIIFact`)
* **Purpose:** Represents a guaranteed, atomic truth extracted from a Knowledge Base.
* **Fields:** Dataset-specific schema fields (e.g., `TrackerFact` contains `canonical_vendor`, `category`).
* **Ownership:** Instantiated by `NetworkContext` matchers.
* **Lifecycle:** Created per successful match, appended to a `ConnectionRecord`, garbage collected when the record is dumped to CSV.
* **Producer:** `TrackerMatcher`, `CloudMatcher`, `GeoMapper`, etc.
* **Consumer:** `ConnectionBuilder`.
* **Immutability:** Strictly immutable (`frozen=True`).

### 2.2 `RawEvent`
* **Purpose:** Atomic representation of a single network packet's semantic payload.
* **Fields:** Timestamp, 6-tuple identity, L4 payload size, protocol flags, extracted strings (SNI, HTTP Host, DNS Query).
* **Producer:** `pcap_parser.py`.
* **Consumer:** `ConnectionBuilder`.
* **Immutability:** Strictly immutable.

### 2.3 `ConnectionRecord`
* **Purpose:** Aggregation of a network flow enriched with all known facts.
* **Fields:** 6-tuple, byte/packet volumes, timing, and optional attached Fact Models.
* **Producer:** `ConnectionBuilder`.
* **Consumer:** `AppSummaryBuilder` and CSV Writers.
* **Immutability:** Mutated during the bucket-collapse phase inside `ConnectionBuilder`, then frozen before being passed to consumers.

### 2.4 `AppSummary`
* **Purpose:** Application-level metric aggregation supporting geo-difference analysis.
* **Fields:** Nested distribution metrics (e.g., vendor distributions, cloud distributions).
* **Producer:** `AppSummaryBuilder`.
* **Consumer:** CSV Writer.
* **Immutability:** Strictly immutable upon generation.

---

## 3. Repository-Wide DatasetManager

`DatasetManager` is not a PCAP component; it is a repository-wide core service located at `knowledge_base/dataset_manager.py`.

* **WHY:** Managing CSV validation, file I/O, and provenance hashing is identical whether analyzing a Dalvik `.dex` file or a `.pcap` file.
* **WHAT IT DOES:** Manages Manifest datasets, Static DEX datasets, Network datasets, and all future datasets.
* **HOW IT WORKS:** Exposes a unified API (e.g., `load_dataset("network.trackers")`). It reads `metadata.json`, verifies the file hash, uses `kb_schemas.py` to parse the CSV, and returns a frozen list of validated domain models.
* **LIFECYCLE:** Instantiated as a singleton by the pipeline master orchestrator. Lives for the duration of the pipeline execution.

---

## 4. Knowledge Base Registration Workflow

Adding a new Knowledge Base requires a strict, multi-step engineering workflow. No dataset can bypass this sequence.

1. **Dataset Import:** Maintainer adds `NewImporter` to `knowledge_base/network/importers/` to parse raw source data into `NormalizedModel`.
2. **Offline Builder:** Maintainer writes `NewBuilder` to ingest the model, resolve conflicts deterministically, and output a structured CSV.
3. **Builder Statistics Generation:** The builder outputs metadata (e.g., `rows_processed`, `duplicates_removed`, `conflicts_resolved`) to a local `.json` file alongside the CSV.
4. **DatasetManager Registration:** Maintainer updates `kb_schemas.py` and `metadata.json` so `DatasetManager` recognizes the new CSV and its hash.
5. **Matcher Implementation:** Engineer writes `NewMatcher` inheriting from `SuffixMatcher` (or standard Dict base).
6. **NetworkContext Registration:** `NetworkContext` is updated to instantiate `NewMatcher` upon initialization.
7. **ConnectionBuilder Integration:** `ConnectionBuilder` calls `context.new_matcher.match()` during bucket collapse.
8. **AppSummary Integration (Optional):** `AppSummaryBuilder` creates new distributions based on the new facts.

---

## 5. Output Schema Versioning

While input datasets use provenance hashing, the output artifacts (`pcap_connections.csv`, `pcap_app_summary.csv`) utilize an explicit `OUTPUT_SCHEMA_VERSION`.

* **WHY:** Downstream Pandas/Jupyter notebooks used by researchers will crash if columns are renamed, removed, or fundamentally change semantic meaning.
* **HOW:** `constants.py` exports `OUTPUT_SCHEMA_VERSION = "2.0.0"`. 
* **MANAGEMENT:** Adding a column increments the minor version (`2.1.0`). Removing/renaming a column increments the major version (`3.0.0`).
* **DISCOVERY:** The version is stamped into `pcap_trace.json`. Downstream tooling reads the trace file first to load the correct Pandas dataframes.

---

## 6. Builder Statistics & Provenance

Every offline Builder must generate structural metadata during execution.

* **WHY:** Pipeline maintainers need visibility into dataset health. If Exodus updates their format and drops 90% of their rows, the Builder must flag this before it poisons the `processed/` directory.
* **WHAT:**
  * `total_raw_rows_ingested`
  * `duplicates_removed`
  * `conflicts_resolved` (e.g., Tracker X was both Ad and Analytics, resolved to Ad)
  * `invalid_rows_dropped`
  * `generation_duration_ms`
* **WHERE:** Written to `knowledge_base/network/processed/.stats_tracker.json`.
* **PROVENANCE:** The final processed CSV must have its `SHA256` hash, upstream version, generation timestamp, and license written to `metadata.json`.

---

## 7. Dependency Graph & Isolation Rules

To prevent spaghetti code, module dependencies are strictly enforced.

### Allowed Dependencies:
* `AppSummaryBuilder` → Depends on `ConnectionRecord`.
* `ConnectionBuilder` → Depends on `RawEvent`, `NetworkContext`.
* `NetworkContext` → Depends on Matchers (`TrackerMatcher`, etc.).
* Matchers → Depend on `DatasetManager` (for initialization data).

### Forbidden Dependencies:
* **Parser Isolation:** `pcap_parser.py` MUST NEVER import `NetworkContext`, Matchers, `DatasetManager`, or schemas.
* **Builder Isolation:** `ConnectionBuilder` MUST NEVER import `dpkt` or any packet parsing logic.
* **Offline Isolation:** Pipeline runtime code MUST NEVER import `builders/` or `importers/`.

---

## 8. Concurrency Model & Memory Ownership

The PCAP pipeline is designed for massive parallelization (e.g., processing 1,000 PCAPs across 32 cores).

* **Immutability:** `TrackerFact`, `RawEvent`, and `AppSummary` are strictly immutable.
* **NetworkContext:** The `NetworkContext` and all enclosed matchers are strictly **READ-ONLY** and **THREAD-SAFE** after initialization.
* **DatasetManager:** Used primarily during pipeline boot sequence. Can be safely accessed by multiple workers as it yields distinct immutable copies (or shares frozen references).
* **Caches:** LRU Caches on matcher lookups (`@functools.lru_cache`) are thread-safe in Python. They are bound by `maxsize` to prevent unbounded memory leaks across massive execution runs.
* **Ownership:** A worker thread creating a `ConnectionBuilder` owns the mutated `ConnectionRecord` objects until they are flushed to disk.

---

## 9. Error Handling Specification

Failures are handled explicitly based on subsystem location.

### Initialization Failures (Fatal)
* **Modes:** Missing dataset CSV, corrupted CSV, `kb_schema` validation failure, `SHA256` hash mismatch.
* **Recovery:** None. `DatasetManager` raises `FatalKnowledgeBaseError`. Execution halts immediately to prevent corrupt output generation.

### Parsing Failures (Non-Fatal)
* **Modes:** Malformed PCAP, truncated TCP payload, `dpkt` parsing exception.
* **Recovery:** `pcap_parser.py` logs the error, drops the corrupted specific packet, and continues parsing the remaining buffer. Raises no exceptions to the caller.

### Enrichment Failures (Non-Fatal)
* **Modes:** Regex compilation failure (prevented during boot), Unknown ASN format.
* **Recovery:** `NetworkContext` matchers catch internal errors, log a warning, and return `None` (representing an unenriched state). `ConnectionBuilder` continues execution.

---

## 10. Performance Specification

Every implementation must satisfy these rigid engineering targets to ensure the pipeline scales to 100,000+ APK datasets.

* **Initialization Time:** `DatasetManager` must validate and load all datasets into `NetworkContext` in **< 2.0 seconds**.
* **Memory Footprint:** The combined in-memory size of all Matchers (Tries, Dicts, Regexes) must not exceed **250 MB**.
* **Lookup Latency:** Suffix matching and MMDB lookups must resolve in **< 1.0 ms** per domain/IP.
* **Regex Throughput:** The master PII regex must scan a standard 1KB HTTP payload in **< 0.5 ms**.
* **WHY:** High latencies inside the packet iteration loop (millions of packets per run) will permanently bottleneck the pipeline.

---

## 11. Testing Specification

Testing is mandated across four independent levels.

### 1. Dataset Validation
* **Inputs:** Raw synthetic JSON/CSV files with known conflicts and edge cases.
* **Criteria:** Builders must output the exact, bit-for-bit expected CSV, properly resolving conflicts.

### 2. Knowledge Base Validation
* **Inputs:** Mock `processed/` CSVs injected into Matchers.
* **Criteria:** `TrackerMatcher` must accurately resolve subdomains (`ads.vungle.com` -> `vungle.com`). PII regexes must trigger on standard formats and reject slight malformations.

### 3. Pipeline Validation
* **Inputs:** A static, gold-standard `.pcap` file containing exactly 1 DNS query, 1 TLS handshake to a known tracker, and 1 HTTP request with PII.
* **Criteria:** The output `pcap_connections.csv` must exactly match a committed expected schema.

### 4. Regression Benchmarking
* **Inputs:** 1GB production PCAP file.
* **Criteria:** Must pass the Performance Specifications (Section 10). Memory leaks are monitored via `tracemalloc`.

---

## 12. Future Extension Rules

Rules for future maintainers expanding the architecture.

* **Adding a New Knowledge Base:** 
  * MUST implement `importer`, `builder`, schema, and `matcher`.
  * MUST NOT alter `pcap_parser.py`.
  * MUST register with `NetworkContext` and `DatasetManager`.
* **Adding a New Protocol (e.g., FTP):**
  * MUST modify `pcap_parser.py` to yield appropriate L4 data in `RawEvent`.
  * MUST NOT alter any Knowledge Base or matcher.
* **Adding a New AppSummary Metric:**
  * MUST modify `AppSummaryBuilder` to compute the metric from `ConnectionRecord` objects.
  * MUST bump the `OUTPUT_SCHEMA_VERSION`.
