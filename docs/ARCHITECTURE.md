# Geo-Difference Mobile Security: System Architecture

This document outlines the architectural design of the Geo-Difference Mobile Security analysis system, explicitly delineating the core engineering and methodological pipeline.

---

## 1. System Overview

The project implements a highly automated, end-to-end pipeline for the cross-jurisdictional security and privacy analysis of Android applications. It fuses static bytecode analysis, manifest scanning, and dynamic network traffic inspection (PCAP) to generate deterministic, reproducible fact tables regarding application behavior, geographic data exposure, and vulnerability presence.

---

## 2. Core Modules (The Analysis Pipeline)

### 2.1 Synthesized Knowledge Base & Matching Engine (`knowledge_base/`)
* **Dataset Synthesis:** A unified ontology that merges disparate, highly fragmented cybersecurity datasets (Axplorer, PScout, TruffleHog regexes, and Exodus Privacy trackers). The system actively deduplicates and cross-references these datasets into a frozen, canonical truth state.
* **Algorithmic Migration (Aho-Corasick):** A high-performance, multi-pattern string matching pipeline utilizing the Aho-Corasick automaton. This replaces standard linear regex evaluations, enabling the system to evaluate tens of thousands of privacy APIs and SDK signatures against massive Android applications with high throughput and bounded memory constraints.

### 2.2 Advanced SDK & Tracker Attribution Engine (`sdk_detection/`)
* **Vendor Canonicalization:** An algorithmic mapping layer that resolves fragmented SDK and tracker names (e.g., collapsing sub-brands into parent corporate entities) to prevent statistical double-counting.
* **Deterministic Tracker Enrichment:** An exact longest-suffix domain matching architecture (with LRU caching) to definitively map network traffic endpoints to parent tracker organizations, bypassing heuristic-based guesswork.
* **Fallback Detection:** A custom detection wrapper that intercepts and categorizes libraries missed by standard external static scanners.

### 2.3 Deterministic Network Analysis Pipeline (`pcap/`)
* **6-Tuple Aggregation:** A custom offline packet processing engine that aggregates raw `dpkt` events into deterministic connection buckets based on a strict 6-tuple identity (Sample ID, Session ID, Domain, Destination IP, Port, Protocol).
* **Custom TLS SNI Extraction:** A byte-walking extraction module to identify Server Name Indication (SNI) hostnames directly from raw ClientHello packets. This custom approach successfully tolerates TLS fragmentation and GREASE extensions.
* **Unified Geo-Risk Attribution:** An in-memory, O(1) GeoIP mapping system that attributes raw IP addresses to their respective Autonomous System Numbers (ASN) and sovereign country codes without relying on vulnerable local DNS resolution.

### 2.4 Vulnerability & Threat Mapping (`cve/` & `manifest_scanner/`)
* **NVD Cross-Referencing:** An analysis engine that dynamically maps identified SDK versions directly to the National Vulnerability Database (NVD) JSON feeds, identifying exposure to documented CVEs.
* **Contextual Manifest Scanning:** An XML parser that correlates requested Android permissions against the synthesized knowledge base to flag known privacy-invasive API boundaries.

---

## 3. Infrastructure & Orchestration

* **Automated Data Ingestion (`pipeline/`):** A robust acquisition pipeline that handles XAPK normalization, split-APK extraction, and automated decompilation via `apktool`, ensuring all apps are converted into standard formats required by static analyzers.
* **Master Orchestration (`run_full_pipeline.py`):** The central nervous system that executes the entire 12-stage pipeline (scraping, downloading, static analysis, dynamic PCAP collection, and disk cleanup) completely unattended.

---

## 4. External Tooling Integration

This architecture integrates several third-party tools to handle low-level extraction and base detection, building advanced logic on top of their output:

* **`apktool`:** Utilized to disassemble Dalvik bytecode into Smali and decode the `AndroidManifest.xml`.
* **`apkeep` (EFF):** Utilized as the download engine to fetch binaries from Google Play.
* **`LibScan`:** An external SDK detection tool used as the baseline static matching engine (wrapped and sanitized by the custom `sdk_detection` module).
* **`dpkt`:** Python library used for raw packet decoding within the custom PCAP analysis engine.
* **External Datasets:** NVD (NIST) feeds, Exodus Privacy trackers, Axplorer/PScout mappings, and MaxMind GeoLite2 databases.
