# Project Tracker — Geo-Difference Mobile Security

**Last Updated:** 17th July 2026  
**Status Legend:** ✅ Complete · 🔄 In Progress · ⏳ Pending · 📁 Archived

---

## 1. Overall Progress

| Phase | Module | Description | Status | Reference |
|-------|--------|-------------|--------|-----------|
| **A** | Environment Setup | Android SDK, ADB, Apktool, project structure and dependencies configured | ✅ | [Running Pipeline](docs/RUNNING_PIPELINE.md) |
| **A** | Application Collection | Scraped top free apps across regional Google Play storefronts | ✅ | [Pipeline README](pipeline/README.md) |
| **A** | APK Acquisition | Downloaded APKs and Split-APKs using apkeep; handles multi-file bundles | ✅ | [Pipeline README](pipeline/README.md) |
| **A** | APK Decompilation | Extracted `AndroidManifest.xml` and Smali bytecode using Apktool | ✅ | [DEX Guide](docs/DEX_IMPLEMENTATION_GUIDE.md) |
| **A** | Sample Indexing | Generated `sample_id = {package}_{country}` as the universal join key | ✅ | [Data README](data/README.md) |
| **B** | Offline Knowledge Base | Merged Axplorer, PScout, FlowDroid, TruffleHog and Exodus into frozen databases | ✅ | [Knowledge Base README](knowledge_base/README.md) |
| **B** | Manifest Analysis | Extracted permissions, components, exported flags and cleartext traffic policy | ✅ | [Manifest Scanner README](manifest_scanner/README.md) |
| **B** | Privacy API Detection | Multi-pattern Aho-Corasick scan of Smali for privacy-sensitive APIs | ✅ | [Matcher Architecture](knowledge_base/docs/matcher_architecture.md) |
| **B** | Secret Detection | Compiled TruffleHog regexes detect hardcoded API keys and tokens in source | ✅ | [Knowledge Enrichment Design](knowledge_base/docs/knowledge_enrichment_design.md) |
| **B** | Geo-Logic Detection | FlowDroid sources/sinks detect location-aware data flows | ✅ | [Manifest Scanner README](manifest_scanner/README.md) |
| **B** | SDK Detection | LibScout + custom fallback Smali detector; prefers LibScout when available | ✅ | [SDK Detection README](sdk_detection/README.md) |
| **B** | SDK Metadata Enrichment | Maps SDK names to canonical vendor, tracker category and ecosystem | ✅ | [SDK Detection README](sdk_detection/README.md) |
| **B** | CVE Matching | Matches embedded library versions against 25 years of NVD CVE feeds | ✅ | [CVE Overview](cve/CVE_Analysis_Overview.md) |
| **C** | ADB Install + Monkey | Automates APK install, Monkey UI exerciser and app teardown per sample | ✅ | [PCAP README](pcap/README.md) |
| **C** | PCAP Collection | PCAPdroid captures per-app network traffic filtered to target package | ✅ | [PCAP README](pcap/README.md) |
| **C** | Network Traffic Analysis | Parses DNS, TLS SNI, GeoIP, tracker matching; aggregates into 6-tuple fact table | 🔄 | [PCAP README](pcap/README.md) |
| **C** | HTTPS Interception (Burp) | Requires CA cert injection into Android root store for payload decryption | 🔄 | *(No file yet — see §7)* |
| **D** | Dataset Integration | Merge all CSVs into one unified analysis dataset joined on `sample_id` | ⏳ | — |
| **D** | Statistical Analysis | Cross-country SDK, tracker, CVE and network endpoint comparison | ⏳ | — |
| **D** | Visualization | Charts, heatmaps, geographic plots for thesis figures | ⏳ | — |
| **D** | Thesis / Research Paper | Final write-up of methodology, results and discussion | ⏳ | — |

---

## 2. Repository Architecture

| Layer | Folder | Description | Reference |
|-------|--------|-------------|-----------|
| Production | `cve/` | Loads NVD feeds and matches detected library versions to CVE records | [CVE Overview](cve/CVE_Analysis_Overview.md) |
| Production | `manifest_scanner/` | Parses `AndroidManifest.xml` and scans Smali; outputs structured CSV fact tables | [Manifest README](manifest_scanner/README.md) |
| Production | `sdk_detection/` | Runs LibScout, fallback detector, canonicalization and Exodus tracker enrichment | [SDK README](sdk_detection/README.md) |
| Production | `pcap/` | Parses raw `.pcap` files into connection records with GeoIP and tracker attribution | [PCAP README](pcap/README.md) |
| Production | `pipeline/` | Orchestrates scraping → download → normalization → decompilation → indexing | [Pipeline README](pipeline/README.md) |
| Production | `knowledge_base/` | Synthesizes external datasets into frozen Aho-Corasick automata and lookup tables | [KB README](knowledge_base/README.md) |
| Data | `data/` | Stores NVD ZIP feeds, GeoIP databases and per-country package list files | [Data README](data/README.md) |
| Third-party | `third_party/` | LibScan binary and extracted reference data used by SDK detection | [External Datasets](docs/external_datasets_and_tools.md) |
| Tools | `tools/validation/` | Audit, benchmark and comparison scripts; never imported by production code | — |
| Archive | `research_archive/` | Read-only historical reports and benchmark outputs from the development phase | [Archive README](research_archive/README.md) |
| Docs | `docs/` | Architecture guide, repository structure rules, dataset references and DEX guide | [Architecture](docs/ARCHITECTURE.md) |

> Full structural rules → [Repository Structure](docs/REPOSITORY_STRUCTURE.md)

---

## 3. Generated Outputs

| Module | Output File | What it contains | Dataset Details |
|--------|-------------|-----------------|-----------------|
| Sample Index | `sample_index.csv` | Master registry of every app keyed on `sample_id` | [Data README](data/README.md) |
| App Summary | `manifest_features.csv` | Per-app rolled-up feature vector for analysis | [App Summary Dataset](manifest_scanner/dataset_details/App_Summary_Dataset_Overview.md) |
| Permissions | `manifest_permissions.csv` | All declared Android permissions per app | [Permission Dataset](manifest_scanner/dataset_details/Permission_Dataset_Overview.md) |
| Components | `manifest_components.csv` | Activities, Services, Receivers, Providers + exported flags | [Component Dataset](manifest_scanner/dataset_details/Component_Dataset_Overview.md) |
| Network Config | `manifest_network_domains.csv` | Cleartext domains and custom Network Security Config entries | [NSC Dataset](manifest_scanner/dataset_details/NSC_Dataset_Overview.md) |
| SDK Detection | `manifest_sdks.csv` | Detected SDKs with canonical vendor, category and tracker flag | [SDK Dataset](manifest_scanner/dataset_details/SDK_Dataset_Overview.md) |
| Static Findings | `static_code_findings.csv` | Hardcoded secrets, privacy API calls and geo-logic sinks | [Findings Dataset](manifest_scanner/dataset_details/Static_Code_Findings_Dataset_Overview.md) |
| CVE Matching | `cve_results.csv` | CVE IDs, CVSS scores and affected library versions per app | [CVE Overview](cve/CVE_Analysis_Overview.md) |
| PCAP Connections | `pcap_connections.csv` | Every unique 6-tuple connection with GeoIP, tracker, TLS metadata | [PCAP README](pcap/README.md) |
| PCAP DNS | `pcap_dns.csv` | DNS queries and responses including hardcoded resolver detection | [PCAP README](pcap/README.md) |
| PCAP Domain Geo | `pcap_domain_geo.csv` | Resolved domain-to-IP-to-country mapping for all endpoints | [PCAP README](pcap/README.md) |
| PCAP App Summary | `pcap_app_summary.csv` | Per-app aggregate: unique countries, trackers, TLS ratio, top ASN | [PCAP README](pcap/README.md) |

---

## 4. External Datasets & Tools

| Dataset / Tool | What it does | Status | Reference |
|----------------|-------------|--------|-----------|
| Google Play Scraper | Queries Play Store by country and category to list top free apps | ✅ | [Pipeline README](pipeline/README.md) |
| apkeep (EFF) | Fetches APK binaries from Google Play; handles split-APK bundles | ✅ | [External Datasets](docs/external_datasets_and_tools.md) |
| Apktool | Disassembles APKs into Smali bytecode and decoded XML resources | ✅ | [DEX Guide](docs/DEX_IMPLEMENTATION_GUIDE.md) |
| LibScout | Signature-based static SDK detector using a pre-built SQLite library database | ✅ | [SDK README](sdk_detection/README.md) |
| NVD (NIST) | 25 years of CVE records with CVSS scores used for vulnerability mapping | ✅ | [CVE Overview](cve/CVE_Analysis_Overview.md) |
| Exodus Privacy | Tracker domain and package prefix database for privacy analysis | ✅ | [KB README](knowledge_base/README.md) |
| Axplorer | Maps Android API methods to the permissions that protect them | ✅ | [Axplorer Report](research_archive/knowledge_base/axplorer_validation_report.md) |
| PScout | Alternative Android permission-to-API mapping for cross-validation | ✅ | [PScout Report](research_archive/knowledge_base/pscout_validation_report.md) |
| FlowDroid Sources/Sinks | Defines privacy-sensitive data sources and geo-aware sink points | ✅ | [Geo Report](research_archive/knowledge_base/flowdroid_geo_report.md) |
| TruffleHog Patterns | 700+ compiled regex patterns for detecting hardcoded secrets and API tokens | ✅ | [TruffleHog Report](research_archive/knowledge_base/trufflehog_import_report.md) |
| Google Play Services AARs | Android framework binaries used as SDK reference signatures | ✅ | [GMS Report](research_archive/knowledge_base/gms_validation_report.md) |
| PCAPdroid | On-device app that captures per-app network traffic as `.pcap` files | ✅ | [PCAP README](pcap/README.md) |
| MaxMind GeoLite2 | Maps IP addresses to country codes and ASN organizations | ✅ | [External Datasets](docs/external_datasets_and_tools.md) |
| Burp Suite | HTTPS proxy for decrypting and inspecting encrypted app traffic | 🔄 | *(No file yet — see §7)* |

---

## 5. Pipeline Workflow

```
[A] Google Play Scraping ──────────────────────────── pipeline/README.md
         │
[A] APK Download & Normalization ────────────────────── pipeline/README.md
         │
[A] APK Decompilation (apktool) ───────────────────── docs/DEX_IMPLEMENTATION_GUIDE.md
         │
[A] Sample Index Generation ────────────────────────── data/README.md
         │
         ├────────────────────────────┐
         │                           │
[B] Manifest Analysis           [B] SDK Detection
  manifest_scanner/README.md      sdk_detection/README.md
         │                           │
[B] Privacy + Secret Detection  [B] CVE Matching
  knowledge_base/docs/            cve/CVE_Analysis_Overview.md
  matcher_architecture.md
         │
[C] ADB Install + Monkey Automation ──────────────── pcap/README.md
         │
[C] PCAP Capture (PCAPdroid)
         │
[C] Traffic Parsing (DNS, TLS SNI, GeoIP) ─────────── pcap/README.md
         │
[D] Dataset Integration ──────────────────────────── (Pending)
         │
[D] Statistical Analysis + Visualization ─────────── (Pending)
         │
[D] Thesis / Research Paper ──────────────────────── (Pending)
```

---

## 6. Design Decisions & Hardcoded Configuration

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| PCAP Capture Duration | 60 seconds | Sufficient for background traffic to initialize |
| Monkey Events | 500 | Balances coverage vs. execution time |
| Smali Scan Directories | `smali/`, `smali_classes2/`, `smali_classes3/` … | Multi-dex support |
| Tracker Matching | Longest-suffix domain match | Deterministic, no false positives |
| LibScout Priority | LibScout > Fallback Smali | Higher accuracy when signatures available |
| Private IP Exclusion | `10.0/8`, `172.16/12`, `192.168/16`, `127.0/8`, `169.254/16` | Exclude routing hops from geo analysis |
| Sample Identity Key | `{package_name}_{country_code}` → `sample_id` | Enables clean CSV joins across all datasets |
| SDK Canonicalization | Custom vendor alias map | Prevents double-counting of sub-brands |

---

## 7. Remaining Tasks

### 🔄 In Progress

| Task | Notes |
|------|-------|
| HTTPS traffic interception (Burp Suite) | Requires custom CA cert injection into Android root store |
| Network Traffic Analysis finalization | Output CSVs generated; cross-country aggregation pending |

### ⏳ Pending — Data Processing

| Task |
|------|
| Merge all generated CSV datasets into unified analysis dataset |
| Dataset validation and duplicate removal |
| Feature engineering for statistical models |

### ⏳ Pending — Statistical Analysis

| Task |
|------|
| SDK distribution comparison (India vs. other regions) |
| Tracker prevalence comparison |
| Permission pattern analysis |
| CVE severity distribution |
| Network hosting country analysis |
| TLS vs. cleartext traffic ratio comparison |

### ⏳ Pending — Visualization

| Task |
|------|
| Summary tables per country |
| Bar charts (permissions, trackers, CVE) |
| Heatmaps (tracker × country) |
| Geographic hosting visualizations |

### ⏳ Pending — Documentation

| Task | Suggested File |
|------|---------------|
| Methodology chapter | `docs/METHODOLOGY.md` *(create later)* |
| Experimental setup | `docs/EXPERIMENTAL_SETUP.md` *(create later)* |
| Results & Discussion | `docs/RESULTS.md` *(create later)* |
| Final research paper | — |

---

## 8. Research Archive

Historical validation reports generated during the knowledge base build phase:

| Report | What it covers | Link |
|--------|----------------|------|
| Aho-Corasick Benchmark | Performance of the multi-pattern automaton vs. linear regex | [aho_benchmark_report.md](research_archive/knowledge_base/aho_benchmark_report.md) |
| Axplorer Validation | Coverage and accuracy of the Axplorer permission-to-API import | [axplorer_validation_report.md](research_archive/knowledge_base/axplorer_validation_report.md) |
| Database Freeze Report | Final frozen state of all synthesized knowledge base tables | [database_freeze_report.md](research_archive/knowledge_base/database_freeze_report.md) |
| Exodus Dataset Summary | Tracker count, domain coverage and deduplication results | [exodus_dataset_summary.md](research_archive/knowledge_base/exodus_dataset_summary.md) |
| Privacy Database Validation | End-to-end correctness check of the merged privacy rule database | [privacy_database_validation.md](research_archive/knowledge_base/privacy_database_validation.md) |
| SDK Pipeline Final Report | Full accuracy and recall metrics of the SDK detection pipeline | [sdk_pipeline_final_report.md](research_archive/knowledge_base/sdk_pipeline_final_report.md) |
| System Validation Report | Integration test results across the entire static analysis pipeline | [system_validation_report.md](research_archive/knowledge_base/system_validation_report.md) |
| Tracker Enricher Report | Validation of longest-suffix tracker matching accuracy | [tracker_enricher_report.md](research_archive/knowledge_base/tracker_enricher_report.md) |

> Full list → [Research Archive README](research_archive/README.md)

---

## 9. Current Status Summary

| Component | Status |
|-----------|--------|
| Data Acquisition Pipeline | ✅ Complete |
| Static Analysis Pipeline | ✅ Complete |
| SDK Detection & Enrichment | ✅ Complete |
| Privacy & Secret Detection | ✅ Complete |
| CVE Matching | ✅ Complete |
| PCAP Collection | ✅ Complete |
| Network Traffic Analysis | 🔄 In Progress |
| HTTPS Traffic Analysis | 🔄 In Progress |
| Repository Freeze & Documentation | ✅ Complete |
| Dataset Integration | ⏳ Pending |
| Statistical Analysis | ⏳ Pending |
| Visualization | ⏳ Pending |
| Thesis / Paper | ⏳ Pending |