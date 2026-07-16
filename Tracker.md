# Project Tracker — Geo-Difference Mobile Security

**Last Updated:** 17th July 2026  
**Status Legend:** ✅ Complete · 🔄 In Progress · ⏳ Pending · 📁 Archived

---

## 1. Overall Progress

| Phase | Module | Status | Reference |
|-------|--------|--------|-----------|
| **A** | Environment Setup | ✅ | [Running Pipeline](docs/RUNNING_PIPELINE.md) |
| **A** | Application Collection | ✅ | [Pipeline README](pipeline/README.md) |
| **A** | APK Acquisition | ✅ | [Pipeline README](pipeline/README.md) |
| **A** | APK Decompilation | ✅ | [DEX Guide](docs/DEX_IMPLEMENTATION_GUIDE.md) |
| **A** | Sample Indexing (`sample_id`) | ✅ | [Data README](data/README.md) |
| **B** | Offline Knowledge Base | ✅ | [Knowledge Base README](knowledge_base/README.md) |
| **B** | Manifest Analysis | ✅ | [Manifest Scanner README](manifest_scanner/README.md) |
| **B** | Privacy API Detection (Aho-Corasick) | ✅ | [Matcher Architecture](knowledge_base/docs/matcher_architecture.md) |
| **B** | Secret Detection (TruffleHog) | ✅ | [Knowledge Enrichment Design](knowledge_base/docs/knowledge_enrichment_design.md) |
| **B** | Geo-Logic Detection | ✅ | [Manifest Scanner README](manifest_scanner/README.md) |
| **B** | SDK Detection (LibScout + Fallback) | ✅ | [SDK Detection README](sdk_detection/README.md) |
| **B** | SDK Metadata Enrichment | ✅ | [SDK Detection README](sdk_detection/README.md) |
| **B** | CVE Matching (NVD) | ✅ | [CVE Overview](cve/CVE_Analysis_Overview.md) |
| **C** | ADB Install + Monkey Automation | ✅ | [PCAP README](pcap/README.md) |
| **C** | PCAP Collection (PCAPdroid) | ✅ | [PCAP README](pcap/README.md) |
| **C** | Network Traffic Analysis | 🔄 | [PCAP README](pcap/README.md) |
| **C** | HTTPS Traffic Interception (Burp) | 🔄 | *(No file yet — see §7)* |
| **D** | Dataset Integration | ⏳ | — |
| **D** | Statistical Analysis | ⏳ | — |
| **D** | Visualization | ⏳ | — |
| **D** | Thesis / Research Paper | ⏳ | — |

---

## 2. Repository Architecture

| Layer | Folder | Role | Reference |
|-------|--------|------|-----------|
| Production | `cve/` | CVE vulnerability matcher | [CVE Overview](cve/CVE_Analysis_Overview.md) |
| Production | `manifest_scanner/` | Static manifest analysis engine | [Manifest README](manifest_scanner/README.md) |
| Production | `sdk_detection/` | SDK & tracker attribution engine | [SDK README](sdk_detection/README.md) |
| Production | `pcap/` | Network traffic analysis engine | [PCAP README](pcap/README.md) |
| Production | `pipeline/` | APK ingestion pipeline | [Pipeline README](pipeline/README.md) |
| Production | `knowledge_base/` | Synthesized privacy rule databases | [KB README](knowledge_base/README.md) |
| Data | `data/` | NVD feeds, GeoIP, package lists | [Data README](data/README.md) |
| Third-party | `third_party/` | LibScan binary & extraction | [External Datasets](docs/external_datasets_and_tools.md) |
| Tools | `tools/validation/` | Audit & benchmark scripts | — |
| Archive | `research_archive/` | Historical reports & experiments | [Archive README](research_archive/README.md) |
| Docs | `docs/` | Architecture & guides | [Architecture](docs/ARCHITECTURE.md) |

> Full structural rules → [Repository Structure](docs/REPOSITORY_STRUCTURE.md)

---

## 3. Generated Outputs

| Module | Output File | Dataset Details |
|--------|-------------|-----------------|
| Sample Index | `sample_index.csv` | [Data README](data/README.md) |
| App Summary | `manifest_features.csv` | [App Summary Dataset](manifest_scanner/dataset_details/App_Summary_Dataset_Overview.md) |
| Permissions | `manifest_permissions.csv` | [Permission Dataset](manifest_scanner/dataset_details/Permission_Dataset_Overview.md) |
| Components | `manifest_components.csv` | [Component Dataset](manifest_scanner/dataset_details/Component_Dataset_Overview.md) |
| Network Config | `manifest_network_domains.csv` | [NSC Dataset](manifest_scanner/dataset_details/NSC_Dataset_Overview.md) |
| SDK Detection | `manifest_sdks.csv` | [SDK Dataset](manifest_scanner/dataset_details/SDK_Dataset_Overview.md) |
| Static Findings | `static_code_findings.csv` | [Findings Dataset](manifest_scanner/dataset_details/Static_Code_Findings_Dataset_Overview.md) |
| CVE Matching | `cve_results.csv` | [CVE Overview](cve/CVE_Analysis_Overview.md) |
| PCAP Connections | `pcap_connections.csv` | [PCAP README](pcap/README.md) |
| PCAP DNS | `pcap_dns.csv` | [PCAP README](pcap/README.md) |
| PCAP Domain Geo | `pcap_domain_geo.csv` | [PCAP README](pcap/README.md) |
| PCAP App Summary | `pcap_app_summary.csv` | [PCAP README](pcap/README.md) |

---

## 4. External Datasets & Tools

| Dataset / Tool | Purpose | Status | Reference |
|----------------|---------|--------|-----------|
| Google Play Scraper | Regional app collection | ✅ | [Pipeline README](pipeline/README.md) |
| apkeep (EFF) | APK acquisition | ✅ | [External Datasets](docs/external_datasets_and_tools.md) |
| Apktool | APK decompilation + Smali | ✅ | [DEX Guide](docs/DEX_IMPLEMENTATION_GUIDE.md) |
| LibScout | Static SDK detection | ✅ | [SDK README](sdk_detection/README.md) |
| NVD (NIST) | CVE vulnerability data | ✅ | [CVE Overview](cve/CVE_Analysis_Overview.md) |
| Exodus Privacy | Tracker identification | ✅ | [KB README](knowledge_base/README.md) |
| Axplorer | Permission-to-API mapping | ✅ | [Axplorer Report](research_archive/knowledge_base/axplorer_validation_report.md) |
| PScout | Android permission mapping | ✅ | [PScout Report](research_archive/knowledge_base/pscout_validation_report.md) |
| FlowDroid Sources/Sinks | Privacy API + geo-logic detection | ✅ | [Geo Report](research_archive/knowledge_base/flowdroid_geo_report.md) |
| TruffleHog Patterns | Hardcoded secret detection | ✅ | [TruffleHog Report](research_archive/knowledge_base/trufflehog_import_report.md) |
| Google Play Services AARs | Android framework API ref | ✅ | [GMS Report](research_archive/knowledge_base/gms_validation_report.md) |
| PCAPdroid | Network traffic capture | ✅ | [PCAP README](pcap/README.md) |
| MaxMind GeoLite2 | IP geolocation + ASN | ✅ | [External Datasets](docs/external_datasets_and_tools.md) |
| Burp Suite | HTTPS interception | 🔄 | *(No file yet — see §7)* |

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

Historical validation reports from the knowledge base build phase:

| Report | Link |
|--------|------|
| Aho-Corasick Benchmark | [aho_benchmark_report.md](research_archive/knowledge_base/aho_benchmark_report.md) |
| Axplorer Validation | [axplorer_validation_report.md](research_archive/knowledge_base/axplorer_validation_report.md) |
| Database Freeze Report | [database_freeze_report.md](research_archive/knowledge_base/database_freeze_report.md) |
| Exodus Dataset Summary | [exodus_dataset_summary.md](research_archive/knowledge_base/exodus_dataset_summary.md) |
| Privacy Database Validation | [privacy_database_validation.md](research_archive/knowledge_base/privacy_database_validation.md) |
| SDK Pipeline Final Report | [sdk_pipeline_final_report.md](research_archive/knowledge_base/sdk_pipeline_final_report.md) |
| System Validation Report | [system_validation_report.md](research_archive/knowledge_base/system_validation_report.md) |
| Tracker Enricher Report | [tracker_enricher_report.md](research_archive/knowledge_base/tracker_enricher_report.md) |

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