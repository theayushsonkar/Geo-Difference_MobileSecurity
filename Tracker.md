# Project Tracker

**Last Updated:** 12th July 2026


---

# 1. Overall Progress

| Phase | Module | Description | Status |
|--------|---------|-------------|--------|
| Phase A | Environment Setup | Android SDK, ADB, Apktool, project structure and dependencies | Complete |
| Phase A | Application Collection | Google Play scraping across regional storefronts | Complete |
| Phase A | APK Acquisition | APK/Split APK download and normalization | Complete |
| Phase A | APK Decompilation | Manifest and Smali extraction using Apktool | Complete |
| Phase A | Sample Indexing | Generation of `sample_id` for dataset joins | Complete |
| Phase B | Offline Knowledge Base | Axplorer, PScout, FlowDroid, Google APIs, TruffleHog preprocessing | Complete |
| Phase B | Manifest Analysis | Components, permissions, exported flags, security configuration extraction | Complete |
| Phase B | Privacy API Detection | Smali scanning using Aho-Corasick automaton | Complete |
| Phase B | Secret Detection | Hardcoded secret detection using compiled TruffleHog patterns | Complete |
| Phase B | Geo-Logic Detection | Detection using FlowDroid sources/sinks and custom rules | Complete |
| Phase B | SDK Detection | LibScout, fallback detector and canonicalization pipeline | Complete |
| Phase B | SDK Metadata Enrichment | Vendor, tracker and ecosystem enrichment | Complete |
| Phase B | CVE Matching | Embedded library vulnerability matching using NVD | Complete |
| Phase C | Automated Execution | ADB installation, permission handling and Monkey automation | Complete |
| Phase C | PCAP Collection | Automated PCAPdroid traffic capture | Complete |
| Phase C | Network Traffic Analysis | DNS, SNI, GeoIP, tracker detection and aggregation | In Progress |
| Phase C | HTTPS Traffic Analysis | Burp Suite integration and HTTPS interception | In Progress |
| Phase D | Dataset Integration | Merge outputs into unified dataset | Pending |
| Phase D | Statistical Analysis | Cross-country comparison and hypothesis testing | Pending |
| Phase D | Visualization | Figures, charts and summary tables | Pending |
| Phase D | Research Documentation | Thesis / Research paper | Pending |

---

# 2. Generated Outputs

| Module | Output |
|--------|--------|
| Sample Index | `sample_index.csv` |
| Manifest Analysis | `manifest_features.csv` |
| Permissions | `manifest_permissions.csv` |
| Components | `manifest_components.csv` |
| Network Configuration | `manifest_network_domains.csv` |
| SDK Detection | `manifest_sdks.csv` |
| CVE Matching | `cve_results.csv` |
| PCAP Analysis | `pcap_connections.csv` |
| PCAP Analysis | `pcap_domains.csv` |
| PCAP Analysis | `pcap_trackers.csv` |
| PCAP Analysis | `pcap_app_summary.csv` |

---

# 3. External Datasets & Tools

| Dataset / Tool | Purpose | Status |
|----------------|---------|--------|
| Google Play Scraper | Regional application collection | Complete |
| apkeep | APK acquisition | Complete |
| Apktool | APK decompilation | Complete |
| LibScout | Static SDK detection | Complete |
| LibScout SQLite Database | Library signature database | Complete |
| National Vulnerability Database (NVD) | CVE enrichment | Complete |
| Exodus Privacy Dataset | Tracker identification and metadata enrichment | Complete |
| Axplorer | Permission-to-API mapping | Complete |
| PScout | Android permission mapping | Complete |
| FlowDroid Sources & Sinks | Privacy API and geo-logic detection | Complete |
| TruffleHog Patterns | Hardcoded secret detection | Complete |
| Google Play Services AARs | Android framework API reference | Complete |
| Custom SDK Metadata | SDK vendor and ecosystem metadata | Complete |
| PCAPdroid | Network traffic collection | Complete |
| Burp Suite | HTTPS interception and payload inspection | In Progress |

---

# 4. Pipeline Workflow

```text
Google Play Scraping
        │
        ▼
APK Download
        │
        ▼
APK Normalization
        │
        ▼
APK Decompilation
        │
        ▼
Sample Index Generation
        │
        ├─────────────────────┐
        ▼                     ▼
Manifest Analysis      SDK Detection
        │                     │
        ├──────────────┬──────┘
        ▼              ▼
Privacy Analysis   CVE Matching
        │
        ▼
ADB Installation
        │
        ▼
Monkey Automation
        │
        ▼
PCAP Collection
        │
        ▼
Traffic Parsing
        │
        ▼
Dataset Generation
        │
        ▼
Dataset Integration
        │
        ▼
Statistical Analysis
        │
        ▼
Visualization & Report
```

---

# 5. Design Assumptions

| Assumption |
|------------|
| Private IP ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), localhost (`127.0.0.0/8`), and link-local (`169.254.0.0/16`) are excluded before GeoIP and tracker analysis. |
| Tracker detection uses deterministic longest-prefix matching. |
| LibScout results are preferred over fallback Smali detection when available. |
| Heavy code obfuscation may reduce fallback detector accuracy. |
| JVM startup overhead for LibScout is acceptable in batch execution. |
| `sample_id` and `package_name` are used for joining datasets. |

---

# 6. Hardcoded Configuration

| Configuration | Value |
|---------------|-------|
| PCAP Capture Duration | 60 seconds |
| Monkey Events | 500 |
| Curated SDK Metadata | Vendor aliases, canonical SDK names and ecosystem mappings |
| Smali Directory Patterns | `smali/`, `smali_classes2/`, `smali_classes3/`, ... |

---

# 7. Remaining Tasks

## Dynamic Analysis

| Task | Status |
|------|--------|
| Burp Suite integration | In Progress |
| HTTPS interception | Pending |
| HTTPS payload decryption | Pending |
| HTTP request extraction | Pending |
| HTTP response extraction | Pending |
| Payload inspection | Pending |
| Sensitive data detection | Pending |

*Note: Burp Suite HTTPS interception will require modifying the automated device setup to inject a custom CA Certificate into the Android device's root store, as PCAPdroid only captures raw encrypted packets.*

---

## Data Processing

| Task | Status |
|------|--------|
| Merge all generated CSV datasets | Pending |
| Dataset validation | Pending |
| Feature engineering | Pending |

---

## Statistical Analysis

| Task | Status |
|------|--------|
| SDK distribution comparison | Pending |
| Tracker prevalence comparison | Pending |
| Permission analysis | Pending |
| CVE distribution analysis | Pending |
| Network endpoint comparison | Pending |
| Hosting country analysis | Pending |
| TLS and cleartext traffic comparison | Pending |

---

## Visualization

| Task | Status |
|------|--------|
| Summary tables | Pending |
| Bar charts | Pending |
| Heatmaps | Pending |
| Geographic visualizations | Pending |
| Comparative plots | Pending |

---

## Scale-Up

| Task | Status |
|------|--------|
| Increase number of target countries | Pending |
| Process larger APK dataset | Pending |
| Execute full pipeline | Pending |

---

## Documentation

| Task | Status |
|------|--------|
| Methodology | Pending |
| Experimental setup | Pending |
| Results | Pending |
| Discussion | Pending |
| Conclusion | Pending |
| Final research paper | Pending |

---

# 8. Current Summary

| Component | Status |
|-----------|--------|
| Data Acquisition Pipeline | Complete |
| Static Analysis Pipeline | Complete |
| SDK Detection | Complete |
| Privacy Analysis | Complete |
| CVE Matching | Complete |
| PCAP Collection | Complete |
| Network Traffic Analysis | Almost Completed |
| HTTPS Traffic Analysis | In Progress |
| Dataset Integration | Pending |
| Statistical Analysis | Pending |
| Visualization | Pending |
| Documentation | Pending |