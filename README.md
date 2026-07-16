# Geo-Difference Mobile Security Research Pipeline

This repository contains the end-to-end research pipeline for the **Geo-Difference Mobile Security** project. The pipeline is designed to study regional differences in Android applications across three main dimensions:
1. **Static Manifest Configurations** (Permissions, components, cleartext traffic policies, security configurations).
2. **Vulnerability Landscapes (CVE)** (Embedded libraries and their associated public vulnerabilities).
3. **Dynamic Network Behavior (PCAP)** (Active network hosts, tracker endpoints, DNS query patterns, and country-hosting distributions).

---

## 1. Architectural Blueprint

The pipeline is split into three phases: **Ingestion**, **Static Analysis (Manifest & CVE)**, and **Dynamic Analysis (PCAP Collection & Aggregation)**.

```text
                                  +-----------------------+
                                  |      scrapper.py      |  <-- Geographically target top apps
                                  +-----------+-----------+
                                              |
                                              ▼
                                  +-----------------------+
                                  |   download_apks.py    |  <-- Fetch APKs/Split-APKs
                                  +-----------+-----------+
                                              |
                                              ▼
                                  +-----------------------+
                                  |  normalize_packages.py|  <-- Standardize local names
                                  +-----------+-----------+
                                              |
                                              ▼
                                  +-----------------------+
                                  |    decode_apks.py     |  <-- Run Apktool to extract raw XML/Smali
                                  +-----------+-----------+
                                              |
                                              ▼
                                  +-----------------------+
                                  | build_sample_index.py |  <-- Register hashes & country metadata
                                  +-----------+-----------+
                                              |
                       +----------------------+----------------------+
                       |                                             |
                       ▼                                             ▼
          +-------------------------+                   +-------------------------+
          |    scan_manifest.py     |                   |    collect_pcap.py      |
          |   (manifest_scanner)    |                   | (ADB + PCAPdroid + UI)  |
          +------------+------------+                   +------------+------------+
                       |                                             |
                       ▼                                             ▼
          +-------------------------+                   +-------------------------+
          |      cve/main.py        |                   |  run_pcap_analysis.py   |
          |  (NVD Vulnerability)    |                   |       (pcap/*)          |
          +------------+------------+                   +------------+------------+
                       |                                             |
                       +----------------------+----------------------+
                                              |
                                              ▼
                                  +-----------------------+
                                  |   Downstream Pandas   |  <-- Join all facts on sample_id
                                  | & SciPy Data Analysis |      & package_name
                                  +-----------------------+
```

---

## 2. Phase-by-Phase Process & Logic

### Phase A: Ingestion & Environment Setup

#### 1. Target Scraping (`scrapper.py`)
*   **Logic:** Queries Google Play Store across specified target country codes (e.g., `in`, `us`, `de`, `ru`) and categories to list the top free apps.
*   **Output:** Generates `output/top_apps_full.csv` containing metadata (release date, price, categories, ranking).
*   **Subsequent step:** `pipeline/prepare_india_package_list.py` parses this master list to generate localized text files of target package IDs (e.g., `data/package_lists/india_packages.txt`).

#### 2. APK Downloader (`pipeline/download_apks.py`)
*   **Logic:** Connects to Play Store/APKeep services, downloads the APK binaries (supporting single APKs and split APK bundles).
*   **Output:** Files saved under `apks/<package_name>/*.apk`.

#### 3. Normalization (`pipeline/normalize_packages.py`)
*   **Logic:** Cleans package structures, ensures filenames match their package IDs, and verifies that no corrupted files exist before decompression.

#### 4. Decompilation/Decoding (`pipeline/decode_apks.py`)
*   **Logic:** Runs `apktool` on all APKs inside `apks/` to reconstruct their layout, extract human-readable `AndroidManifest.xml`, resources, and Smali bytecode files.
*   **Output:** Extracted folders are saved to `decoded/<package_name>_decoded/`.

#### 5. Sample Index Building (`pipeline/build_sample_index.py`)
*   **Logic:** Indexes decoded and downloaded directories, computes SHA256 hashes of the files, and links each file structure to its targeted country market.
*   **Output:** Creates the master project database `sample_index.csv` in the root folder. All subsequent analysis steps join their outputs against this index using the unique `sample_id` key (format: `{package_name}_{country_code}`).

---

### Phase B: Static Analysis Stage

#### 6. Manifest Scanner (`scan_manifest.py` invoking `manifest_scanner/`)
*   **Logic:** Inspects `AndroidManifest.xml` statically.
    *   **Components:** Extracts list of Activities, Services, Receivers, and Providers. Flags if components are `exported`. For Android 12+ (SDK 31+), it validates if `android:exported` is explicitly configured.
    *   **Cleartext Policy:** Extracts `android:usesCleartextTraffic` configurations to track if cleartext HTTP is allowed.
    *   **Network Security Config:** Parses the XML references pointing to custom network policies to identify if user-installed certificates or cleartext domains are allowed.
*   **Output:** Structured CSV tables in `output/manifest/` tracking permissions, components, and policy rules.

#### 7. CVE Matching Stage (`cve/main.py`)
*   **Logic:** Matches physical libraries discovered in the app's DEX files against known CVE records:
    *   Loads vulnerability records from the National Vulnerability Database (NVD) via `nvd_loader.py`.
    *   Determines library package namespaces and versions.
    *   Runs the matcher (`matcher.py`) to map identified versions to corresponding CVE codes.
*   **Output:** Tabular reports of matching CVEs, CVSS scores, and vector configurations.

---

### Phase C: Dynamic Analysis Stage

#### 8. Automated Capture Collection (`collect_pcap.py`)
*   **Logic:** Installs, captures, and cleans up apps on an Android device:
    *   Installs APK/split-APKs from `apks/<package_name>/` using ADB.
    *   Sends an intent to **PCAPdroid** to start capturing network packets. The capture is filtered *specifically* to the target app's package name so no background system traffic is recorded.
    *   Launches the app and runs the Android **Monkey UI exerciser** to simulate random user taps, scrolls, and key presses for a set duration to trigger network requests.
    *   Force-stops the target app, stops the PCAPdroid capture, pulls the `.pcap` capture file to `data/pcap/{sample_id}.pcap` on the host PC, and uninstalls the app from the device.
*   **Key Parameters:**
    *   `--capture-time`: Duration to capture traffic (default: 60s).
    *   `--monkey-events`: Amount of random UI actions to inject (default: 500).

#### 9. Traffic Analysis & Geolocation (`run_pcap_analysis.py` invoking `pcap/`)
*   **Logic:** Converts raw packet files (`.pcap`/`.pcapng`) into tabular datasets:
    *   `pcap_parser.py`: Uses `dpkt` to parse packets. Resolves domains using DNS queries, HTTP Host headers, and TLS ClientHello Server Name Indication (SNI) extensions.
    *   `tracker_matcher.py`: Suffix-matches hostnames against tracker rules and resolves them to parent canonical vendor entities (e.g., `Google`, `Unity`).
    *   `geoip.py`: Queries IP geolocations, ASN numbers, and hosting organizations. Implements single-caching to prevent rate-limit blocks and dual-state inconsistency.
    *   `connection_builder.py`: Aggregates packets into logical sessions grouped by 6-tuple: `(sample_id, session_id, domain, dst_ip, dst_port, protocol)`.
    *   `app_summary.py`: Compiles aggregates. Computes country-hosting concentrations **excluding private/local network ranges** (`10.x.x.x`, `192.168.x.x`, `172.16.x.x`, or `PRI`) to prevent routing hops from corrupting results.

---

## 3. Data Schema & Core Identifiers

### Primary Keys & Join Paths
*   **`sample_id`**: Master key (e.g., `com.bgfa_in`). Format is `{package_name}_{country_code}`.
*   **`package_name`**: Standard package identifier (e.g., `com.bgfa`).

Any researcher or analytical engine can join static features (Manifest component counts, CVE risks) and dynamic features (tracker counts, TLS encryption percentages, top-country hosting) using simple Pandas joins:
```python
import pandas as pd

manifest_df = pd.read_csv("output/manifest_features.csv")
pcap_summary_df = pd.read_csv("output/pcap/pcap_app_summary.csv")

# Join on sample_id
merged_dataset = pd.merge(manifest_df, pcap_summary_df, on="sample_id")
```

---

## 4. End-to-End Command Execution Guide

From the root project directory:

### Step 1: Prep Package List
```powershell
python pipeline/prepare_india_package_list.py
```

### Step 2: Download APK Binaries
```powershell
python pipeline/download_apks.py --packages data/package_lists/india_packages.txt --source google-play --limit 5
```

### Step 3: Normalize Local Layouts
```powershell
python pipeline/normalize_packages.py
```

### Step 4: Decompile/Decode APK Files
```powershell
python pipeline/decode_apks.py
```

### Step 5: Build Master Index
```powershell
python pipeline/build_sample_index.py --app-store google-play
```

### Step 6: Scan Application Manifests
```powershell
python scan_manifest.py --input-dir decoded/ --output-dir output/manifest/ --sample-index sample_index.csv
```

### Step 7: Run CVE Vulnerability Analysis
```powershell
python cve/main.py --input-dir decoded/ --output-dir output/cve/ --sample-index sample_index.csv
```

### Step 8: Capture Live Traffic on Connected Device
```powershell
# Interactive mode (checks with you before processing each app)
python collect_pcap.py --capture-time 60 --monkey-events 500

# Automated mode (runs all apps, skips already captured, non-interactive)
python collect_pcap.py --auto --skip-captured --capture-time 60 --monkey-events 500
```

### Step 9: Parse Captured PCAPs
```powershell
python run_pcap_analysis.py --input-dir data/pcap --output-dir output/pcap --sample-index sample_index.csv
```

---

## 5. Repository Layout

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
