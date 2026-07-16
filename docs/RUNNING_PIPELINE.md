# Pipeline Execution Guide: Commands, Options, and Stages

This document lists all commands required to run the Geo-Difference Mobile Security pipeline. You can run the stages **one-by-one** (recommended for testing) or run a subset of them.

---

## Stage-wise Command List

### Stage 1: Package List Preparation
Extracts target app packages for a given region from scraped datasets.
```powershell
python pipeline/prepare_india_package_list.py
```

### Stage 2: Download APKs
Downloads APK binaries or split APK bundles from the target app store.
```powershell
python pipeline/download_apks.py --packages data/package_lists/india_packages.txt --source google-play --limit 5
```
*   **Key Flags:**
    *   `--packages`: Path to text file containing target package names.
    *   `--source`: Download provider (e.g. `google-play`).
    *   `--limit`: Maximum number of packages to download.
    *   `--email` & `--token`: Credentials required by the Play Store provider.

### Stage 3: Package Normalization
Standardizes folder layouts and checks file integrity.
```powershell
python pipeline/normalize_packages.py
```

### Stage 4: Decompile / Decode APKs
Invokes `apktool` to extract XML configurations, resources, and Smali bytecode files.
```powershell
python pipeline/decode_apks.py
```

### Stage 5: Build Master Sample Index
Creates the master registry matching APK files, hashes, package names, and target countries.
```powershell
python pipeline/build_sample_index.py --app-store google-play
```

### Stage 6: Static Manifest Analysis
Statically scans decoded manifest files for components, exported declarations, permissions, and network policies.
```powershell
python scan_manifest.py --input-dir decoded/ --output-dir output/manifest/ --sample-index sample_index.csv
```
*   **Key Flags:**
    *   `--input-dir`: Directory containing decompiled APK folders.
    *   `--output-dir`: Output directory for generated CSV reports.
    *   `--sample-index`: Master registry mapping file.

### Stage 7: CVE Vulnerability Matching
Matches embedded third-party library versions found in DEX files against public CVE vulnerability data.
```powershell
python cve/main.py --input-dir decoded/ --output-dir output/cve/ --sample-index sample_index.csv
```

### Stage 8: Live Traffic Collection (PCAP)
Installs APKs on a connected Android phone, runs Monkey UI simulation, captures network traffic using PCAPdroid, and pulls files to your PC.
```powershell
# Interactive Mode (Prompts for confirmation before installing/capturing each app)
python collect_pcap.py --capture-time 60 --monkey-events 500

# Fully Automated Mode (Runs all apps, skips already captured, non-interactive)
python collect_pcap.py --auto --skip-captured --capture-time 60 --monkey-events 500
```
*   **Key Flags:**
    *   `--auto`: Runs without y/n prompts per app (useful for overnight/headless runs).
    *   `--skip-captured`: Skips apps that already have a `.pcap` file in the output directory.
    *   `--capture-time`: Seconds to run PCAPdroid VPN capture (default: 60).
    *   `--monkey-events`: Number of random UI interactions executed (default: 500).
    *   `--country`: Filter to process apps matching a specific country code (e.g. `--country IN`).

### Stage 9: Traffic Parsing & Aggregation
Parses captured raw traffic PCAP files to resolve domains, ASN, geolocation coordinates, and known tracker categories.
```powershell
python run_pcap_analysis.py --input-dir data/pcap --output-dir output/pcap --sample-index sample_index.csv
```

---

## Running the Pipeline End-to-End

To run the entire pipeline end-to-end, execute the following commands sequentially in your PowerShell terminal:

```powershell
# Step 1: Prepare Ingestion lists
python pipeline/prepare_india_package_list.py
python pipeline/download_apks.py --packages data/package_lists/india_packages.txt --source google-play --limit 5
python pipeline/normalize_packages.py

# Step 2: Decompile and Index
python pipeline/decode_apks.py
python pipeline/build_sample_index.py --app-store google-play

# Step 3: Run Static Scanners (Manifest & CVE)
python scan_manifest.py --input-dir decoded/ --output-dir output/manifest/ --sample-index sample_index.csv
python cve/main.py --input-dir decoded/ --output-dir output/cve/ --sample-index sample_index.csv

# Step 4: Run Dynamic Capture (ADB Device must be connected)
python collect_pcap.py --auto --skip-captured --capture-time 60 --monkey-events 500

# Step 5: Process Captured Traffic
python run_pcap_analysis.py --input-dir data/pcap --output-dir output/pcap --sample-index sample_index.csv
```

---

## Verifying Pipeline Output

Once all stages complete, verify your `output/` directory structure matches:

```text
output/
├── manifest/
│   ├── manifest_components.csv
│   ├── manifest_permissions.csv
│   └── ...
├── cve/
│   ├── cve_matches.csv
│   └── ...
└── pcap/
    ├── pcap_connections.csv
    ├── pcap_dns.csv
    ├── pcap_domain_geo.csv
    ├── pcap_app_summary.csv
    └── pcap_trace.json
```
