# APK Acquisition & Pre-Processing Pipeline

This directory contains the automation scripts responsible for the first phase of the Geo-Difference Mobile Security project: curating target applications, automating APK acquisition, normalizing application formats, decoding bytecode, and establishing the foundational dataset index used by all downstream analysis engines.

The pipeline is designed for high-throughput, reproducible application processing across different app stores, package formats, and geographic markets.

---

## 1. Architectural Overview

The acquisition pipeline enforces a strict, linear flow of data from raw Google Play metadata to fully decoded, indexed applications ready for static analysis.

```text
    [Play Store Scraped Metadata]
               │
    1. Corpus Curation (e.g. prepare_package_list)
               │
               ▼
       data/package_lists/*.txt
               │
    2. download_apks.py (apkeep)
               │
               ▼
            apks/ (Raw .apk / .xapk)
               │
    3. normalize_packages.py
               │
               ▼
        normalized/ (Pure .apk files)
               │
    4. decode_apks.py (apktool)
               │
               ▼
         decoded/ (Smali / AndroidManifest.xml)
               │
    5. build_sample_index.py
               │
               ▼
        sample_index.csv (Pipeline Truth)
```

---

## 2. Pipeline Stages & Logic

### 2.1 Corpus Curation 
**Purpose:** Filters a global dataset of scraped Play Store metadata (`output/top_apps_full.csv`) down to a specific, unique target corpus for the configured market (e.g., a specific country code).
**Logic:**
- Filters rows strictly for the target market's `country_code` (e.g., `IN`, `US`, etc.).
- Sorts applications by `category_code` and `rank` to ensure analysis operates on the most popular apps in descending order.
- Deduplicates on `appId` (package name) to prevent redundant processing.
- Emits two artifacts to `data/package_lists/`: a plain-text target list for the downloader, and a rich metadata CSV used later by the network analysis engine to attribute country of origin.

### 2.2 Automated Acquisition (`download_apks.py`)
**Purpose:** Retrieves raw application binaries using [apkeep](https://github.com/EFForg/apkeep).
**Logic:**
- Supports downloading from multiple sources (`--source apk-pure` or `--source google-play`).
- **Google Play Mode:** Automates AAS token/email authentication via `--ini`, and utilizes `wsl` natively when executed on Windows (`os.name == "nt"`) to overcome strict pathing issues with Google Play split APKs. Forces `-o split_apk=true -r 1` for reliable, parallel-disabled downloads of split architectures.
- **Deduplication:** Checks the `apks/` directory before initiating a download. If a `.apk` or `.xapk` exists, it skips the network request.
- Logs successes to `logs/download_success.txt` and captures raw `apkeep` stdout/stderr into `logs/download.log` for failure triage.

### 2.3 Format Normalization (`normalize_packages.py`)
**Purpose:** Standardizes raw downloads into a uniform directory of standalone `.apk` files.
**Logic:**
- Modern app stores distribute apps as split APKs (`.xapk` or `.apks`). The static analyzer (specifically `apktool`) requires standard `.apk` files.
- **APK Path:** If the app downloaded as standalone `.apk` files, they are safely copied from `apks/` to `normalized/`.
- **XAPK Path:** If the app downloaded as a `.xapk` bundle, the script treats it as a standard ZIP archive (`zipfile.ZipFile`) and extracts its internal components (including the base APK and split configuration APKs) directly into the `normalized/` directory.

### 2.4 Bytecode Decoding (`decode_apks.py`)
**Purpose:** Unpacks the APK to retrieve the `AndroidManifest.xml` and disassemble Dalvik bytecode to Smali for static analysis.
**Logic:**
- Scans `normalized/` for the main APK file (explicitly ignoring files prefixed with `config.`, which represent split resources/architectures).
- Invokes `apktool` as a subprocess with strict JVM boundaries (`-Xmx1024M`) and ZIP handling flags (`-Djdk.util.zip.disableZip64ExtraFieldValidation=true`) to bypass anti-analysis protections designed to crash standard unzip utilities.
- Disassembles the APK into `decoded/<package_name>_decoded`.
- Implements robust error handling and timeout logging to ensure a single malformed APK does not crash the entire batch.

### 2.5 Index Generation (`build_sample_index.py`)
**Purpose:** Freezes the state of the acquired data into `sample_index.csv`, which serves as the canonical source of truth for all downstream engines (CVE mapping, PCAP aggregation, Manifest scanning).
**Logic:**
- **Verification:** An app is only considered "indexed" if its decoded directory exists AND it possesses an unpacked `AndroidManifest.xml`. Apps that failed `apktool` decompilation are silently skipped.
- **Cryptographic Hashing:** Computes the SHA-256 hash of the main APK in chunks (`65536` bytes) to guarantee file integrity and provide a cryptographic identifier for academic reproducibility.
- **Output:** Constructs the final `sample_index.csv` containing the `sample_id`, `package_name`, `apk_sha256`, `app_store`, and configured pathing/market metadata.
- **Concurrency Safety:** Implements a fallback write mechanism (`sample_index_fallback.csv`) in case the main CSV is locked by a researcher analyzing it in Excel during pipeline execution.

---

## 3. Execution Requirements

The pipeline requires several external binaries to function. Ensure these are configured correctly in the respective script constants:
1. **apkeep:** Set the path to the `apkeep` executable (or ensure it's inside a WSL `$PATH` if using Google Play on Windows).
2. **apktool:** Set the path to the `apktool.jar` archive.
3. **Java (JRE/JDK):** Required in system `$PATH` for `apktool` invocation.

All artifacts generated by these scripts are strictly placed in standard root-level directories (`apks/`, `normalized/`, `decoded/`) which are explicitly excluded from version control due to binary sizes.
