# Data Directory Overview

This directory acts as the central staging area for both static reference datasets and dynamic, run-specific inputs used throughout the offline analysis pipeline. 

> [!IMPORTANT]
> **Version Control Policy:** Only the `nvd/` directory is committed to the repository, as it contains immutable vulnerability definitions. The `package_lists/` and `pcap/` directories contain dynamic, per-run datasets and are explicitly excluded from version control.

```text
data/
├── nvd/               [STATIC] NVD CVE annual feeds (2002–2026), compressed archives
├── package_lists/     [DYNAMIC] The curated app corpus for the current pipeline run
└── pcap/              [DYNAMIC] Per-app raw network captures for the current run
```

---

## 1. NVD Vulnerability Feeds (`nvd/`) 
*(Static Reference Data)*

### 1.1 Source & Format
The National Vulnerability Database (NVD), maintained by NIST, distributes the complete CVE catalog as annual JSON 2.0 feeds. Each feed is compressed into a ZIP archive and named by year:

```
nvdcve-2.0-YYYY.json.zip
```

The archive contains a single JSON file structured as:
```json
{
  "vulnerabilities": [
    { "cve": { "id": "CVE-...", "metrics": {...}, "configurations": [...] } },
    ...
  ]
}
```

### 1.2 Coverage
The local snapshot spans **annual feeds from 2002 through 2026**, providing full historical coverage of the CVE catalog. Total uncompressed data exceeds several gigabytes; the compressed archives range from ~730 KB (2003) to ~20 MB (2024–2025), reflecting the year-on-year growth in disclosed vulnerabilities.

### 1.3 Consumption
The `cve/nvd_loader.py` module reads these archives **in-memory via `zipfile.ZipFile`** — no pre-extraction step is required or performed. Each CVE entry is parsed into a `CVERecord` dataclass capturing: CVE ID, publication and modification dates, CVSS score (v3.1/v3.0/v2.0 priority ladder), CPE-derived vendor/product fields, and structured version range constraints (`versionStartIncluding`, `versionEndExcluding`, etc.).

---

## 2. Application Corpus (`package_lists/`)
*(Dynamic Run Data)*

### 2.1 Purpose
This directory defines the **target application population** for a specific execution of the pipeline. The contents of this directory change depending on the scope of the current research experiment (e.g., analyzing a specific country market, category, or time period).

### 2.2 Files

#### `<target_name>_packages.txt`
A plain-text list of Android package identifiers (one per line), used as direct input to APK download and decoding stages. Each line is a fully qualified package name (e.g., `com.example.app`).

#### `<target_name>_packages_metadata.csv`
A structured CSV providing rich provenance metadata for each app in the corpus. While the number of entries fluctuates per run, the schema remains consistent:

| Column | Description |
|---|---|
| `country_code` | ISO 3166-1 alpha-2 market code (e.g., `in`, `us`) |
| `country_name` | Human-readable market name |
| `category_code` | Google Play category identifier (e.g., `EDUCATION`) |
| `category_name` | Human-readable category label |
| `rank` | Play Store rank within the category at time of scraping |
| `appId` | Fully qualified Android package name |
| `title` | App display name |
| `developer` | Developer or publisher entity |
| `publisherCountry` | Declared country of the developer/publisher |
| `installs` | Install count bucket from Play Store (e.g., `10,000,000+`) |
| `score` | Average user rating (0–5) |
| `appUrl` | Canonical Play Store listing URL |

---

## 3. Network Captures (`pcap/`)
*(Dynamic Run Data)*

### 3.1 Purpose
This directory stores raw packet captures (PCAP format) recorded during dynamic analysis. The number of captures varies based on the size of the corpus defined in `package_lists/`.

### 3.2 File Naming Convention
Files follow the pattern:

```
<package_name>_<country_code>.pcap
```

For example:
- `com.example.app_in.pcap` — Captured from an Indian market context.
- `com.example.app_unknown.pcap` — Country context unresolved at capture time.

### 3.3 Coverage
The directory size and file count scale linearly with the experimental corpus. File sizes range from a few KB (minimal-traffic apps or failed sessions) to tens of megabytes, reflecting significant variation in session duration and data transfer intensity. Files with no traffic usually represent captures where the app produced no network activity during the recording window (e.g., fully offline apps or apps that failed to launch).

### 3.4 Execution Trace (`collect_trace.json`)
The `collect_trace.json` file is a machine-generated run metadata artifact produced by the PCAP collection harness. It records capture timestamps, per-app collection status, device identifiers, and any error codes encountered during the batch session. It is used for reproducibility verification and is **not consumed by any analysis module**; it serves as an audit log for the data collection phase.

### 3.5 Consumption
PCAP files are consumed by the network analysis module, which parses raw frames to extract:
- **TLS SNI fields** — identifying contacted hostnames before encryption.
- **DNS query names** — mapping app behavior to domain-level network destinations.
- **HTTP Host headers** — for unencrypted connections.

These are subsequently aggregated into per-app domain contact lists and cross-referenced against known tracker network signatures from the SDK detection enrichment phase.
