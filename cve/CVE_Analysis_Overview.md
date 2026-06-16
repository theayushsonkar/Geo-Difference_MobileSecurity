# CVE Analysis Module

## Overview

The CVE Analysis module identifies known vulnerabilities in Android applications by matching detected SDK versions against vulnerability information extracted from the National Vulnerability Database (NVD).

The module operates entirely on SDK metadata produced during earlier analysis stages and does not inspect APKs directly.

Its primary responsibilities are:

- Load and parse NVD CVE datasets directly from compressed ZIP archives.
- Extract affected products and vulnerable version ranges.
- Match detected SDK versions against vulnerable versions using a product-only candidate lookup layer.
- Record confirmed SDK ↔ CVE matches.
- Record skipped SDKs and matching coverage.
- Produce application-level vulnerability summaries.
- Generate execution trace metadata.

---

## Running the Analysis

### 1. Prerequisites
Ensure you have the following directory structure and files in place:
1. **NVD Archives**: Store NVD zip archives under `data/nvd/` (e.g. `nvdcve-2.0-2020.json.zip`, `nvdcve-2.0-2021.json.zip`, etc.).
2. **SDK Inputs**: Ensure the SDK metadata file `output/manifest_sdks.csv` exists and contains the analyzed applications' SDK version details (with columns: `sample_id`, `package_name`, `sdk_name`, `sdk_identifier`, `sdk_version`).
3. **Dependencies**: Ensure the environment has `pandas` and `packaging` packages installed.

### 2. Execution Command
Run the main pipeline from the workspace root directory:

```bash
python -m cve.main
```

---

# High-Level Workflow

```text
output/manifest_sdks.csv
        │
        ▼
Load SDK Records
        │
        ▼
Load NVD Dataset (data/nvd/*.zip)
        │
        ▼
Build Search Indexes (Product Index Only)
        │
        ▼
Generate SDK Search Tokens (Clean & Split)
        │
        ▼
Expand Tokens Using Alias Mapping (SDK_ALIASES)
        │
        ▼
Find Candidate CVEs (product_index only)
        │
        ▼
Apply Version Filtering (version_in_range)
        │
        ▼
Generate CVE Matches (Deduplicated)
        │
        ▼
Generate Coverage Report (no_version, parse_error, no_nvd_entry)
        │
        ▼
Generate App Summary (Aggregated Counts)
        │
        ▼
Generate Trace Metadata (cve_trace.json)
```

---

# Input Data

## SDK Input

The module consumes:

```text
output/manifest_sdks.csv
```

Required columns:

- `sample_id`: Identifier of the analyzed application.
- `package_name`: The application's package name.
- `sdk_name`: Human-readable name of the SDK.
- `sdk_identifier`: The unique SDK identifier (e.g. Maven coordinate).
- `sdk_version`: The detected version string of the SDK.
- `sdk_version_source`: Source of the version detection.
- `sdk_version_confidence`: Confidence level of the version detection.

Example:

```csv
sample_id,package_name,sdk_name,sdk_identifier,sdk_version,sdk_version_source,sdk_version_confidence
app1,com.example,Firebase,com.google.firebase:firebase-common,19.0.0,buildconfig,high
app1,com.example,AppLovin MAX,com.applovin,4.3.0.1,buildconfig,high
```

---

## NVD Input

NVD files are stored under:

```text
data/nvd/
```

Example files:

```text
nvdcve-2.0-2020.json.zip
nvdcve-2.0-2021.json.zip
...
nvdcve-2.0-2026.json.zip
```

The loader reads JSON directly from ZIP archives dynamically. No manual extraction step is required.

---

# Module Structure

```text
cve/
├── __init__.py
├── schemas.py
├── nvd_loader.py
├── versioning.py
├── matcher.py
├── aggregator.py
├── trace.py
└── main.py
```

---

# schemas.py

Defines the canonical, strongly-typed data structures used in the CVE matching pipeline. All classes use `slots=True` for memory optimization.

---

## SDKRecord

Represents one SDK entry loaded from `manifest_sdks.csv`.

```python
@dataclass(slots=True)
class SDKRecord:
    sample_id: str
    package_name: str
    sdk_name: str
    sdk_identifier: str
    sdk_version: str | None
    sdk_version_source: str | None
    sdk_version_confidence: str | None
```

---

## CVERecord

Represents one vulnerability extracted from NVD. A single CVE may generate multiple CVERecord objects if it affects multiple vendor/product combinations.

```python
@dataclass(slots=True)
class CVERecord:
    cve_id: str
    published_date: str | None
    last_modified_date: str | None
    cvss_version: str | None
    cvss_score: float | None
    severity: str | None
    cvss_vector: str | None
    vendor: str | None
    product: str | None
    version_ranges: list[dict]
```

---

## CVEMatch

Represents a confirmed SDK vulnerability match. Writes out to `output/sdk_cve_matches.csv`.

```python
@dataclass(slots=True)
class CVEMatch:
    sample_id: str
    package_name: str
    sdk_name: str
    sdk_identifier: str
    sdk_version: str
    cve_id: str
    published_date: str | None
    last_modified_date: str | None
    cvss_version: str | None
    cvss_score: float | None
    severity: str | None
    cvss_vector: str | None
    affected_version_range: str | None
    nvd_snapshot_date: str
```

---

## CoverageRecord

Represents SDKs that could not be matched or were skipped. Writes out to `output/cve_coverage_report.csv`.

```python
@dataclass(slots=True)
class CoverageRecord:
    sample_id: str
    sdk_name: str
    sdk_identifier: str
    sdk_version: str | None
    skip_reason: str
```

---

# nvd_loader.py

Handles finding, loading, parsing, and indexing of reference NVD vulnerability datasets.

### Step 1: Discover NVD Files
Recursively searches `data/nvd/` for `*.zip` archives.

### Step 2: Load JSON From ZIP
Uses `zipfile.ZipFile` to load JSON content dynamically in-memory without extracted files on disk.

### Step 3: Parse CVE Metadata
Retrieves CVE identifiers, dates, and CVSS information. The CVSS parser prioritizes CVSS v3.1, falls back to v3.0, and lastly v2.0.

### Step 4: Parse Affected Products
Standardizes CPE 2.3 criteria (e.g. `cpe:2.3:a:google:firebase_android_sdk:*`) into distinct `vendor` and `product` components.

### Step 5: Extract Version Constraints
Extracts boundary properties (`versionStartIncluding`, `versionStartExcluding`, `versionEndIncluding`, `versionEndExcluding`) and maps them to `version_ranges`.

### Step 6: Indexing
Constructs two fast-lookup indices:
- `vendor`: maps vendor tokens to matching CVERecords.
- `product`: maps product tokens to matching CVERecords (currently the only driver of candidate retrieval).

---

# versioning.py

Handles version parsing and evaluation logic using `packaging.version.Version`.

### parse_version_safe(ver_str)
Safely parses version strings. Invalid/unsupported formats return `None` (rather than crashing the pipeline).

### version_in_range(...)
Evaluates a target SDK version against specific boundary conditions:
- `version_start_including` / `version_start_excluding`
- `version_end_including` / `version_end_excluding`

### has_real_version_constraints(version_ranges)
Helper to filter out CVEs lacking concrete version intervals. Range structures such as `[]`, `[{}]`, or dictionary inputs containing no boundary keys are rejected.

### matches_any_range(sdk_version, version_ranges)
Evaluates if the target version matches at least one valid range boundary within the range list.

---

# matcher.py

Coordinates the core matching logic.

## Token Cleanup and Extraction

Tokens are extracted from `sdk_identifier` and `sdk_name` using `_extract_search_tokens()`:
- Splits on colons (`:`), dots (`.`), spaces, and slashes (`/`).
- Generates variations swapping hyphens (`-`) and underscores (`_`).
- Filters out generic stopwords: `{"google", "android", "play", "sdk", "library", "common", "core", "mobile", "client", "ads"}`.
- Ignores domain prefixes: `{"com", "org", "net", "edu", "gov", "mil", "io", "co", "squareup", "unity3d"}`.

## Alias Mapping Layer

To align custom/third-party Maven coordinates with official NVD product entries, a lightweight alias dictionary `SDK_ALIASES` is applied:

```python
SDK_ALIASES = {
    "com.google.firebase": ["firebase", "firebase_android_sdk"],
    "com.google.android.gms": ["google_play_services", "play_services"],
    "com.facebook": ["facebook", "facebook_android_sdk", "android_sdk"],
    "com.squareup.okhttp3": ["okhttp"],
    "com.squareup.retrofit2": ["retrofit"],
    "com.google.code.gson": ["gson"],
    "com.unity3d.ads": ["unity", "unity_ads"],
    "com.applovin": ["applovin"],
    "com.bytedance.sdk": ["pangle", "bytedance"],
    "com.mbridge": ["mbridge", "mintegral"]
}
```

If the SDK's `sdk_identifier` begins with any alias key, the associated alias words are appended to the search tokens.

## Matching Algorithm

For each SDK record:
1. **Validate & Parse Version**: If missing, skip with `no_version`. If invalid, skip with `parse_error`.
2. **Generate and Expand Tokens**: Extracts and expands tokens using alias rules.
3. **Lookup Candidates**: Queries only `product_index` with tokens. Vendor index lookups are completely bypassed to eliminate broad false positives. Deduplicates candidates via `(cve_id, vendor, product)`.
4. **Apply Strict Version Constraints**: Only emits matches if the candidate has real version constraints and `matches_any_range()` returns `True`.
5. **Deduplication**: Resulting matches are deduplicated via `(sample_id, sdk_identifier, cve_id)`.
6. **Coverage Log**: If no matches are found, logs a `CoverageRecord` with `no_nvd_entry`.

---

# aggregator.py

Aggregates individual `CVEMatch` objects into application-level metrics:
- `total_cve_matches`: Total matches generated.
- `unique_cve_count`: Count of unique CVE IDs.
- `affected_sdk_count`: Count of unique vulnerable SDKs.
- `nvd_snapshot_date`: Output generation date.

Writes output to `output/app_cve_summary.csv` grouped by `sample_id`.

---

# trace.py

Writes execution metadata to `output/cve_trace.json`. Consists of:
- `run_timestamp`: ISO-8601 UTC timestamp.
- `nvd_snapshot_date`: Execution date.
- `sdk_rows_processed`: Count of processed SDKs.
- `sdk_rows_skipped`: Count of skipped SDKs.
- `sdk_rows_matched`: Count of matched SDKs.
- `unique_cves_found`: Count of unique CVE IDs identified.

---

# main.py

Coordinates the execution of the entire CVE matching pipeline:
1. Loads NVD reference datasets and builds indices.
2. Reads detected SDK records from `output/manifest_sdks.csv`.
3. Invokes the matching engine in `matcher.py`.
4. Alphabetically sorts matches by `(sample_id, sdk_identifier, cve_id)` and writes to `output/sdk_cve_matches.csv`.
5. Alphabetically sorts skipped entries by `(sample_id, sdk_identifier)` and writes to `output/cve_coverage_report.csv`.
6. Invokes the aggregator to produce app-level summaries and writes to `output/app_cve_summary.csv`.
7. Builds and writes trace statistics to `output/cve_trace.json`.

---

# Output Files

### output/sdk_cve_matches.csv
Contains confirmed SDK-to-CVE matches sorted alphabetically.

### output/cve_coverage_report.csv
Maintains list of skipped or non-matching SDKs.

### output/app_cve_summary.csv
Summarizes total vulnerabilities at the app level.

### output/cve_trace.json
Contains execution statistics and timestamps.

---

# Extension Points

The CVE pipeline is built to easily accommodate future extensions:
- **Expanded Alias Lists**: Add extra package mappings directly to `SDK_ALIASES`.
- **Alternative Vulnerability Feeds**: Integrate OSV (Open Source Vulnerability) JSON structures or custom vulnerability datasets.
- **Advanced Scoring**: Incorporate risk, severity, or EPSS scores into matched CVE outputs.
