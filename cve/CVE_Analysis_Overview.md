# CVE Vulnerability Mapping Engine

This module implements a deterministic, offline vulnerability mapping engine for Android applications. It bridges the semantic gap between detected third-party Software Development Kits (SDKs) — sourced from the manifest analysis stage — and structured vulnerability records from the National Vulnerability Database (NVD). Operating exclusively on extracted SDK metadata (`output/manifest_sdks.csv`), the engine cross-references detected library version strings against CPE-based version constraints to identify known Common Vulnerabilities and Exposures (CVEs) without requiring re-analysis of the underlying APKs.

---

## 1. Architectural Overview

The mapping engine is a composable, memory-efficient pipeline orchestrating five sequential phases. Each phase is implemented as an isolated module with strict, typed interfaces defined in `schemas.py`.

```text
┌─────────────────────────────────────────┐
│       Extracted SDK Metadata            │ (output/manifest_sdks.csv)
│  sample_id, sdk_identifier, sdk_version │
└────────────────┬────────────────────────┘
                 │
         ┌───────▼───────┐
         │ NVD Ingestion │  nvd_loader.py
         │ & Indexing    │  ──► ZIP → JSON → CVERecord → product_index
         └───────┬───────┘
                 │ dict: product_token → [CVERecord]
         ┌───────▼──────────────┐
         │ Tokenization &       │  matcher.py
         │ Alias Expansion      │  ──► stopwords stripped, SDK_ALIASES injected
         └───────┬──────────────┘
                 │ set[str] tokens
         ┌───────▼────────────────┐
         │ Candidate Lookup &     │  matcher.py + versioning.py
         │ Version Constraint     │  ──► product_index only, packaging.version
         │ Resolution             │
         └───────┬────────────────┘
                 │ list[CVEMatch] + list[CoverageRecord]
        ┌────────▼──────────────┐
        │ Application-Level     │  aggregator.py
        │ Aggregation           │  ──► groupby sample_id → summary metrics
        └────────┬──────────────┘
                 │
         ┌───────▼────────┐
         │ Trace & Output │  trace.py + main.py
         │ Serialization  │  ──► sdk_cve_matches.csv, cve_coverage_report.csv,
         └────────────────┘       app_cve_summary.csv, cve_trace.json
```

---

## 2. Data Schemas (`schemas.py`)

All pipeline data flows through four strongly-typed `@dataclass(slots=True)` structures. The `slots=True` annotation reduces per-instance memory overhead, which is critical when processing tens of thousands of CVE records.

| Schema | Source | Destination |
|---|---|---|
| `SDKRecord` | `manifest_sdks.csv` | Input to matcher |
| `CVERecord` | NVD JSON feed | Built by `nvd_loader`, consumed by `matcher` |
| `CVEMatch` | Verified version match | `sdk_cve_matches.csv` |
| `CoverageRecord` | Skipped/unmatched SDKs | `cve_coverage_report.csv` |

**`CVERecord`** is the most structurally complex. A single NVD CVE entry can affect multiple `(vendor, product)` pairs, each with its own version range boundaries. The loader therefore emits *one `CVERecord` per `(vendor, product)` pair*, meaning a single CVE-ID can produce several records in the index. The `version_ranges` field is a `list[dict]` where each dict may hold up to four NVD boundary keys:

```python
{
    "versionStartIncluding": "20.0.0",  # >= 20.0.0
    "versionEndExcluding":   "21.5.2"   # <  21.5.2
}
```

---

## 3. NVD Ingestion & Indexing (`nvd_loader.py`)

### 3.1 Zero-Extraction ZIP Loading
The NVD distributes vulnerability data as paginated, annual JSON feeds compressed into ZIP archives (`nvdcve-2.0-YYYY.json.zip`). To avoid unnecessary disk writes, `load_nvd()` reads JSON streams **directly from ZIP archives in memory** using `zipfile.ZipFile`, requiring no prior extraction step.

### 3.2 CVSS Normalization
NVD records can carry metrics in CVSS v2.0, v3.0, or v3.1 format. The `_extract_cvss()` function enforces a strict priority ladder:

```
cvssMetricV31 > cvssMetricV30 > cvssMetricV2
```

Within each version tier, `Primary` metrics are preferred over `Secondary` when multiple assessors have scored the same CVE.

### 3.3 CPE 2.3 Parsing
Every affected product is encoded in a CPE 2.3 URI (e.g., `cpe:2.3:a:google:firebase_android_sdk:*`). The `_parse_cpe_criteria()` function tokenizes the URI on `:`, accounts for escaped colons (`\:`), and extracts the `vendor` (index 3) and `product` (index 4) components. Wildcards (`*`) are discarded.

### 3.4 Version Range Extraction
For each CPE match entry, the parser selectively extracts only the four recognized NVD boundary keys (`versionStartIncluding`, `versionStartExcluding`, `versionEndIncluding`, `versionEndExcluding`). These are grouped by `(vendor, product)` and stored as the `version_ranges` list on the emitted `CVERecord`.

### 3.5 Inverted Index Construction (`build_indexes`)
`build_indexes()` compiles the parsed record list into two `defaultdict(list)` maps:

- **`vendor_index`**: `vendor_token → [CVERecord]` — built but intentionally **not queried** at match time to prevent overly broad false positives (e.g., the token `"google"` matching thousands of unrelated records).
- **`product_index`**: `product_token → [CVERecord]` — the **sole driver** of candidate retrieval at match time.

---

## 4. Token Expansion & Alias Mapping (`matcher.py`)

### 4.1 The Semantic Gap Problem
A fundamental challenge in vulnerability mapping is the *terminology mismatch* between the Android software supply chain and the NVD. Maven coordinates (e.g., `com.google.android.gms:play-services-auth:20.4.1`) bear no resemblance to the NVD product names that curators assign (e.g., `play_services`). Raw tokenization of the Maven coordinate would yield fragments like `"play"`, `"services"`, `"auth"` — all of which are stopwords that convey no discriminative signal.

### 4.2 Tokenization & Stopword Stripping (`_extract_search_tokens`)
Tokens are extracted from both `sdk_identifier` and `sdk_name` by splitting on four delimiters (`.`, `:`, ` `, `/`). Hyphenated and underscored fragments are additionally decomposed. Two filter sets are applied:

- **Domain prefixes** (discarded): `{"com", "org", "net", "edu", "gov", "mil", "io", "co", "squareup", "unity3d"}`
- **Semantic stopwords** (discarded): `{"google", "android", "play", "sdk", "library", "common", "core", "mobile", "client", "ads"}`

Tokens that survive both filters are normalized to lowercase and deduplicated into a `set[str]`. Hyphen/underscore variants are also emitted (e.g., `"firebase-android"` → `"firebase_android"`) to handle NVD naming inconsistencies.

### 4.3 Alias Injection (`SDK_ALIASES`)
Stopword filtering alone cannot reconstruct the idiomatic NVD product names. The `SDK_ALIASES` dictionary provides explicit prefix-keyed mappings that inject known NVD-compatible tokens:

```python
SDK_ALIASES = {
    "com.google.firebase":       ["firebase", "firebase_android_sdk"],
    "com.google.android.gms":    ["google_play_services", "play_services"],
    "com.facebook":              ["facebook", "facebook_android_sdk", "android_sdk"],
    "com.squareup.okhttp3":      ["okhttp"],
    "com.squareup.retrofit2":    ["retrofit"],
    "com.google.code.gson":      ["gson"],
    "com.unity3d.ads":           ["unity", "unity_ads"],
    "com.applovin":              ["applovin"],
    "com.bytedance.sdk":         ["pangle", "bytedance"],
    "com.mbridge":               ["mbridge", "mintegral"],
}
```

`_expand_tokens_with_aliases()` performs a prefix scan: if `sdk_identifier.startswith(key)`, the associated alias list is merged into the token set. This is a O(|SDK_ALIASES|) operation per SDK record.

---

## 5. Candidate Lookup & Version Constraint Resolution

### 5.1 Product-Only Index Lookup (`_find_candidate_cves`)
With the expanded token set, the matcher queries **only `product_index`**. For each token, the corresponding list of `CVERecord` objects is retrieved and merged into a deduplicated dict keyed on `(cve_id, vendor, product)` to prevent double-counting.

The vendor index is deliberately bypassed. Querying it would cause a single token like `"firebase"` to also match every CVE attributed to any Google product, producing thousands of irrelevant candidates.

### 5.2 Version Constraint Evaluation (`versioning.py`)

**Pre-flight guard — `has_real_version_constraints()`**: Before any numerical comparison, the engine checks that at least one of the four boundary keys exists in the candidate's `version_ranges`. CVEs with empty or boundary-free range structures (e.g., `[{}]`) are unconditionally rejected. This guard prevents matching on catch-all CVEs that affect "all versions" without specifying bounds.

**Numerical evaluation — `version_in_range()`**: Uses `packaging.version.Version` for PEP 440-compatible comparison, supporting multi-part version strings (e.g., `20.4.1`, `3.12.0.0`). The function maps the four NVD boundary keys to four comparison operators:

| NVD Key | Operator |
|---|---|
| `versionStartIncluding` | `>=` |
| `versionStartExcluding` | `>` |
| `versionEndIncluding` | `<=` |
| `versionEndExcluding` | `<` |

Missing boundaries are treated as unbounded (no constraint in that direction). An unparseable boundary string on the NVD side causes the range to be discarded (returns `False`), preventing a malformed NVD record from generating a spurious match.

**Multi-range disjunction — `matches_any_range()`**: A single CVE can specify multiple disjoint vulnerable ranges (e.g., `>=1.0 <2.0` OR `>=3.0 <4.0`). The function iterates over all ranges and returns `True` on the first match, implementing short-circuit OR evaluation.

**Safe version parsing — `parse_version_safe()`**: Version strings from the SDK extraction phase may contain non-standard formats or trailing noise. Rather than raising `InvalidVersion`, the function catches all exceptions and returns `None`, triggering a `parse_error` coverage record for that SDK row.

### 5.3 Match Deduplication
Confirmed matches are deduplicated by a three-tuple key `(sample_id, sdk_identifier, cve_id)` tracked in a `seen_matches` set. This prevents duplicate rows in the output CSV when the same SDK-CVE pair is confirmed by multiple product tokens hitting the same `CVERecord`.

---

## 6. Coverage Audit & Output

Every SDK record entering the matcher is guaranteed to produce exactly one outcome, ensuring 100% input accountability:

| Outcome | Condition | Output |
|---|---|---|
| `no_version` | `sdk_version` is null or empty | `CoverageRecord(skip_reason="no_version")` |
| `parse_error` | `packaging` cannot parse the version string | `CoverageRecord(skip_reason="parse_error")` |
| `no_nvd_entry` | No candidate passes version constraints | `CoverageRecord(skip_reason="no_nvd_entry")` |
| Confirmed match | Version falls within at least one NVD range | `CVEMatch` row |

### Output Files

| File | Content |
|---|---|
| `output/sdk_cve_matches.csv` | Verified SDK↔CVE matches, sorted by `(sample_id, sdk_identifier, cve_id)` |
| `output/cve_coverage_report.csv` | All skipped SDKs with their skip reason |
| `output/app_cve_summary.csv` | Per-application aggregates: `total_cve_matches`, `unique_cve_count`, `affected_sdk_count` |
| `output/cve_trace.json` | Run metadata: timestamp, snapshot date, processed/skipped/matched counts |

---

## 7. Application-Level Aggregation (`aggregator.py`)

`generate_app_summary()` converts `list[CVEMatch]` into a `pandas.DataFrame` grouped by `sample_id`. Three metrics are computed:

- **`total_cve_matches`**: Raw count of all match rows for the application.
- **`unique_cve_count`**: `nunique` on `cve_id` — removes inflation from multiple SDK records hitting the same CVE.
- **`affected_sdk_count`**: `nunique` on `sdk_identifier` — the number of distinct vulnerable library coordinates.

Results are sorted ascending by `sample_id` for deterministic output ordering.

---

## 8. Execution Interface

The engine is invoked as a zero-configuration pipeline from the workspace root. With `output/manifest_sdks.csv` and `data/nvd/*.zip` in place:

```bash
python -m cve.main
```

---

## 9. Extension Points

The modular design isolates each concern, enabling targeted extension without pipeline-wide changes:

- **Expanded Alias Coverage**: Add new `sdk_identifier` prefix → NVD product token mappings to `SDK_ALIASES` in `matcher.py`.
- **Alternative Vulnerability Feeds**: OSV (Open Source Vulnerability) JSON schemas or custom internal datasets can be integrated by implementing a new loader that emits `CVERecord` objects and passes them to `build_indexes()`.
- **Advanced Risk Scoring**: EPSS scores or custom severity weights can be appended directly to `CVEMatch` fields in `schemas.py` and serialized by `main.py`.
