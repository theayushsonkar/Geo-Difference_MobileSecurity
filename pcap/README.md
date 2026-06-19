# PCAP Analysis Pipeline: Architecture, Logic, and Design Documentation

Welcome to the **PCAP Analysis Pipeline** for the Geo-Difference Mobile Security research project. This document serves as a comprehensive developer reference, explaining the technical architecture, data processing logic, output schemas, and the rationale behind key design choices.

---

## 1. Architectural Overview

The pipeline processes raw Android network capture files (`.pcap` / `.pcapng` files collected via tools like PCAPdroid) and transforms them into structured, statistically sound tabular datasets (`.csv`) ready for downstream cross-validation and analysis in tools like `pandas`, `scipy`, and `seaborn`.

### Data Flow Diagram

```text
Raw PCAP File
     │
     ▼
pcap_parser.py (dpkt parsing)
     │
     ├─► Raw TCP/UDP packets -> RawEvent streams
     └─► DNS Queries/Answers -> DNSRecord streams
     │
     ▼
tracker_matcher.py & constants.py (Tracker suffix matching & Canonicalization)
     │
     ▼
geoip.py (IP geolocation & ASN enrichment with single-caching)
     │
     ▼
connection_builder.py (Aggregation by 6-tuple key)
     │
     ├─► ConnectionRecord (Fact Table)
     └─► DomainGeoRecord (Fact Table)
     │
     ▼
app_summary.py (Metrics, country concentration, ASN metrics)
     │
     ▼
run_pcap_analysis.py (Coordinate runs, load metadata from sample_index.csv)
     │
     ├─► pcap_connections.csv
     ├─► pcap_dns.csv
     ├─► pcap_domain_geo.csv
     ├─► pcap_app_summary.csv
     └─► pcap_trace.json
```

---

## 2. Key Design Philosophies

### A. Facts-Only Principle (Zero Subjectivity)
Downstream security research relies on reproducible, unbiased data. To prevent subjective bias, **the pipeline does not generate arbitrary "risk scores", "privacy scores", or "threat ratings"**. Instead, it generates strict, dry fact tables (e.g., ports, payload sizes, exact countries, known tracker categories, and canonical vendor names) and leaves risk attribution to downstream models.

### B. Statistical Soundness
The pipeline preserves packet and connection counts alongside byte volumes (`payload_bytes_total`). This allows researchers to perform weight-based and frequency-based statistical tests (e.g., Chi-Square tests on country distribution or ANOVA on traffic volume by category) without losing data resolution.

---

## 3. Pipeline Stages & Logic

### A. Parser (`pcap_parser.py`)
*   **Purpose:** Read packet streams from a PCAP/PCAPNG file using `dpkt`.
*   **Logic:**
    *   Examines Link Layer headers (supporting both Ethernet and raw DLT_RAW IP headers).
    *   Walks TCP and UDP streams.
    *   Extracts application-layer headers:
        *   **DNS:** Extracts transaction IDs, query names, types, response codes, and resolves answer IP mappings.
        *   **HTTP:** Parses cleartext payload to extract the `Host` header.
        *   **TLS:** Walks the TLS record structure to find Handshake packets, parses the `ClientHello` message, and extracts the Server Name Indication (SNI) extension.
    *   Emits flat `RawEvent` dataclass streams (which include fields like `first_seen`, `is_tls`, `is_quic`, `is_dns`, `is_http`, `payload_bytes`).

### B. Tracker Matcher (`tracker_matcher.py` & `constants.py`)
*   **Purpose:** Map destination domains to known advertising, analytics, and utility SDKs.
*   **Logic:**
    *   Computes suffix matching against a curated database of rules.
    *   Enforces **Canonical Vendor Mapping**. Multiple SDK variations (e.g., `Google Ads`, `Google DV360`) are grouped under a single parent entity (e.g., `Google`). This enables accurate market-concentration research when comparing manifest-declared SDKs against actual network behavior.
    *   Filters out operating system and anti-analysis checks (e.g., connectivity check domains like `connectivitycheck.android.com` and captive portals) to prevent infrastructure traffic from skewing the results.

### C. GeoIP Mapper (`geoip.py`)
*   **Purpose:** Resolve geographic country codes, country names, Autonomous System Numbers (ASN), and organization names for destination IPs.
*   **Logic:**
    *   Queries geolocation endpoint APIs.
    *   Uses a **Unified Caching System**. By caching geolocations inside the `GeoMapper` object itself (and removing local builder-level caches), we avoid dual-source-of-truth bugs and prevent redundant external rate-limit triggers.

### D. Connection Builder (`connection_builder.py`)
*   **Purpose:** Aggregate thousands of raw network packets into logical communication streams.
*   **Logic:**
    *   Groups events into unique buckets based on a **6-Tuple Aggregation Key**:
        ```python
        (sample_id, session_id, domain, dst_ip, dst_port, protocol)
        ```
    *   Calculates summary statistics per bucket (e.g., total connections, payload bytes sum, start/end timestamps).
    *   Preserves critical protocol evidence flags (`is_tls`, `is_dns`, `is_http`, `is_quic`) to prevent attribution loss during aggregation.

### E. App Summary Builder (`app_summary.py`)
*   **Purpose:** Consolidate fact records into a high-level overview of a single app's network behavior.
*   **Logic:**
    *   **Country Concentration:** Computes concentration percentage metrics (e.g., top 1 country percentage, top 3 country percentage) **excluding private, local, or unknown ranges** (e.g., `10.x.x.x`, `192.168.x.x`, `172.16.x.x`, or `PRI`) to prevent routing hops and carrier NATs from skewing geographic results.
    *   **Protocol Distribution:** Evaluates distribution metrics based on the connections' protocol flags.

### F. Analysis Coordinator (`run_pcap_analysis.py`)
*   **Purpose:** Enforce pipeline execution across directories, load metadata, and write exports.
*   **Logic:**
    *   **Robust Metadata Enrichment**: Loads `sample_index.csv` using `pandas` and cleans white spaces from both headers and values. It maps the PCAP's filename stem (`sample_id`) to the index row to resolve the true `package_name` and `app_country_code`.
    *   If a lookup fails, it prints a clear warning (e.g., `No sample_index entry found for sample_id=...`) instead of silently falling back.
    *   **Deterministic Session ID**: Enforces that each sample is isolated into its own session string (e.g., `{sample_id}_session_1`) to prevent data leakage across different app runs.

---

## 4. Output Schemas & Specification

Every run of the pipeline produces five outputs in the target folder:

### 1. `pcap_connections.csv`
Contains the facts of each aggregated connection stream.

| Field | Type | Description |
| :--- | :--- | :--- |
| `run_id` | String | Unique UUID for the run. |
| `sample_id` | String | Unique identifier of the APK sample. |
| `package_name` | String | Enriched app package name. |
| `app_country_code` | String | Country code of the market where the app was collected. |
| `session_id` | String | Unique run session identifier (`{sample_id}_session_1`). |
| `domain` | String | Destination hostname (resolved or queried). |
| `dst_ip` | String | Destination IP address. |
| `dst_port` | Integer | Destination port. |
| `protocol` | String | Transport protocol (`TCP` or `UDP`). |
| `discovery_source` | String | Method used to resolve the domain (`dns_query`, `http_host`, `tls_sni`, `quic`, or `unknown`). |
| `payload_bytes_total` | Integer | Total payload bytes transferred (excluding header overhead). |
| `is_tls` | Boolean | True if TLS handshake evidence was observed. |
| `is_quic` | Boolean | True if QUIC protocol traffic was observed. |
| `is_dns` | Boolean | True if DNS protocol traffic was observed. |
| `is_known_tracker` | Boolean | True if domain matches the tracker database. |
| `canonical_vendor` | String | Parent vendor name (e.g., `Google`, `Facebook`, `Liftoff`). |
| `ip_country_code` | String | Two-letter country code of the hosting destination. |
| `ip_asn_org` | String | ISP/Organization owning the destination IP block. |

### 2. `pcap_dns.csv`
Tracks individual DNS transactions to allow analysis of resolution delays, DNS hijacking, and CNAME cloaking.

| Field | Type | Description |
| :--- | :--- | :--- |
| `sample_id` | String | Unique identifier of the APK sample. |
| `query_name` | String | Domain name queried. |
| `query_type` | String | DNS Record type (e.g., `A`, `AAAA`, `TXT`). |
| `resolver_ip` | String | DNS Server IP address. |
| `response_ips` | String | Pipe-delimited (`\|`) string of returned IP addresses. |
| `response_count` | Integer | Number of IP addresses returned in the answer. |
| `is_hardcoded_resolver` | Boolean | True if query bypassed local settings to query public servers (e.g. Google `8.8.8.8`). |

### 3. `pcap_domain_geo.csv`
A lightweight, deduped look-up table containing domain-to-IP-to-country associations to mapping geo-distribution.

### 4. `pcap_app_summary.csv`
App-level aggregates of network exposure, protocol distribution, and tracker counts.

| Field | Type | Description |
| :--- | :--- | :--- |
| `sample_id` | String | Unique identifier of the APK sample. |
| `package_name` | String | App package name. |
| `app_country_code` | String | Sourced market country code. |
| `total_connection_records` | Integer | Number of rows in `pcap_connections.csv` for this app. |
| `total_payload_bytes` | Integer | Total payload bytes transferred. |
| `tls_connection_count` | Integer | Total TLS-derived connection occurrences. |
| `http_connection_count` | Integer | Total cleartext HTTP connection occurrences. |
| `country_top1_code` | String | Code of the country hosting the largest percentage of connections (excluding `PRI`). |
| `country_top1_pct` | Float | Percentage of connections hosted by the top country. |
| `tracker_domain_count` | Integer | Number of unique tracker domains contacted. |
| `tracker_vendor_count` | Integer | Number of unique tracker vendors contacted. |

### 5. `pcap_trace.json`
Maintains reproducibility metrics of the pipeline run. It documents execution timestamp, processed file counts, database versions (GeoIP and Trackers), processing time, and a structured array of any processing errors (e.g. corrupted PCAP structures) encountered during execution.

---

## 5. Rationale Behind Core Correctness Decisions

### A. Why is `discovery_source` prioritized?
Domain attribution can be ambiguous. To ensure academic validity, the pipeline applies a strict priority mapping:
1.  `dns_query` (Highest Priority) — If the domain was resolved via raw DNS queries, it represents direct resolution.
2.  `http_host` — Extracted from cleartext `Host` headers in HTTP streams.
3.  `tls_sni` — Extracted from encrypted client requests during handshakes.
4.  `quic` — Extracted from QUIC packet payloads.
5.  `unknown` — Reverted to only if no protocol-layer evidence is present.

### B. Why was `https_count` replaced by `tls_connection_count`?
Calculating encrypted web traffic by subtracting `http_count` from `tcp_count` is statistically invalid because TCP traffic includes non-HTTP protocols (e.g., SMTP, SSH, custom sockets). We now compute `tls_connection_count` using explicit TLS ClientHello SNI handshakes.

### C. Why are local IPs excluded from country statistics?
Private IP addresses (e.g., local DNS resolvers or captive portals) resolve to `PRIVATE` or `PRI` countries. If included in top-country metrics, they artificially inflate the concentration value of the local market, corrupting the analysis. Filtering them out ensures that only remote hosting locations skew the concentration values.

---

## 6. How to Run & Validate

### Running the Analysis Pipeline
Place your target `.pcap` files inside `data/pcap`, register your apps in `sample_index.csv`, and run:
```powershell
python run_pcap_analysis.py --input-dir data/pcap --output-dir output/pcap --sample-index sample_index.csv
```

### Running Unit/Integration Tests
Consolidated unit tests reside inside the `tests/` directory. To run all unit tests:
```powershell
python -m unittest discover -s tests
```
