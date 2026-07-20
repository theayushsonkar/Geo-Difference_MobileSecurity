# PCAP Network Analysis Engine

This module implements a deterministic, offline network traffic analysis engine for Android applications. It processes raw PCAP captures — collected during controlled dynamic execution of each APK — and transforms them into structured, statistically reproducible fact tables for downstream cross-country and cross-category analysis.

The pipeline operates exclusively on packet captures and a sample index; it does not re-analyze the underlying APKs.

---

## 1. Architectural Overview

```text
data/pcap/<package_name>_<cc>.pcap
             │
    ┌────────▼────────┐
    │  pcap_parser.py │  dpkt — raw IPv4/TCP/UDP frame decoding
    │  (RawEvent)     │  DNS, TLS SNI, HTTP Host, QUIC extraction
    └────────┬────────┘
             │ list[RawEvent]
    ┌────────▼──────────────┐
    │  connection_builder.py│  6-tuple aggregation
    │  (ConnectionBuilder)  │  Tracker enrichment, GeoIP, tldextract
    └────────┬──────────────┘
             │ BuildResult
             │  ├── list[ConnectionRecord]
             │  ├── list[DNSRecord]
             │  └── list[DomainGeoRecord]
    ┌────────▼──────────────┐
    │  app_summary.py       │  Per-app metric aggregation
    │  (AppSummaryBuilder)  │  Country/ASN concentration, tracker breakdown
    └────────┬──────────────┘
             │ AppSummary
    ┌────────▼──────────────────────────────────┐
    │  run_pcap_analysis.py (pipeline entry)    │
    │  Reads: sample_index.csv                  │
    │  Writes: pcap_connections.csv             │
    │          pcap_dns.csv                     │
    │          pcap_domain_geo.csv              │
    │          pcap_app_summary.csv             │
    │          pcap_trace.json                  │
    └───────────────────────────────────────────┘
```

---

## 2. Design Principles

### 2.1 Facts-Only Table Design
The pipeline emits no risk scores, threat ratings, or privacy grades. All output fields are dry, machine-verifiable facts (ports, byte counts, country codes, ASN strings, boolean flags). Risk attribution is delegated to downstream statistical models. This prevents analytical bias from contaminating the raw dataset.

### 2.2 Statistical Soundness
Both connection counts (`connection_count`) and payload volumes (`payload_bytes_total`) are preserved independently in `ConnectionRecord`. This allows researchers to apply both frequency-weighted and volume-weighted analyses without re-deriving data from aggregate totals.

### 2.3 Unified GeoIP Cache
`GeoMapper` maintains a single in-process dictionary (`_cache: dict[str, GeoResult]`) that spans all stages. There are no secondary caches at the builder or summary layers. This eliminates dual-source-of-truth bugs and prevents redundant rate-limit triggers against the `ip-api.com` fallback backend.

---

## 3. Module Reference

### 3.1 Packet Parser (`pcap_parser.py`)

**Entry point:** `parse_pcap(path: Path) → list[RawEvent]`

The parser supports two link-layer framings without configuration:
- **DLT_RAW** (PCAPDroid default): The buffer is directly parsed as a raw IPv4 packet.
- **Ethernet (DLT_EN10MB)**: The buffer is decoded via `dpkt.ethernet.Ethernet`, and the inner IP layer is extracted.

Only IPv4 packets are processed. IPv6 is skipped.

For each packet, the parser attempts application-layer identification in a strict priority order:

| Priority | Protocol | Detection Method |
|---|---|---|
| 1 | DNS | Port 53 (TCP or UDP) → `dpkt.dns.DNS` |
| 2 | TLS | TCP payload starting with `0x16` → ClientHello SNI extraction |
| 3 | HTTP | TCP dst port `80/8080/8008` → `dpkt.http.Request`, `Host:` header |
| 4 | QUIC | UDP dst/src port 443 → `is_quic=True` flag |
| 5 | Fallback | Generic TCP/UDP event, no domain |

TLS SNI extraction uses a two-stage approach: (1) `dpkt.ssl.TLS` library parser, (2) manual byte-level walking of the ClientHello extension list, tolerating packet fragmentation and GREASE extension types that crash the library parser.

The resulting `RawEvent` dataclass carries:
- Timestamp, source/dest IP, source/dest port, protocol
- Payload size in bytes
- Boolean flags: `is_dns`, `is_tls`, `is_http`, `is_quic`
- Extracted evidence: `dns_query`, `dns_response_ips`, `tls_sni`, `http_host`
- A single unified `domain` field (populated from the highest-priority evidence found)

---

### 3.2 Connection Builder (`connection_builder.py`)

**Entry point:** `ConnectionBuilder(geo_mapper).build(events, sample_id, session_id) → BuildResult`

The builder performs a two-pass aggregation over the flat `RawEvent` stream.

**Pass 1 — Event routing:**
- DNS events are individually emitted as `DNSRecord` objects (not aggregated), preserving per-transaction resolver and response data.
- For every `(domain, dst_ip)` pair seen for the first time, a `DomainGeoRecord` is created and a GeoIP lookup is triggered (cached immediately).
- Every event is placed into a **6-tuple bucket**: `(sample_id, session_id, domain, dst_ip, dst_port, protocol)`.

**Pass 2 — Bucket collapse:**
For each bucket, the builder:
1. Runs `tldextract` to decompose the domain into `registered_domain`, `tld`, `subdomain`.
2. Calls `match_domain()` (tracker matcher) to retrieve tracker identity metadata.
3. Looks up `GeoMapper.lookup(dst_ip)` for country/ASN data (returns from cache in O(1)).
4. Checks the destination port against `STANDARD_PORTS` (`{80, 443, 53, 8080, 8443, 8008}`) to set `is_nonstandard_port`.
5. Checks the resolver IP against `HARDCODED_DNS_RESOLVERS` to set `is_hardcoded_dns`.
6. Checks the domain against `ANTI_ANALYSIS_DOMAINS` to set `is_anti_analysis_probe`.
7. OR-reduces protocol evidence flags across all events in the bucket.

Each bucket yields exactly one `ConnectionRecord`.

---

### 3.3 Tracker Matcher (`tracker_matcher.py` + `constants.py`)

**Entry points:** `match_domain(domain: str) → TrackerMatch`, `match_domains(domains) → dict`

The matcher performs **longest-suffix matching** against the `TRACKER_DOMAINS` dictionary defined in `constants.py`. For a domain to match a suffix `S`, it must satisfy:

```
domain == S  OR  domain.endswith("." + S)
```

When multiple suffixes match (e.g., `"vungle.com"` and `"ads.vungle.com"`), the longest suffix wins, ensuring the most specific entry is returned. Results are memoized with `@lru_cache(maxsize=4096)` to eliminate redundant linear scans for repeated domains.

The `TRACKER_DOMAINS` dict maps a suffix to a `(sdk_name, vendor_country, sdk_category)` tuple. Categories include: `ad_network`, `ad_mediation`, `ad_exchange`, `ad_measurement`, `attribution`, `analytics`, `cdn`, `crash_reporting`, `push_notifications`, `social_analytics`, `data_broker`.

The `CANONICAL_VENDOR_MAP` collapses sub-brands to parent entities (e.g., `"Vungle Ads"`, `"Vungle Metrics"` → `"Vungle"`), enabling accurate market-concentration statistics without double-counting parent organizations.

---

### 3.4 GeoIP Mapper (`geoip.py`)

**Entry point:** `GeoMapper(db_dir?).lookup(ip) → GeoResult`

The `GeoMapper` auto-selects its backend at construction time:

| Backend | Condition | Rate Limit |
|---|---|---|
| **MaxMind GeoLite2** | `data/geoip/GeoLite2-Country.mmdb` present + `geoip2` installed | None (local DB) |
| **ip-api.com** | MaxMind unavailable | 45 req/min; batched at 100 IPs per POST |

Private IP ranges (`10.x`, `127.x`, `172.16–31.x`, `192.168.x`, `169.254.x`) are short-circuited to `country_code="PRIVATE"` without any external call.

The `GeoResult` object carries: `country_code`, `country_name`, `asn` (AS number string), `asn_org` (organization name), `source` (`"maxmind"` | `"ip-api"` | `"private"`).

---

### 3.5 App Summary Builder (`app_summary.py`)

**Entry point:** `AppSummaryBuilder().build(connections, dns_records, domain_geo_records) → AppSummary`

Aggregates the three fact tables into a single `AppSummary` row covering 13 metric groups:

| Group | Key Metrics |
|---|---|
| Volume | `total_connection_records`, `total_payload_bytes`, `session_duration_sec` |
| Domains | `unique_domains`, `unique_registered_domains`, `unique_ips`, `unique_countries` |
| Country distribution | `country_top1_code`, `country_top1_pct`, `country_top3_pct` (excludes `PRIVATE`/`LOCAL`) |
| ASN distribution | `top_asn`, `top_asn_pct` |
| Protocol breakdown | `dns_connection_count`, `http_connection_count`, `tls_connection_count`, `quic_connection_count` |
| Transport flags | `nonstandard_port_connection_count`, `nonstandard_port_domain_count` |
| Tracker statistics | `tracker_domain_count`, `tracker_vendor_count`, `tracker_category_count`, `top_tracker_vendor` |
| DNS statistics | `dns_query_count`, `hardcoded_dns_detected`, `doh_detected`, `avg_dns_response_count` |
| Anti-analysis | `anti_analysis_detected`, `anti_analysis_domain_count` |
| Cloud exposure | `aws_domain_count`, `google_cloud_domain_count`, `alibaba_domain_count`, `tencent_domain_count` |

Country concentration metrics exclude `PRIVATE`, `LOCAL`, and `UNKNOWN` codes, ensuring that carrier NAT hops and local DNS resolvers do not inflate the top-country percentage.

---

## 4. Reference Constants (`constants.py`)

All domain classification rules, exclusion sets, and thresholds are centralized in `constants.py`:

| Constant | Purpose |
|---|---|
| `TRACKER_DOMAINS` | Suffix → `(sdk_name, vendor_country, sdk_category)` — 86 entries |
| `HARDCODED_DNS_RESOLVERS` | IPs that bypass system DNS (Google `8.8.8.8`, Cloudflare `1.1.1.1`, etc.) |
| `ANTI_ANALYSIS_DOMAINS` | Connectivity probe domains used to detect MITM/proxy environments |
| `DOH_DOMAINS` | Known DNS-over-HTTPS resolver hostnames |
| `HIGH_RISK_COUNTRIES` | `{CN, RU, IR, KP}` — data sovereignty risk flag |
| `STANDARD_PORTS` | `{80, 443, 53, 8080, 8443, 8008}` — anything else sets `is_nonstandard_port` |
| `LARGE_DOWNLOAD_THRESHOLD_BYTES` | 1 MB — threshold for `is_large_download` flag |
| `PII_PATTERNS` | Regex patterns for GAID, Android_ID, Device_UUID, location, and 6 other PII types |

---

## 5. Output Schema

Five outputs are produced per pipeline run, written to `output/pcap/`:

### `pcap_connections.csv`
One row per unique 6-tuple bucket `(sample_id, session_id, domain, dst_ip, dst_port, protocol)`.

| Field | Description |
|---|---|
| `sample_id` / `session_id` | App identity and run session |
| `domain`, `registered_domain`, `tld`, `subdomain` | Full domain decomposition |
| `dst_ip`, `dst_port`, `protocol` | Network flow identity |
| `connection_count` | Raw packet count in this bucket |
| `payload_bytes_total` | Total L4 payload bytes |
| `first_seen` / `last_seen` | Unix timestamps |
| `tracker_matched`, `sdk_name`, `canonical_vendor`, `sdk_category` | Tracker identity |
| `geo_country_code`, `geo_country_name`, `asn_number`, `asn_org` | GeoLite2 enrichment |
| `is_tls`, `is_quic`, `is_dns`, `is_http` | Protocol evidence flags |
| `is_nonstandard_port`, `is_hardcoded_dns`, `is_anti_analysis_probe` | Security flags |

### `pcap_dns.csv`
One row per DNS query observed.

| Field | Description |
|---|---|
| `query_name` | Queried domain |
| `resolver_ip` | DNS server used |
| `response_ips` | Pipe-delimited resolved IPs |
| `response_count` | Number of answers |
| `is_hardcoded_resolver` | True if resolver bypasses system DNS |
| `is_doh_resolver` | True if resolver is a known DoH endpoint |
| `is_anti_analysis_probe` | True if query is a connectivity/MITM probe |

### `pcap_domain_geo.csv`
Deduplicated `(domain, dst_ip)` → GeoIP lookup table. One row per unique pair.

### `pcap_app_summary.csv`
One row per app session. Contains all 13 metric groups from `AppSummary`.

### `pcap_trace.json`
Execution metadata: run UUID, timestamp, PCAP file count, GeoIP backend version, tracker DB version, processing errors.

---

## 6. Execution Interface

```bash
python run_pcap_analysis.py \
    --input-dir  data/pcap \
    --output-dir output/pcap \
    --sample-index sample_index.csv
```

The `sample_index.csv` must contain `sample_id`, `package_name`, and `app_country_code` columns. The `sample_id` is derived from the PCAP filename stem (e.g., `com.example.app_in` from `com.example.app_in.pcap`).
