# Knowledge Base Module: Technical Overview

**Geo-Difference Mobile Security — Static Analysis Research System**

---

## Abstract

The `knowledge_base` module is the detection intelligence layer of a large-scale Android static analysis system designed to identify privacy-sensitive API usage, hardcoded secrets, and indirect geo-inference logic across thousands of APKs. The module is architecturally divided into two strictly non-overlapping phases: an **offline build pipeline** that ingests, normalizes, and consolidates three heterogeneous academic and industry datasets into a single canonical database; and a **runtime detection engine** that applies high-performance pattern matching against decompiled Smali bytecode during live APK scanning. This document describes both phases in full technical detail, covering dataset provenance, parsing mechanics, deduplication strategy, in-memory enrichment, and the algorithmic rationale for each matcher.

---

## Table of Contents

### Part I — Static Analysis Knowledge Base

1. [Architectural Overview](#1-architectural-overview)
2. [The Canonical Data Model](#2-the-canonical-data-model)
3. [Dataset Sources and Import Pipeline](#3-dataset-sources-and-import-pipeline)
   - 3.1 [Axplorer](#31-axplorer)
   - 3.2 [PScout](#32-pscout)
   - 3.3 [Google Play Services (GMS)](#33-google-play-services-gms)
   - 3.4 [TruffleHog Secret Patterns](#34-trufflehog-secret-patterns)
   - 3.5 [FlowDroid Geo-Logic Rules](#35-flowdroid-geo-logic-rules)
4. [Database Merge Pipeline](#4-database-merge-pipeline)
5. [Runtime Detection Engine](#5-runtime-detection-engine)
   - 5.1 [MatcherFactory and CacheManager](#51-matcherfactory-and-cachemanager)
   - 5.2 [Knowledge Enrichment Engine](#52-knowledge-enrichment-engine)
   - 5.3 [Privacy Matcher — Aho-Corasick](#53-privacy-matcher--aho-corasick)
   - 5.4 [Secret Matcher — Compiled Regex](#54-secret-matcher--compiled-regex)
   - 5.5 [Geo Matcher — Rule-Based Regex](#55-geo-matcher--rule-based-regex)
6. [Schema Layer](#6-schema-layer)
7. [Canonical Database Summary](#7-canonical-database-summary)
8. [End-to-End Runtime Flow](#8-end-to-end-runtime-flow)
9. [References](#9-references)

### Part II — PCAP Network Knowledge Base

10. [PCAP KB Architectural Overview](#10-pcap-kb-architectural-overview)
11. [Shared Infrastructure](#11-shared-infrastructure)
12. [Tracker Knowledge Base](#12-tracker-knowledge-base)
13. [GeoLite2 Knowledge Base](#13-geolite2-knowledge-base)
14. [DNS Resolver Knowledge Base](#14-dns-resolver-knowledge-base)
15. [PII Detection Knowledge Base](#15-pii-detection-knowledge-base)
16. [PCAP KB Canonical Database Summary](#16-pcap-kb-canonical-database-summary)
17. [PCAP End-to-End Runtime Flow](#17-pcap-end-to-end-runtime-flow)
18. [PCAP References](#18-pcap-references)

---

## 1. Architectural Overview

The module enforces a strict data flow boundary:

```
┌───────────────────────────────────┐
│         OFFLINE BUILD PHASE       │
│                                   │
│  Axplorer ──┐                     │
│  PScout  ───┼──► Merge ──► privacy_apis.csv
│  GMS     ──┘                     │
│                                   │
│  TruffleHog ──► secret_patterns.csv
│  FlowDroid  ──► geo_logic.csv    │
└───────────────────────────────────┘
                    │
             Frozen Metadata
                    │
┌───────────────────▼───────────────┐
│          RUNTIME ENGINE           │
│                                   │
│  KnowledgeEnrichmentEngine        │
│    └─► PrivacyMatcher (Aho-Corasick)
│    └─► SecretMatcher (Regex)     │
│    └─► GeoMatcher (Rule-based)   │
│                                   │
│  Input: Smali bytecode            │
│  Output: BaseFinding objects      │
└───────────────────────────────────┘
```

The runtime engine **never** reads raw upstream sources. All detection operates exclusively on the frozen metadata produced during the build phase, ensuring reproducibility and scan consistency across all APKs.

---

## 2. The Canonical Data Model

All privacy API records across all three datasets are normalized into a single shared dataclass defined in `schemas/privacy_api_schema.py`:

```python
@dataclass
class PrivacyAPIRecord:
    record_id:                str        # UUID-5 seeded from canonical identity
    category:                 str        # e.g., "Location", "Contacts"
    subcategory:              str        # e.g., "GPS", "Phone"
    framework:                str        # "Android Framework" | GMS artifact name
    package_name:             str        # e.g., "android.location"
    class_name:               str        # e.g., "LocationManager"
    method_name:              str        # e.g., "getLastKnownLocation"
    api_name:                 str        # Same as method_name
    api_type:                 str        # "method" | "field" | "constructor"
    permission:               str        # e.g., "android.permission.ACCESS_FINE_LOCATION"
    sources:                  List[str]  # ["Axplorer", "PScout"]
    source_versions:          List[str]  # ["API-23", "API-25"]
    supported_android_versions: List[int]
    min_android_api:          Optional[int]
    max_android_api:          Optional[int]
    confidence:               str        # "MEDIUM" | "HIGH" | "VERY_HIGH"
    deprecated:               bool
    documentation_url:        str
    notes:                    str
```

The `record_id` is a **deterministic UUID-5** seeded from the canonical identity string:
```
privacy-api://{framework}/{package_name}/{class_name}/{method_name}/{api_type}
```
This ensures the same API always receives the same identifier regardless of import order.

---

## 3. Dataset Sources and Import Pipeline

### 3.1 Axplorer

**Origin:** Axplorer [Backes et al., CCS 2016] is a static analysis tool that systematically maps the Android Open Source Project (AOSP) permission system by analyzing inter-component communication graphs in the Android framework itself. It produces exhaustive `framework-map-*.txt` files organized per Android API level.

**Format:**
```
android.location.LocationManager.getLastKnownLocation(java.lang.String) :: android.permission.ACCESS_FINE_LOCATION
```
Each line encodes `<fully-qualified-signature> :: <permission>` using `::` as a separator.

**Importer:** `importers/import_axplorer.py` — `AxplorerImporter`

**Parsing mechanics:**
1. **Discovery:** Recursively finds all `framework-map-*.txt` files under `raw/axplorer/`. The parent directory name (e.g., `api-23`) is parsed to extract the minimum Android API level.
2. **Signature extraction:** For each line, the `::` separator splits the API signature from the permission. The signature is further parsed by locating the opening parenthesis `(` to isolate `package.class.method`. The last `.` before `(` separates method from class; the preceding `.` separates class from package.
3. **Permission taxonomy resolution:** The permission string is looked up in two chained maps loaded from `metadata/android_permission_groups.csv` and `metadata/group_to_privacy_category.csv`:
   ```
   ACCESS_FINE_LOCATION → LOCATION (group) → Location (category)
   ```
   Permissions that cannot be resolved produce `category = "Unknown"`, retained for traceability.
4. **API-level deduplication:** The same method may appear across multiple API-level files. Within the importer, records are deduplicated on the key `(framework, package, class, method, permission)`, merging their `supported_android_versions` lists and computing `min_android_api` / `max_android_api`.
5. **Output:** `build_outputs/axplorer_import.csv`

---

### 3.2 PScout

**Origin:** PScout [Au et al., CCS 2012] is an alternative Android permission mapping produced via a Datalog-based call-graph analysis of AOSP. Because PScout and Axplorer use independent methodologies (Datalog reachability vs. static call-graph traversal), APIs confirmed by both carry stronger evidential weight.

**Formats:** PScout ships in two formats:
- **XML** (`perm-def-API-23.xml`, `perm-def-API-25.xml`, `perm-def-manual.xml`, `javadoc-perm-def-API-23.xml`): Structured `<permissionDef>` elements with `className`, `target`, `targetKind`, and nested `<permission>` nodes.
- **TXT** (`perm-def-default.txt`): Jimple-style entries:
  ```
  <android.location.LocationManager: android.location.Location getLastKnownLocation(java.lang.String)> -> ACCESS_COARSE_LOCATION, ACCESS_FINE_LOCATION
  ```

**Importer:** `importers/import_pscout.py` — `PScoutImporter`

**Parsing mechanics:**
- **XML path:** Parsed with `xml.etree.ElementTree`. For each `permissionDef`, the `className` attribute provides the fully qualified class, and `target`+`targetKind` provides the method or field. If a `permissionDef` has multiple `<permission>` children, each generates a separate record.
- **TXT path:** Lines are split on `->`. The left side is a Jimple signature wrapped in `<>`. The colon `:` inside separates the class from the method signature. `targetKind` is heuristically inferred: if `(` appears in the target string, it is a method; otherwise a field. Multiple permissions on the right side (comma-separated) each generate a separate record. Permissions lacking the `android.permission.` prefix are normalized automatically.
- **Permission taxonomy resolution:** Identical two-step chain as Axplorer.
- **Deduplication key:** `(framework, package, class, method, permission)` — same as Axplorer, enabling cross-dataset merging.
- **Output:** `build_outputs/pscout_import.csv`

---

### 3.3 Google Play Services (GMS)

**Origin:** Google Mobile Services provides proprietary APIs beyond AOSP — including the Fused Location Provider, Activity Recognition API, Places API, and Google Maps SDK. These APIs are the dominant mechanism for location access in commercial Android apps yet are entirely absent from both Axplorer and PScout.

**Format:** GMS ships as Android Archive (`.aar`) files. Each AAR contains a `classes.jar` with compiled Java bytecode (`.class` files).

**Importer:** `importers/import_gms.py` — `GMSImporter`

**Parsing mechanics:**
1. **Artifact manifest:** `metadata/gms_artifacts.csv` lists each AAR file with its artifact ID, version, framework label, and `enabled` flag. Only enabled artifacts are processed.
2. **JAR extraction:** For each enabled AAR, the importer extracts `classes.jar` using Python's `zipfile` module.
3. **Bytecode inspection:** The `jawa` library (`jawa.cf.ClassFile`) is used to parse each `.class` file. Only `public` classes are processed. For each public class:
   - All `public` methods are enumerated and emitted as `api_type="method"` records.
   - All `public` fields are enumerated and emitted as `api_type="field"` records.
4. **Category assignment:** GMS records are created with `category="Unknown"` at import time. Semantic categorization is deferred entirely to the Knowledge Enrichment Engine at runtime, which applies `classification_rules.csv` against GMS class and package names.
5. **Deduplication key:** `(package_name, class_name, method_name)` — omits framework to collapse version duplicates.
6. **Output:** `build_outputs/gms_import.csv`

**Justification:** Commercial Android apps overwhelmingly prefer `com.google.android.gms.location.FusedLocationProviderClient` over `android.location.LocationManager`. A scanner that covers only AOSP APIs misses the dominant location access pattern in production apps.

---

### 3.4 TruffleHog Secret Patterns

**Origin:** TruffleHog [Trufflesecurity, 2023] is an industry-standard secrets scanning engine containing 931 curated regex detectors targeting hardcoded API keys, OAuth tokens, private keys, and service credentials across hundreds of providers (AWS, GCP, Stripe, Twilio, Firebase, etc.).

**Format:** Each rule provides: `pattern_id`, `provider`, `secret_type`, raw regex string (Google RE2 dialect), `severity`.

**Importer:** `pipeline/importers/import_trufflehog.py`

**Key technical detail — RE2 vs Python `re`:** TruffleHog rules are authored for Google's RE2 engine. Python's `re` module does not support certain RE2 constructs (`\z` anchor, possessive quantifiers, mid-pattern inline modifiers). During import and at runtime initialization, each pattern is attempted with `re.compile()`. Patterns that fail are flagged `supported=False` and retained in `metadata/secret_patterns.csv` for traceability but excluded from live matching. This fault-tolerant design prevents a single incompatible regex from crashing the scanner.

**Output:** `metadata/secret_patterns.csv`

---

### 3.5 FlowDroid Geo-Logic Rules

**Origin:** FlowDroid [Arzt et al., PLDI 2014] is a precise static taint analysis framework. Its source/sink configuration encodes indirect geo-inference API call chains — sequences of method calls that reveal physical location without `ACCESS_FINE_LOCATION` (e.g., reading cell tower signal strength via `TelephonyManager`, WiFi SSID via `WifiManager`, or barometric pressure via `SensorManager`).

**Importer:** `pipeline/importers/import_flowdroid_geo.py`

**Rule loading at runtime:** `pipeline/geo_rule_loader.py` — `GeoRuleLoader` reads `metadata/geo_logic.csv`. For each rule, a Python regex is compiled from the class/method name:
- If the method name is all-uppercase (a constant field), a strict anchored pattern is generated: `(?i)\bClassName\.METHOD\b`
- Otherwise, an optional-class pattern is generated: `(?i)(?:ClassName[;.])?methodName\b` — this handles both Java dot-notation and Smali semicolon-notation in the same rule.

Rules are cached as an **immutable tuple** after first load (`cls._cache`), preventing re-parsing on subsequent calls within the same process.

**Output:** `metadata/geo_logic.csv`

---

## 4. Database Merge Pipeline

### 4.1 DatabaseMerger (`pipeline/merge_database.py`)

After the three importers complete, `DatabaseMerger` consolidates `axplorer_import.csv`, `pscout_import.csv`, and `gms_import.csv` into the canonical `processed/privacy_apis.csv`.

**Deduplication key:**
```python
key = (framework, package_name, class_name, method_name, api_type)
```

**Merge algorithm (per record):**
```
if key not in merged_records:
    Generate record_id = UUID5(NAMESPACE_URL, canonical_string)
    Initialize record with first-seen metadata
    Initialize meta dict: sources={}, permissions={}, android_versions={}

else (duplicate):
    meta["sources"].update(new_sources)
    meta["permissions"].update(new_permissions)
    meta["android_versions"].update(new_versions)

    # Category conflict resolution:
    if existing_category == "Unknown" and new_category != "Unknown":
        adopt new_category
    elif both are known and disagree:
        log WARNING, increment conflict counter, retain existing
```

**Confidence scoring** is assigned after all sources have been merged, based on multi-source corroboration:

| Sources Contributing | Confidence |
|---|---|
| 3 or more | `VERY_HIGH` |
| 2 | `HIGH` |
| 1 | `MEDIUM` |

This means APIs confirmed independently by both Axplorer and PScout receive `HIGH` confidence, while APIs appearing in all three datasets receive `VERY_HIGH`.

**Final sort:** Records are sorted by key tuple before writing, ensuring a deterministic CSV output regardless of processing order.

**Output:** `processed/privacy_apis.csv` — **9,336 canonical records**.

---

## 5. Runtime Detection Engine

### 5.1 MatcherFactory and CacheManager

`pipeline/matcher_factory.py` implements a **Singleton factory** using `__new__` override. `initialize()` is guarded by `CacheManager.has("matchers_initialized")`, ensuring all three matchers are constructed and warmed exactly once per process regardless of how many APKs are scanned.

```python
# First call: full initialization
MatcherFactory.initialize()
  → PrivacyMatcher().initialize()   # builds Aho-Corasick automaton
  → SecretMatcher().initialize()    # compiles 931 regex patterns
  → GeoMatcher().initialize()       # loads 24 geo-inference rules
  → CacheManager.set("matchers_initialized", True)

# All subsequent calls: no-op (cache hit)
MatcherFactory.initialize()  # returns immediately
```

`CacheManager` is a plain module-level dict (`_store = {}`), providing O(1) get/set/has operations. Its simplicity is intentional: it stores only three objects per process lifecycle.

---

### 5.2 Knowledge Enrichment Engine (`pipeline/knowledge_enrichment.py`)

Before the Privacy Matcher can be built, the canonical database requires semantic augmentation. Many records arrive from the importers with `category = "Unknown"` because their Android permission could not be resolved to a privacy category (e.g., GMS records, or AOSP APIs with non-standard permissions). The `KnowledgeEnrichmentEngine` resolves this entirely in memory.

**Input files:**
- `processed/privacy_apis.csv` — read as immutable input; never modified.
- `metadata/classification_rules.csv` — 90 hand-curated rules.

**Rule schema:**

| Column | Values |
|---|---|
| `level` | `method`, `class`, `package`, `keyword` |
| `pattern` | Exact string or regex depending on level |
| `category` | Target privacy category |
| `subcategory` | Target privacy subcategory |
| `confidence` | `VERY_HIGH`, `HIGH`, `MEDIUM`, `LOW` |
| `notes` | Research justification |

**Rule organization:** Rules are loaded into four separate lookup structures:
```python
method_rules:  Dict[str, List[rule]]  # key = "pkg.Class.method"
class_rules:   Dict[str, List[rule]]  # key = "pkg.Class"
package_rules: Dict[str, List[rule]]  # key = "pkg"
keyword_rules: List[(compiled_regex, rule)]
```

**Enrichment algorithm (per record):**
```
rec = shallow_copy(api_record)   # canonical fields never mutated

full_method = f"{pkg}.{cls}.{method}"
full_class  = f"{pkg}.{cls}"

1. Check method_rules[full_method]  → if match, apply and continue
2. Check class_rules[full_class]    → if match, apply and continue
3. Check package_rules[pkg]         → if match, apply and continue
4. Scan keyword_rules for regex     → collect all matching rules

Priority: Method > Class > Package > Keyword (specificity cascade)
```

**Conflict resolution:** If multiple rules at the same level produce conflicting categories, the engine appends a `CONFLICT: {categories}` annotation to the record's `notes` field and does not overwrite the existing category. This prevents incorrect enrichment from being silently applied.

**Output:** List of enriched `PrivacyAPIRecord` objects **in memory only**. The canonical CSV is never rewritten. This enforces the single-source-of-truth property: `privacy_apis.csv` remains the permanent ground truth; enrichment is always derived on demand.

---

### 5.3 Privacy Matcher — Aho-Corasick (`pipeline/aho_matcher.py`)

**Detection target:** Calls to privacy-sensitive APIs in Smali bytecode.

**Algorithm:** The Aho-Corasick multi-pattern string search algorithm [Aho & Corasick, CACM 1975].

#### Why Aho-Corasick?

A naïve approach would construct a regex alternation of all 9,336 patterns: `getLastKnownLocation|requestLocationUpdates|...`. Python's `re` engine evaluates alternations sequentially with backtracking, yielding O(N × P) worst-case complexity where N is the text length and P is the pattern count. At 9,336 patterns over Smali files averaging tens of thousands of lines, this approach is computationally infeasible at scale.

Aho-Corasick builds a **finite automaton** with **failure links** (suffix links) that allow the automaton to transition to the longest proper suffix state on a mismatch without restarting. This guarantees:
- **Build:** O(Σ|pattern|) — one-time cost proportional to total pattern character count.
- **Search:** O(|text| + |matches|) — strictly linear in text length, independent of pattern count.

#### Token generation

For each enriched `PrivacyAPIRecord`, a search token is derived:
```python
if class_name and method_name:
    if method_name == "<init>":
        token = class_name           # Constructor: match class name
    else:
        token = f"{class_name}.{method_name}"  # Standard method
elif class_name:
    token = class_name
elif package_name:
    token = package_name.split('.')[-1]  # Last package segment
```
All tokens are **lowercased** before insertion. This enables case-insensitive matching without a case-insensitive automaton, keeping the automaton alphabet small.

Records with `category = "Unknown"` after enrichment are skipped — they would produce false positives by matching generic class names without semantic meaning.

#### Automaton construction

```python
mapping: Dict[str, List[{category, subcategory, confidence}]]

for each enriched record:
    token = generate_token(record).lower()
    mapping[token].append({
        "category":    record.category,
        "subcategory": record.subcategory,
        "confidence":  normalize_confidence(record.confidence)
    })

# Deduplicate (category, subcategory) pairs per token
for key, values in mapping.items():
    unique_vals = deduplicate_by_category_subcategory(values)
    automaton.add_word(key, unique_vals)

automaton.make_automaton()   # Compiles failure links
```

**Result:** 1,266 unique lowercased tokens in the automaton (de-duplicated from 9,336 records because many APIs share the same class name or method name prefix).

#### Search phase

```python
text_lower = text.lower()
seen = set()

for end_idx, values in automaton.iter(text_lower):
    for v in values:
        tup = (v["category"], v["subcategory"], v["token"])
        if tup not in seen:
            seen.add(tup)
            findings.append(PrivacyFinding(
                category=v["category"],
                subcategory=v["subcategory"],
                confidence=v["confidence"],
                matched_text=v["token"],
                offset_start=end_idx - len(v["token"]) + 1,
                offset_end=end_idx,
                source="privacy_api",
                api_signature=v["token"]
            ))

findings.sort(key=lambda x: (x.category, x.subcategory, x.matched_text))
```

The de-duplication set prevents the same (category, subcategory, token) triple from generating multiple findings within a single file, handling the case where a short token appears as a substring of a longer one.

---

### 5.4 Secret Matcher — Compiled Regex (`pipeline/secret_matcher.py`)

**Detection target:** Hardcoded API keys, OAuth tokens, private keys, and service credentials in Smali string literals.

**Algorithm:** Pre-compiled regex set from `metadata/secret_patterns.csv`.

Unlike the Privacy Matcher which targets structured method signatures, secrets are unstructured strings that vary dramatically in format across providers. Aho-Corasick cannot be applied because secret patterns are not fixed strings — they are complex character classes and quantifiers.

**Build phase:**
```python
for row in csv_reader:
    raw_regex = row["regex"]
    try:
        compiled = re.compile(raw_regex)
        supported = True
    except re.error:
        supported = False    # RE2-only syntax rejected by Python re

pattern = SecretPattern(
    pattern_id=row["pattern_id"],
    provider=row["provider"],
    secret_type=row["secret_type"],
    raw_regex=raw_regex,
    compiled_regex=compiled,
    severity=row["severity"],
    supported=supported
)
```

**Search phase:**
```python
for pat in self.patterns:
    if not pat.supported or pat.compiled_regex is None:
        continue
    for match in pat.compiled_regex.finditer(text):
        findings.append(SecretFinding(
            subcategory=pat.secret_type,
            confidence=pat.severity.lower(),
            matched_text=match.group(0),
            rule_id=pat.pattern_id
        ))
```

**`generate_reports` flag:** When `SecretMatcher` is constructed with `generate_reports=True` (default in the factory), it writes `processed/unsupported_secret_patterns.csv` and `processed/secret_loader_statistics.csv` during initialization. This provides a record of which TruffleHog patterns were incompatible with Python's regex engine.

---

### 5.5 Geo Matcher — Rule-Based Regex (`pipeline/geo_matcher.py`)

**Detection target:** Indirect geo-inference API calls that reveal physical location without explicit GPS permission.

**Examples of detected patterns:**
- `TelephonyManager.getCellLocation()` — cell tower triangulation
- `WifiManager.getScanResults()` — WiFi SSID positioning
- `SensorManager.registerListener()` for `TYPE_PRESSURE` — barometric altitude

**Algorithm:** `GeoRuleLoader` compiles each entry in `metadata/geo_logic.csv` into a Python regex pattern using the following logic:

```python
if cls_name and method:
    if method.isupper():
        # Constant field — require class name prefix
        regex = rf"(?i)\b{re.escape(cls_name)}\.{re.escape(method)}\b"
    else:
        # Method — class name optional (handles Smali notation)
        regex = rf"(?i)(?:{re.escape(cls_name)}[;.])?{re.escape(method)}\b"
else:
    regex = rf"(?i)\b{re.escape(method)}\b"
```

The optional class prefix pattern `(?:ClassName[;.])?` handles both Java-style `ClassName.method` and Smali-style `LClassName;->method` without requiring two separate rules per API.

**Caching:** `GeoRuleLoader._cache` stores the compiled rule set as an **immutable tuple** after first load, preventing redundant file I/O and regex compilation across multiple APK scans.

**Output:** 24 active geo-inference rules covering Location, Sensor, Telephony, and WiFi categories.

---

## 6. Schema Layer (`schemas/`)

All findings implement `BaseFinding` and are returned as strictly typed dataclass instances:

| Schema | Matcher | Key Fields |
|---|---|---|
| `PrivacyFinding` | `PrivacyMatcher` | `category`, `subcategory`, `confidence`, `api_signature` |
| `SecretFinding` | `SecretMatcher` | `subcategory` (secret type), `confidence` (severity), `rule_id` |
| `GeoFinding` | `GeoMatcher` | `category`, `subcategory`, `confidence`, `rule_id` |

All three inherit `BaseFinding` which provides: `matcher`, `category`, `subcategory`, `confidence`, `matched_text`, `offset_start`, `offset_end`, `source`.

---

## 7. Canonical Database Summary

| File | Location | Produced By | Consumed By | Records |
|---|---|---|---|---|
| `privacy_apis.csv` | `processed/` | `merge_database.py` | `knowledge_enrichment.py` | 9,336 |
| `secret_patterns.csv` | `metadata/` | `import_trufflehog.py` | `secret_matcher.py` | 931 |
| `geo_logic.csv` | `metadata/` | `import_flowdroid_geo.py` | `geo_rule_loader.py` | 24 |
| `classification_rules.csv` | `metadata/` | Hand-curated | `knowledge_enrichment.py` | 90 |
| `android_permission_groups.csv` | `metadata/` | AOSP documentation | `import_axplorer.py`, `import_pscout.py` | — |
| `group_to_privacy_category.csv` | `metadata/` | Hand-curated | `import_axplorer.py`, `import_pscout.py` | — |

---

## 8. End-to-End Runtime Flow

```
scan_manifest.py
    └─► ManifestFeatureExtractor
            └─► MatcherFactory.initialize()   [called once per process]
                    ├─► KnowledgeEnrichmentEngine.enrich()
                    │       ├── load classification_rules.csv  (90 rules)
                    │       ├── load privacy_apis.csv          (9,336 records)
                    │       └── enrich in-memory → 9,336 enriched records
                    │
                    ├─► PrivacyMatcher.build(enriched_records)
                    │       └── Aho-Corasick automaton, 1,266 tokens
                    │
                    ├─► SecretMatcher.initialize()
                    │       └── 931 compiled regex patterns
                    │
                    └─► GeoMatcher.initialize()
                            └── 24 geo-inference rules

    For each decoded APK:
        For each Smali file:
            ├─► PrivacyMatcher.search(text) → List[PrivacyFinding]
            ├─► SecretMatcher.search(text)  → List[SecretFinding]
            └─► GeoMatcher.search(text)     → List[GeoFinding]

        Aggregate findings → static_code_findings.csv
```

---

## 9. References

- Aho, A. V., & Corasick, M. J. (1975). Efficient string matching: an aid to bibliographic search. *Communications of the ACM*, 18(6), 333–340.
- Arzt, S., et al. (2014). FlowDroid: Precise context, flow, field, object-sensitive and lifecycle-aware taint analysis for Android apps. *ACM SIGPLAN Notices*, 49(6), 259–269.
- Au, K. W. Y., et al. (2012). PScout: Analyzing the Android permission specification. *Proceedings of CCS 2012*.
- Backes, M., et al. (2016). Demystifying the Semantics of Personal Data. *Proceedings of CCS 2016* (Axplorer).
- Trufflesecurity. (2023). TruffleHog: Find leaked credentials. https://github.com/trufflesecurity/trufflehog

---
---

# Part II — PCAP Network Knowledge Base

## 10. PCAP KB Architectural Overview

The PCAP Network Knowledge Base is the dynamic enrichment intelligence layer of the pipeline, operating on **live captured network traffic** (PCAP files) from Android applications. Where the Static Analysis KB produces findings from decompiled bytecode, the PCAP KB enriches raw connection-level facts extracted by `pcap_parser.py` and assembled into `ConnectionRecord` objects by `ConnectionBuilder`.

The PCAP KB is composed of **four independent, deterministic enrichment modules**, each following the same build-time / runtime separation enforced by the Static Analysis KB:

```
┌─────────────────────────────────────────────────────┐
│                OFFLINE BUILD PHASE                  │
│                                                     │
│  Exodus + EasyPrivacy ──► trackers.csv              │
│  dnscrypt-resolvers   ──► dns_resolvers.csv         │
│    + public_dns.csv                                 │
│  MaxMind GeoLite2     ──► (binary .mmdb files)      │
│  pii_rules.csv        ──► pii_patterns.csv          │
│    + presidio_rules.csv                             │
└───────────────────────────┬─────────────────────────┘
                            │  Frozen Processed Datasets
                            │
┌───────────────────────────▼─────────────────────────┐
│                 RUNTIME ENGINE                      │
│                                                     │
│  NetworkContext                                     │
│    └─► TrackerMatcher    (suffix-trie)              │
│    └─► GeoMapper         (MaxMind reader)           │
│    └─► DNSResolverMatcher (IP dict lookup)          │
│    └─► PIIMatcher        (master regex + validator) │
│                                                     │
│  Input:  PacketEvent stream from pcap_parser.py     │
│  Output: ConnectionRecord with enriched Fact fields │
└─────────────────────────────────────────────────────┘
```

The runtime engine **never reads raw upstream sources at scan time**. All enrichment operates exclusively on the frozen processed datasets produced during the offline build phase, ensuring reproducibility across all PCAP scans.

---

## 11. Shared Infrastructure

All four PCAP KB modules share a common infrastructure defined in `knowledge_base/network/`:

### DatasetManager (`knowledge_base/dataset_manager.py`)

The single entry point for loading any processed KB dataset into the runtime. All four matchers are instantiated via `DatasetManager` methods:

| Method | Returns | Used By |
|---|---|---|
| `load_network_trackers()` | `List[TrackerFact]` | `TrackerMatcher` |
| `load_geolite()` | `GeoMapper` | `ConnectionBuilder` |
| `load_dns_resolvers()` | `List[DNSResolverFact]` | `DNSResolverMatcher` |
| `load_pii_patterns()` | `List[dict]` | `PIIMatcher` |

### NetworkContext (`pcap/network_context.py`)

A lightweight dependency-injection container that holds all four matcher instances and is passed to `ConnectionBuilder` at construction time. This decouples the matcher lifecycle from any individual PCAP scan.

```python
ctx = NetworkContext(
    tracker_matcher      = TrackerMatcher(tracker_facts),
    geo_mapper           = manager.load_geolite(),
    dns_resolver_matcher = DNSResolverMatcher(resolver_dict),
    pii_matcher          = PIIMatcher(pii_patterns),
)
conn_builder = ConnectionBuilder(network_context=ctx)
```

### SuffixMatcher (`pcap/matchers/suffix_matcher.py`)

A generic, type-parameterized **longest-suffix trie** used as the base class for `TrackerMatcher` and `DNSResolverMatcher`. The trie stores reversed domain labels and walks the tree label-by-label, recording the deepest matching value. This produces correct longest-suffix semantics with O(L) lookup per domain, where L is the number of domain labels.

---

## 12. Tracker Knowledge Base

### 12.1 Dataset Sources

| Dataset | Type | Records | Provides |
|---|---|---|---|
| **Exodus Privacy** | Tracker catalog (API + domain suffix) | Curated | `vendor`, `canonical_vendor`, `category` |
| **EasyPrivacy** | Domain blocklist | ~47,000 | Domain suffix only (no vendor metadata) |

**Source files:** `knowledge_base/raw/tracker/exodus.json`, `knowledge_base/raw/tracker/easyprivacy.txt`

### 12.2 Build Pipeline

**Importer:** `knowledge_base/network/importers/tracker_importer.py` — `TrackerImporter`

**Builder:** `knowledge_base/network/builders/tracker_builder.py` — `TrackerBuilder`

**Build mechanics:**
1. **Exodus import:** Each tracker entry in `exodus.json` supplies a list of network signatures (domain suffixes). For each signature, a `TrackerFact` is created carrying `vendor`, `canonical_vendor`, `category`, and `source_dataset = "Exodus"`.
2. **Canonical vendor mapping:** Raw Exodus vendor names are normalized through `canonical_tracker_map.json`, which collapses variant spellings (e.g., `"Google Firebase Analytics"`, `"Google Firebase"`) to a single canonical vendor (e.g., `"Google"`).
3. **EasyPrivacy import:** Each non-comment domain rule from `easyprivacy.txt` produces a `TrackerFact` with `vendor = ""`, `category = ""`, and `source_dataset = "EasyPrivacy"`. These entries correctly identify tracking behavior without vendor attribution.
4. **Merge and deduplication:** Exodus records are loaded first; EasyPrivacy records are merged second. Duplicate domain suffixes retain the Exodus record (which carries richer metadata) and append the EasyPrivacy source tag.
5. **Output:** `knowledge_base/network/processed/trackers.csv` — **47,217 domain-suffix rules**.

**Output schema:**

```
domain_suffix, vendor, canonical_vendor, category, source_dataset, source_version
```

### 12.3 Runtime — TrackerMatcher

**Matcher:** `pcap/matchers/tracker_matcher.py` — `TrackerMatcher(SuffixMatcher[TrackerFact])`

**Algorithm:** Longest-suffix trie lookup with an `@functools.lru_cache(maxsize=8192)` on `match()` for repeated domain lookups across connections within the same scan session.

**Match semantics:** A domain is considered a tracker match whenever `tracker_fact is not None`, regardless of whether the `vendor` field is populated. EasyPrivacy-only matches carry no vendor metadata but still correctly indicate tracking behavior.

**Populated fields on `ConnectionRecord`:**
- `tracker_fact: TrackerFact` — the matched KB entry
- `tracker_matched: bool` — set to `True` for downstream `AppSummary` aggregation
- `canonical_vendor: str` — propagated for vendor distribution metrics
- `sdk_category: str` — propagated for category distribution metrics

### 12.4 Validation Results (211 PCAPs, 32,793 connections)

| Metric | Value |
|---|---|
| Domain-suffix rules | 47,217 |
| Tracker coverage | **45.8%** of observed domains |
| Unique vendors matched | 41 |
| Unique categories matched | 5 |
| Top vendors | Google, Meta, AppLovin, Mintegral, InMobi |
| Top categories | Advertising, Analytics, Crash Reporting |

---

## 13. GeoLite2 Knowledge Base

### 13.1 Dataset Source

| Dataset | Type | Provides |
|---|---|---|
| **MaxMind GeoLite2-City** | Binary MMDB | `country_code`, `country_name`, `continent`, `city` |
| **MaxMind GeoLite2-ASN** | Binary MMDB | `asn`, `organization`, `organization_type` |

**Source files:** `knowledge_base/data/geolite/GeoLite2-City.mmdb`, `knowledge_base/data/geolite/GeoLite2-ASN.mmdb`

GeoLite2 databases are distributed under the MaxMind End User License Agreement and are not redistributed in the repository. They must be downloaded separately from the MaxMind developer portal.

### 13.2 Build Phase

The GeoLite2 databases require no offline build step. The binary MMDB files are used directly at runtime via the `maxminddb` Python library. There is no intermediate CSV processing layer.

### 13.3 Runtime — GeoMapper

**Mapper:** `pcap/matchers/geo_mapper.py` — `GeoMapper`

**Algorithm:** Two independent `maxminddb.open_database()` handles, one for City and one for ASN. Each IP lookup performs a binary tree traversal of the MMDB structure in O(log N) time.

**RFC1918 short-circuit:** Private network ranges (`10.x.x.x`, `192.168.x.x`, `172.16–31.x.x`) are detected before the MMDB query and returned as `GeoFact(country_code="PRIVATE")` to avoid spurious lookups.

**Populated fields on `ConnectionRecord`:**
- `geo_fact: GeoFact` — `country_code`, `country_name`, `continent`
- `asn_fact: ASNFact` — `asn`, `organization`, `organization_type`

### 13.4 Validation Results (211 PCAPs, 32,793 connections)

| Metric | Value |
|---|---|
| Unique destination IPs | 1,584 |
| GeoIP resolved | 1,584 |
| GeoIP coverage | **100.0%** |
| Unique countries observed | 21 |
| Unique ASNs observed | 79 |
| Top organizations | Google LLC, Amazon, BHARTI Airtel, Cloudflare, Meta |

---

## 14. DNS Resolver Knowledge Base

### 14.1 Dataset Sources

| Dataset | Type | Records | Role |
|---|---|---|---|
| **dnscrypt-resolvers** | Official resolver list (CSV/JSON) | Primary | Full resolver catalog with DoH/DoT/DNSCrypt metadata |
| **public_dns.csv** | Hand-curated override layer | Secondary | Confirms and overrides well-known IPs (Google, Cloudflare variants, etc.) |

**Source files:** `knowledge_base/raw/dns/dnscrypt-resolvers/`, `knowledge_base/raw/dns/public_dns.csv`

### 14.2 Build Pipeline

**Importer:** `knowledge_base/network/importers/dns_resolver_importer.py` — `DNSResolverImporter`

**Builder:** `knowledge_base/network/builders/dns_resolver_builder.py` — `DNSResolverBuilder`

**Build mechanics:**
1. **dnscrypt-resolvers import:** Resolver entries are parsed from the official `public-resolvers.md` file. Each entry yields `ip_address`, `provider`, `supports_doh`, `supports_dot`, `supports_dnscrypt`, and `confidence = "MEDIUM"`.
2. **Canonical provider mapping:** Raw provider names are collapsed through `canonical_dns_provider_map.json` to 14 canonical providers (e.g., `"Google"`, `"Cloudflare"`, `"Quad9"`) plus a catch-all `"Community"` bucket for independent operators.
3. **public_dns.csv override:** Entries in the override layer are loaded last with `confidence = "HIGH"` and take precedence over primary-source entries for the same IP address.
4. **Merge and deduplication:** IP address is the deduplication key. The override layer can correct provider names, confidence levels, and capability flags without altering the primary source data.
5. **Output:** `knowledge_base/network/processed/dns_resolvers.csv` — **614 resolver entries**.

**Output schema:**

```
ip_address, provider, canonical_provider, resolver_name,
provider_country, supports_doh, supports_dot, source_dataset,
source_version, confidence
```

### 14.3 Runtime — DNSResolverMatcher

**Matcher:** `pcap/matchers/dns_resolver_matcher.py` — `DNSResolverMatcher`

**Algorithm:** O(1) Python dict lookup keyed on `ip_address` string. The entire resolver dataset is loaded into a flat dictionary at startup.

**Populated fields on `DNSRecord`:**
- `dns_resolver_fact: DNSResolverFact` — `canonical_provider`, `supports_doh`, `supports_dot`, `confidence`

### 14.4 Validation Results (211 PCAPs, 10,587 DNS queries)

| Metric | Value |
|---|---|
| Resolver entries | 614 |
| Canonical providers | 14 (+ Community) |
| DNS coverage | **0.1%** |
| Dominant resolver | `10.215.173.2` (local DHCP forwarder, 99.9% of queries) |

> **Note:** The near-zero coverage is an expected consequence of the emulator capture environment, not a Knowledge Base defect. See `docs/KB_LIMITATIONS.md` for a full explanation.

---

## 15. PII Detection Knowledge Base

### 15.1 Dataset Sources

| Dataset | Type | Patterns | Confidence | Role |
|---|---|---|---|---|
| **pii_rules.csv** | Android-specific rules (RFC/IEEE sourced) | 15 | HIGH | Primary detection rules |
| **presidio_rules.csv** | Microsoft Presidio recognizers | 4 | MEDIUM | Industry-standard supplement |

**Source files:** `knowledge_base/raw/pii/pii_rules.csv`, `knowledge_base/raw/pii/presidio_rules.csv`

### 15.2 Build Pipeline

**Importer:** `knowledge_base/network/importers/pii_importer.py` — `PIIImporter`

**Builder:** `knowledge_base/network/builders/pii_builder.py` — `PIIBuilder`

**Build mechanics:**
1. **Presidio import:** Rules from `presidio_rules.csv` are loaded first with `confidence = "MEDIUM"` and `source_dataset = "Presidio"`.
2. **Android-specific import:** Rules from `pii_rules.csv` are merged second with `confidence = "HIGH"`. Where a `pattern_name` exists in both datasets (e.g., `Email Address`), the Android-specific HIGH-confidence rule overwrites the Presidio MEDIUM-confidence entry.
3. **Regex validation:** All regex patterns are individually compiled with `re.compile()` during build. Patterns failing compilation are rejected, preventing a malformed rule from crashing the runtime engine.
4. **Output:** `knowledge_base/network/processed/pii_patterns.csv` — **19 total patterns** (15 HIGH + 4 MEDIUM).

**Output schema:**

```
pattern_name, category, regex, source_reference, source_dataset, confidence
```

### 15.3 Runtime — PIIMatcher and Validators

**Matcher:** `pcap/matchers/pii_matcher.py` — `PIIMatcher`

**Algorithm:** A **single-pass master regex** is compiled at startup by joining all named-group patterns:
```python
master = "|".join(f"(?P<{name}>{regex})" for name, regex in patterns)
```
This yields O(N) complexity over the text, with only one regex engine pass regardless of the number of patterns.

**Validator Registry:** `pcap/matchers/pii_validators.py` implements deterministic post-match validators that are applied after a regex match to eliminate false positives:

| Pattern | Validator | Algorithm |
|---|---|---|
| IMEI | `validate_luhn` | Luhn Mod-10 checksum |
| ICCID | `validate_luhn` | Luhn Mod-10 checksum |
| Credit Card | `validate_luhn` | Luhn Mod-10 checksum |
| Phone Number | `validate_e164` | E.164 bounds check + `+` prefix |
| Email Address | `validate_email` | RFC structural check |
| UUID | `validate_uuid` | `uuid.UUID()` native parser |
| IPv4 | `validate_ipv4` | `ipaddress` octet range check |
| Latitude | `validate_latitude` | Bounds: −90.0 to +90.0 |
| Longitude | `validate_longitude` | Bounds: −180.0 to +180.0 |

Only matches that pass their validator are promoted to `PIIFact` objects. Matches with no registered validator are promoted directly.

**Inspected fields per connection:**
- HTTP URL path
- HTTP header values
- HTTP request/response body (plaintext only)
- DNS query names

TLS-encrypted payloads are never decrypted or inspected.

**Populated fields on `ConnectionRecord`:**
- `pii_facts: List[PIIFact]` — each with `pattern_name`, `category`, `matched_value`, `source_location`, `confidence`, `source_dataset`

### 15.4 PII Categories

| Category | Patterns |
|---|---|
| Identity | Email Address, Phone Number, IMSI, US SSN, UK NHS |
| Hardware | IMEI, ICCID, Android ID, UUID, MAC Address |
| Authentication | Bearer Token, JWT Token, Session ID |
| Location | Latitude, Longitude, SSID |
| Network | IPv4 |
| Financial | Credit Card, Bitcoin Address |

### 15.5 Validation Results (211 PCAPs, 32,793 connections)

| Metric | Value |
|---|---|
| Total patterns | 19 (15 HIGH + 4 MEDIUM) |
| Total PII matches | 10 |
| PCAPs with PII | 4 |
| Top patterns detected | IPv4 (6), Android ID (1), UUID (1), Bearer Token (1) |

---

## 16. PCAP KB Canonical Database Summary

| File | Location | Produced By | Consumed By | Records |
|---|---|---|---|---|
| `trackers.csv` | `network/processed/` | `tracker_builder.py` | `TrackerMatcher` | 47,217 |
| `dns_resolvers.csv` | `network/processed/` | `dns_resolver_builder.py` | `DNSResolverMatcher` | 614 |
| `pii_patterns.csv` | `network/processed/` | `pii_builder.py` | `PIIMatcher` | 19 |
| `GeoLite2-City.mmdb` | `data/geolite/` | MaxMind (external) | `GeoMapper` | — |
| `GeoLite2-ASN.mmdb` | `data/geolite/` | MaxMind (external) | `GeoMapper` | — |
| `canonical_tracker_map.json` | `network/metadata/` | Hand-curated | `tracker_builder.py` | — |
| `canonical_dns_provider_map.json` | `network/metadata/` | Hand-curated | `dns_resolver_builder.py` | — |

---

## 17. PCAP End-to-End Runtime Flow

```
run_pcap_analysis.py
    └─► DatasetManager()
            ├─► load_network_trackers()   →  TrackerMatcher     (47,217 suffix rules)
            ├─► load_geolite()            →  GeoMapper          (City + ASN MMDB)
            ├─► load_dns_resolvers()      →  DNSResolverMatcher (614 IP entries)
            └─► load_pii_patterns()       →  PIIMatcher         (19 patterns, 9 validators)

    NetworkContext(tracker_matcher, geo_mapper, dns_resolver_matcher, pii_matcher)
    ConnectionBuilder(network_context=ctx)

    For each PCAP file:
        parse_pcap(pcap_path) → List[PacketEvent]
        conn_builder.build(events) →
            For each unique (domain, dst_ip, dst_port, protocol) flow:
                ├─► TrackerMatcher.match(domain)         → tracker_fact
                ├─► GeoMapper.lookup_geo(dst_ip)         → geo_fact
                ├─► GeoMapper.lookup_asn(dst_ip)         → asn_fact
                ├─► DNSResolverMatcher.match(resolver_ip)→ dns_resolver_fact
                └─► PIIMatcher.search(url, headers, body)→ List[PIIFact]

            → ConnectionRecord (all facts attached)

        AppSummaryBuilder.build(connections, dns_records) → AppSummary
```

---

## 18. PCAP References

- Exodus Privacy. (2023). Exodus — Tracker analysis platform. https://exodus-privacy.eu.org
- EasyList Authors. (2023). EasyPrivacy — Tracking protection filter list. https://easylist.to
- Frank Denis et al. (2023). DNSCrypt public resolver list. https://github.com/DNSCrypt/dnscrypt-resolvers
- MaxMind. (2023). GeoLite2 Free Geolocation Data. https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
- Microsoft. (2023). Presidio — Data Protection and De-identification SDK. https://github.com/microsoft/presidio
- ITU-T E.164. (2010). The international public telecommunication numbering plan.
- 3GPP TS 23.003. (2023). Numbering, addressing and identification (IMEI, IMSI, ICCID).
- RFC 4122. (2005). A Universally Unique IDentifier (UUID) URN Namespace.
- RFC 6750. (2012). The OAuth 2.0 Authorization Framework: Bearer Token Usage.
- RFC 7519. (2015). JSON Web Token (JWT).
