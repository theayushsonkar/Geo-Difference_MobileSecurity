# Knowledge Base Module: Technical Overview

**Geo-Difference Mobile Security — Static Analysis Research System**

---

## Abstract

The `knowledge_base` module is the detection intelligence layer of a large-scale Android static analysis system designed to identify privacy-sensitive API usage, hardcoded secrets, and indirect geo-inference logic across thousands of APKs. The module is architecturally divided into two strictly non-overlapping phases: an **offline build pipeline** that ingests, normalizes, and consolidates three heterogeneous academic and industry datasets into a single canonical database; and a **runtime detection engine** that applies high-performance pattern matching against decompiled Smali bytecode during live APK scanning. This document describes both phases in full technical detail, covering dataset provenance, parsing mechanics, deduplication strategy, in-memory enrichment, and the algorithmic rationale for each matcher.

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
