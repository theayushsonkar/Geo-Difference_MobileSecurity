# Static Code Findings Dataset (`manifest_static_code_findings.csv`)

Each row represents **one distinct finding discovered via static code analysis within one application**.

This dataset captures hardcoded secrets, privacy-sensitive API usage, and geo-sensitive logic found directly in the application's code (smali), resources, and configuration files. It is powered by the Knowledge Base module, utilizing the Aho-Corasick algorithm for high-performance pattern matching.

---

## Metadata Fields

### `run_id`

**What it stores:**
Identifier of the extraction run that produced the record.

**Why it is stored:**
Allows the output to be traced back to a specific execution of the analysis pipeline.

---

### `schema_version`

**What it stores:**
Version of the dataset schema.

**Why it is stored:**
Ensures that the structure of the dataset remains interpretable even if new columns are added in future versions.

---

### `parser_version`

**What it stores:**
Version of the extraction tool.

**Why it is stored:**
Makes it possible to identify which version of the extraction logic generated the result.

---

## Application Identification Fields

These fields identify the application in which the finding was detected.

---

### `sample_id`

**What it stores:**
Unique identifier assigned to the analyzed application sample.

**Why it is stored:**
Acts as the link between this dataset and all other datasets generated for the same application.

---

### `package_name`

**What it stores:**
Android package name of the application.

**Why it is stored:**
Provides a human-readable identifier for the application and simplifies verification of results.

---

### `app_country_code`

**What it stores:**
Country or market associated with the application sample.

**Why it is stored:**
Allows findings to be grouped and compared across countries.

---

### `app_region_group`

**What it stores:**
Higher-level geographical grouping assigned to the application.

**Why it is stored:**
Allows findings to be compared across broader regions.

---

## Finding Identification Fields

These fields describe the nature and classification of the static code finding.

---

### `finding_id`

**What it stores:**
A deterministic hash identifying the unique combination of finding type, subtype, and normalized value within this specific sample.

**Why it is stored:**
Provides a unique identifier for the finding record.

---

### `finding_type`

**What it stores:**
The high-level category of the finding.

Examples:

```text
secret
pii_api
geo_logic
```

*(Note: `pii_api` findings represent privacy-sensitive API usages mapped directly from the integrated Axplorer, PScout, and GMS databases).*

**Why it is stored:**
Allows analysts to filter findings by broad security or privacy domains.

---

### `finding_subtype`

**What it stores:**
The specific rule or classification that triggered the finding.

Examples:

```text
google_api_key
aws_access_key
location_gps
device_id_imei
```

**Why it is stored:**
Provides granular categorization of the specific data or logic that was discovered.

---

### `normalized_value`

**What it stores:**
The canonical representation of the finding. For secrets, this may be the secret itself. For APIs, it is the canonical method signature.

**Why it is stored:**
Allows grouping of identical findings (e.g., the same API key used in multiple places).

---

### `finding_confidence`

**What it stores:**
The confidence level of the rule that generated the finding.

Examples:

```text
low
medium
high
exact
```

**Why it is stored:**
Helps analysts prioritize findings and filter out potential false positives.

---

## Evidence Fields

These fields describe where and how the finding was located in the application.

---

### `occurrence_count`

**What it stores:**
The total number of times this specific finding was encountered across all files in the application.

**Why it is stored:**
Indicates the prevalence of the hardcoded secret or API usage.

---

### `source_file_count`

**What it stores:**
The number of distinct files that contain the finding.

**Why it is stored:**
Shows how widely distributed the finding is throughout the codebase.

---

### `source_layer`

**What it stores:**
The layer of the application where the finding was primarily discovered.

Examples:

```text
smali
res_xml
res_values
manifest_meta_data
assets_json
```

**Why it is stored:**
Provides context on whether the finding was in compiled code, configuration files, or assets.

---

### `source_file`

**What it stores:**
A representative file path where the finding was located.

Example:

```text
smali/com/example/app/MainActivity.smali
```

**Why it is stored:**
Provides a starting point for manual verification or triage.

---

### `evidence_snippet`

**What it stores:**
A short snippet of the text or code surrounding the finding.

**Why it is stored:**
Provides immediate context for the finding without requiring the analyst to decompile the application.

---

### `finding_metadata`

**What it stores:**
Additional JSON-formatted metadata associated with the finding (e.g., related permissions, flags, or contextual hints).

**Why it is stored:**
Provides an extensible field for complex findings that require more detail than a single category or value.

---

# Summary

This dataset records:

* Hardcoded secrets and credentials discovered in the application.
* Usage of privacy-sensitive APIs (PII).
* Presence of geo-sensitive logic or endpoints.
* Exactly where these findings were located in the decompiled layers.

Together, these fields provide a detailed view of the application's internal security posture and privacy behaviors as discovered through static code analysis.
