# SDK Dataset (`manifest_sdks.csv`)

Each row represents **one detected SDK within one application**.

This dataset is used to capture the third-party SDKs integrated into Android applications. The dataset records what SDKs are present, where they come from, how they were identified, and what evidence was used to detect them.

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

These fields identify the application in which the SDK was detected.

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

Example:

```text
com.ecffri.arrows
```

---

### `app_country_code`

**What it stores:**
Country or market associated with the application sample.

Examples:

```text
IN
US
BR
CN
```

**Why it is stored:**
Allows SDK usage to be grouped and compared across countries.

---

### `app_region_group`

**What it stores:**
Higher-level geographical grouping assigned to the application.

Examples:

```text
south_asia
east_asia
eu_member
```

**Why it is stored:**
Provides a broader geographical view when analyzing applications across multiple countries.

---

## SDK Identification Fields

These fields describe the detected SDK.

---

### `sdk_id`

**What it stores:**
Unique identifier for the SDK record.

**Why it is stored:**
Provides a stable reference for each SDK entry and prevents duplicate records.

---

### `sdk_name`

**What it stores:**
Human-readable name of the SDK.

Examples:

```text
Firebase
AppLovin
Pangle
InMobi
```

**Why it is stored:**
Identifies the specific SDK integrated into the application.

---

### `sdk_prefix`

**What it stores:**
Package prefix used to identify the SDK.

Examples:

```text
com.google.firebase
com.applovin
com.bytedance.sdk
```

**Why it is stored:**
Preserves the exact signature that matched the SDK and makes the detection process transparent.

---

### `sdk_version`

**What it stores:**
Detected SDK version.

**Why it is stored:**
Provides version information that may be useful for future analysis and validation.

Example:

```text
Firebase 20.x
Firebase 32.x
```

---

### `sdk_category`

**What it stores:**
Functional role of the SDK.

Examples:

```text
ad_network
analytics
attribution
social
game_engine
crash_reporting
```

**Why it is stored:**
Allows SDKs to be grouped based on their purpose rather than their specific vendor.

---

## Vendor Origin Fields

These fields describe the organization that develops the SDK.

---

### `vendor_country_code`

**What it stores:**
Country associated with the SDK vendor.

Examples:

```text
US
CN
IN
IL
```

**Why it is stored:**
Records the geographical origin of the SDK vendor and helps describe the application's software supply chain.

---

### `vendor_region_group`

**What it stores:**
Region associated with the SDK vendor.

Examples:

```text
north_america
east_asia
south_asia
```

**Why it is stored:**
Provides a broader geographical grouping of SDK vendors.

---

## Detection Fields

These fields describe how the SDK was identified.

---

### `detected_manifest`

**What it stores:**
Whether the SDK was detected using manifest information.

**Why it is stored:**
Documents the source of the detection and improves traceability.

---

### `detected_smali`

**What it stores:**
Whether the SDK was detected from application code (smali).

**Why it is stored:**
Reserved for future static-analysis stages and maintains compatibility with later versions of the analysis pipeline.

---

### `detected_native`

**What it stores:**
Whether the SDK was detected from native libraries.

**Why it is stored:**
Allows future integration of native-library analysis without changing the dataset structure.

---

### `detected_strings`

**What it stores:**
Whether the SDK was detected from resource files, configuration files, or string values.

**Why it is stored:**
Allows future integration of additional detection sources while keeping the schema consistent.

---

### `detection_source_primary`

**What it stores:**
Primary source used to identify the SDK.

Examples:

```text
manifest
smali
native
strings
```

**Why it is stored:**
Records the strongest source of evidence used for detection.

---

## Evidence Fields

These fields explain why the SDK was detected.

---

### `evidence_type`

**What it stores:**
Type of evidence used for SDK identification.

Examples:

```text
component_name
provider_authority
meta_data
service_name
receiver_name
```

**Why it is stored:**
Documents the type of manifest element that matched the SDK signature.

---

### `evidence_value`

**What it stores:**
Exact value that matched the SDK signature.

Example:

```text
com.google.firebase.auth.internal.GenericIdpActivity
```

**Why it is stored:**
Provides complete transparency into the detection process and allows manual verification of results.

---

### `evidence_count`

**What it stores:**
Number of matching evidence points found for the SDK.

Example:

```text
AppLovin = 18 evidence points
Firebase = 7 evidence points
```

**Why it is stored:**
Provides a rough indication of how extensively the SDK appears throughout the application.

---

# Summary

This dataset records:

* Which SDKs are present in an application.
* What type of functionality each SDK provides.
* The geographical origin of SDK vendors.
* How each SDK was detected.
* The evidence used to support each detection.

Together, these fields provide a structured view of the application's third-party software supply chain as observed during manifest analysis.

