# Component Dataset (`manifest_components.csv`)

## Purpose

This dataset stores information about all Android components declared inside the application's `AndroidManifest.xml`. 
Each row in this dataset represents **one component** declared in the manifest.

---

## Metadata Fields

### `run_id`

**What it stores:**
Identifier of the extraction run.

**Why it is stored:**
Helps track which execution of the tool generated the record.

---

### `schema_version`

**What it stores:**
Version of the dataset schema.

**Why it is stored:**
Allows future versions of the dataset to remain compatible and interpretable.

---

### `parser_version`

**What it stores:**
Version of the extractor used to generate the record.

**Why it is stored:**
Makes it possible to identify which version of the extraction logic produced the result.

---

## Application Identification Fields

### `sample_id`

**What it stores:**
Unique identifier assigned to the application sample.

**Why it is stored:**
Used to connect this component information with other datasets generated from the same application.

---

### `package_name`

**What it stores:**
Android package name of the application.

**Why it is stored:**
Provides a human-readable identifier for the application.

Example:

```text
com.ecffri.arrows
```

---

### `app_country_code`

**What it stores:**
Country label assigned to the application sample.

Examples:

```text
IN
US
BR
CN
```

**Why it is stored:**
Allows grouping applications by country.

---

### `app_region_group`

**What it stores:**
Higher-level geographical region assigned to the application.

Examples:

```text
south_asia
east_asia
eu_member
```

**Why it is stored:**
Allows grouping applications at the regional level.

---

## Component Identification Fields

### `component_id`

**What it stores:**
Unique identifier for the component record.

**Why it is stored:**
Provides a stable identifier for each component.

---

### `component_type`

**What it stores:**
Type of Android component.

Possible values:

```text
activity
activity-alias
service
receiver
provider
```

**Why it is stored:**
Different component types serve different purposes and expose different functionality.

---

### `component_name`

**What it stores:**
Full component class name.

Example:

```text
com.unity3d.player.UnityPlayerActivity
```

**Why it is stored:**
Identifies the exact component declared by the application.

---

### `component_name_format`

**What it stores:**
Format used when the component name was declared.

Examples:

```text
fully_qualified
relative
simple
```

**Why it is stored:**
Useful for preserving how the component originally appeared in the manifest.

---

### `source_xml`

**What it stores:**
XML file from which the component was extracted.

**Why it is stored:**
Provides traceability back to the original source.

---

## Component State Fields

### `enabled_explicit_present`

**What it stores:**
Whether `android:enabled` was explicitly defined.

**Why it is stored:**
Distinguishes between an explicitly configured value and a default Android value.

---

### `enabled_explicit_value`

**What it stores:**
Value assigned to `android:enabled`.

Examples:

```text
true
false
```

**Why it is stored:**
Preserves the original manifest configuration.

---

### `enabled_effective`

**What it stores:**
Final enabled state of the component after applying Android defaults.

**Why it is stored:**
Represents whether the component is effectively active.

---

## Exported Component Fields

### `exported_explicit_present`

**What it stores:**
Whether `android:exported` was explicitly declared.

**Why it is stored:**
The meaning of exported components depends on whether the attribute is explicitly present.

---

### `exported_explicit_value`

**What it stores:**
Raw value of `android:exported`.

Examples:

```text
true
false
```

**Why it is stored:**
Preserves the original manifest value.

---

### `exported_effective`

**What it stores:**
Final exported state after applying Android version-specific rules.

**Why it is stored:**
Indicates whether external applications can access the component.

---

### `exported_effective_source`

**What it stores:**
Reason used to determine the effective exported value.

Examples:

```text
explicit
legacy_default
provider_default
unknown
missing_on_android12plus
```

**Why it is stored:**
Makes the exported-state calculation transparent and reproducible.

---

### `android12_exported_violation`

**What it stores:**
Whether the component violates Android 12 exported-component requirements.

**Why it is stored:**
Android 12 requires explicit exported declarations for components with intent filters.

---

## Intent Filter Fields

### `has_intent_filter`

**What it stores:**
Whether the component contains at least one intent filter.

**Why it is stored:**
Intent filters define how a component can be invoked.

---

### `intent_filter_count`

**What it stores:**
Number of intent filters declared by the component.

**Why it is stored:**
Provides a measure of how many invocation rules are associated with the component.

---

### `action_count`

**What it stores:**
Number of intent actions declared.

**Why it is stored:**
Shows how many actions the component can respond to.

---

### `category_count`

**What it stores:**
Number of intent categories declared.

**Why it is stored:**
Provides additional information about invocation conditions.

---

### `data_count`

**What it stores:**
Number of data elements declared within intent filters.

**Why it is stored:**
Useful for understanding URI and deep-link configurations.

---

## Deep Link Fields

### `custom_scheme_count`

**What it stores:**
Number of custom URI schemes handled by the component.

Examples:

```text
fbconnect://
myapp://
game://
```

**Why it is stored:**
Custom schemes are commonly used for deep linking and inter-application communication.

---

### `http_scheme_count`

**What it stores:**
Number of HTTP schemes handled.

**Why it is stored:**
Indicates support for HTTP-based deep links.

---

### `https_scheme_count`

**What it stores:**
Number of HTTPS schemes handled.

**Why it is stored:**
Indicates support for HTTPS-based deep links.

---

### `market_scheme_count`

**What it stores:**
Number of market URI schemes handled.

**Why it is stored:**
Captures integration with application marketplaces.

---

### `other_scheme_count`

**What it stores:**
Number of URI schemes that do not belong to known categories.

**Why it is stored:**
Ensures uncommon URI schemes are not lost during analysis.

---

## Launch and Browser Fields

### `is_launcher`

**What it stores:**
Whether the component is the application's launcher activity.

**Why it is stored:**
Identifies the main activity shown when the user launches the app.

---

### `is_browsable`

**What it stores:**
Whether the component is browsable from a web browser.

**Why it is stored:**
Browsers can invoke browsable activities through URLs.

---

## Permission Protection Fields

### `has_permission_guard`

**What it stores:**
Whether access to the component is protected by a permission.

**Why it is stored:**
Shows whether Android permission checks are used to restrict access.

---

### `permission_name`

**What it stores:**
Permission associated with the component.

**Why it is stored:**
Preserves the exact permission used for protection.

---

## Process and Execution Fields

### `direct_boot_aware`

**What it stores:**
Whether the component can operate before device unlock.

**Why it is stored:**
Represents component behavior during the Direct Boot phase.

---

### `isolated_process`

**What it stores:**
Whether the component runs inside an isolated process.

**Why it is stored:**
Captures process-level isolation settings.

---

### `process_name`

**What it stores:**
Custom process assigned to the component.

**Why it is stored:**
Shows whether the component executes in a dedicated process.

---

## Content Provider Fields

### `grant_uri_permissions`

**What it stores:**
Whether temporary URI permissions can be granted.

**Why it is stored:**
Captures content-sharing behavior configured by the provider.

---

### `path_permission_count`

**What it stores:**
Number of path-specific permission rules declared by a provider.

**Why it is stored:**
Shows whether provider access control is configured at a finer granularity.

---

## App Link Field

### `auto_verify`

**What it stores:**
Whether Android App Link verification is enabled.

**Why it is stored:**
Indicates the use of verified domain-based deep linking.
