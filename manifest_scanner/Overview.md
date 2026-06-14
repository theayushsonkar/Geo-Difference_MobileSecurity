# Android Manifest Scanner
---

# Objectives

The scanner is designed to answer questions such as:

* What permissions does an application request?
* What Android components does an application expose?
* What third-party SDKs are present?
* What network security policies are configured?
* How do applications differ across countries and regions?
* Do applications distributed in different markets use different SDK ecosystems?
* Do different regions expose different attack-surface characteristics?

To support these goals, the scanner extracts facts from AndroidManifest.xml and related XML resources and stores them in structured datasets.

---

# Project Structure

The scanner is implemented as a modular package.

```text
manifest_scanner/
│
├── __init__.py
├── constants.py
├── models.py
├── schema.py
├── sample_index.py
├── extractor.py
├── output.py
├── runner.py
│
└── scan_manifest.py
```

---

## `constants.py`

Contains:

* Permission family mappings
* SDK database
* Region mappings
* Regex patterns
* Android constants
* Network security constants

This file acts as the reference database used during extraction.

---

## `models.py`

Contains data structures used throughout the scanner.

Examples:

```text
AppFeatures
SDKRecord
PermissionRecord
ComponentRecord
NetworkDomainRecord
```

These models provide a consistent representation of extracted data.

---

## `schema.py`

Defines:

* Dataset schemas
* Column ordering
* Default values
* Data normalization rules

This ensures all output files follow a stable structure.

---

## `sample_index.py`

Loads and validates the input sample index.

Responsible for:

* Reading sample metadata
* Validating sample identifiers
* Validating APK hashes
* Preparing records for analysis

---

## `extractor.py`

Core extraction engine.

Responsible for:

* Manifest parsing
* Permission extraction
* Component analysis
* SDK detection
* Deep-link extraction
* Secret detection
* Network security configuration parsing

Most feature extraction logic resides here.

---

## `output.py`

Handles output generation.

Responsible for:

* CSV writing
* JSON writing
* Foreign-key validation
* Type normalization
* Dataset consistency checks

---

## `runner.py`

Coordinates the overall scanning process.

Responsible for:

* Iterating through samples
* Calling extraction modules
* Handling failures
* Writing final outputs

---

## `scan_manifest.py`

Thin command-line entry point.

Used to start the scanner.

---

# Input Requirements

The scanner expects a `sample_index.csv` file.

Each row represents one application sample.

The index provides:

* Sample identifiers
* Country labels
* Region labels
* APK hashes
* Source paths

The scanner uses this file as the source of truth for all application metadata.

---

# Running the Scanner

Execute the scanner using:

```powershell
python scan_manifest.py --index path/to/sample_index.csv --output ./output
```

Example:

```powershell
python scan_manifest.py --index dataset/sample_index.csv --output results
```

---

# Output Datasets

The scanner generates multiple datasets.

## 1. `manifest_apps.csv`

One row per application.

Contains aggregated features such as:

* Permission counts
* SDK counts
* Exported component counts
* Network security summaries
* Deep-link summaries

This is the primary dataset used for application-level analysis.

---

## 2. `manifest_permissions.csv`

One row per permission declaration.

Contains:

* Requested permissions
* Declared permissions
* Protection levels
* Permission families

---

## 3. `manifest_components.csv`

One row per Android component.

Contains:

* Activities
* Services
* Receivers
* Providers
* Export status
* Intent filters
* Deep-link information

---

## 4. `manifest_sdks.csv`

One row per detected SDK.

Contains:

* SDK identity
* Vendor origin
* SDK category
* Detection evidence

---

## 5. `manifest_network_domains.csv`

One row per network security rule.

Contains:

* Network Security Configuration data
* Domain-specific rules
* Cleartext policies
* Certificate trust settings
* Pinning information

---

## 6. `manifest_trace.json`

Detailed trace output.

Contains:

* Raw evidence
* Derived values
* Extraction metadata
* Validation information

Used primarily for debugging, auditing, and reproducibility.

---

# Dataset Relationships

All datasets are linked using:

```text
sample_id
```

Relationship structure:

```text
manifest_apps.csv
        │
        ├── manifest_permissions.csv
        ├── manifest_components.csv
        ├── manifest_sdks.csv
        └── manifest_network_domains.csv
```

`sample_id` acts as the primary key in `manifest_apps.csv` and as a foreign key in all supporting datasets.

---

# What This Stage Covers

The manifest scanner extracts:

### Application Metadata

* Package names
* Versions
* SDK targets
* Installation preferences

### Permissions

* Requested permissions
* Declared permissions
* Permission families
* Privacy Sandbox permissions

### Components

* Activities
* Services
* Receivers
* Providers
* Exported status
* Deep links

### Third-Party SDKs

* SDK identification
* Vendor origin
* SDK categories

### Network Security Configuration

* Cleartext policies
* Domain exceptions
* Certificate pinning
* Trust anchors
* Debug overrides

### Manifest Configuration

* Backup settings
* Shared user IDs
* Instrumentation
* Queries visibility

---