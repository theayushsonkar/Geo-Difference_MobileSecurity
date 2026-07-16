# Android Geo-Difference Mobile Security Analysis

## Stage 2: DEX / Static Code Analysis

---

# 1. Purpose

The Manifest stage answers:

> What the application declares.

The DEX stage answers:

> What code is actually present.

The DEX stage enriches the existing manifest outputs and extracts code-level facts that cannot reliably be determined from AndroidManifest.xml.

This stage is responsible for:

* SDK verification
* SDK version extraction
* PII API detection
* Secret detection
* Endpoint detection
* Geo-logic detection

This stage is NOT responsible for:

* CVE lookup
* Traffic analysis
* Dynamic analysis
* Native reverse engineering
* Final statistical analysis

The DEX stage should only extract facts.

---

# 2. Architectural Principles

## Principle 1: One Entity = One Table

SDKs are a single logical entity.

Do NOT create:

* manifest_sdks.csv
* dex_sdks.csv
* native_sdks.csv

Instead:

Use:

* manifest_sdks.csv

and enrich existing rows.

Manifest and DEX are merely different evidence sources.

---

## Principle 2: Findings Are Separate Entities

Secrets, endpoints, PII APIs and geo logic are not SDKs.

These belong in:

* static_code_findings.csv

---

## Principle 3: Raw Facts First

Store:

* detected_smali
* sdk_version
* sdk_version_source

Do NOT store:

* vulnerability score
* risk score
* country risk
* security grade

Those belong in later analysis.

---

## Principle 4: CVE Ready, Not CVE Enabled

DEX stage prepares for CVE enrichment.

DEX stage does NOT perform CVE lookup.

---

# 3. Inputs

Per sample:

## Required

Decoded APK directory

Example:

decoded/
├── AndroidManifest.xml
├── smali/
├── smali_classes2/
├── smali_classes3/
├── res/
├── assets/
└── META-INF/

---

## Existing Outputs

manifest_apps.csv

Used for:

* sample_id
* package_name
* app_country_code
* app_region_group
* has_smali

manifest_sdks.csv

Used for:

* existing SDK rows

---

# 4. Outputs

## Updated

manifest_sdks.csv

---

## New

static_code_findings.csv

---

# 5. Processing Pipeline

For each sample:

Step 1

Load sample metadata.

Step 2

Check:

has_smali

If False:

Skip sample.

Record skip statistics.

Step 3

Load existing SDK rows.

Step 4

Scan smali files.

Step 5

Scan resources.

Step 6

Aggregate findings.

Step 7

Update SDK rows.

Step 8

Write outputs.

---

# 6. Smali Discovery Algorithm

Goal:

Efficiently discover all code files.

Directories to scan:

smali/
smali_classes2/
smali_classes3/
smali_classesN/

Algorithm:

Recursively walk.

Collect:

*.smali

Ignore:

binary files
images
compiled resources

Store:

relative path
absolute path

Example:

smali/com/google/firebase/FirebaseApp.smali

---

# 7. SDK Detection Algorithm

Purpose:

Verify SDK presence from actual code.

---

## Input

SDK mapping database.

Example:

com.google.firebase
com.applovin
com.google.android.gms
com.bytedance.sdk
com.mbridge

---

## Step 1

Convert path into package notation.

Example:

smali/com/google/firebase/FirebaseApp.smali

↓

com.google.firebase.FirebaseApp

---

## Step 2

Perform longest-prefix match.

Example:

SDK Prefix:

com.google.firebase

File:

com.google.firebase.messaging.FirebaseMessaging

Match:

Firebase

---

## Step 3

Create evidence.

Evidence contains:

sdk_name
sdk_prefix
source_file

---

## Step 4

Aggregate per:

(sample_id, sdk_name)

NOT per file.

---

## Step 5

Update SDK table.

If SDK exists:

update row.

If SDK missing:

create row.

---

# 8. SDK Version Extraction Algorithm

Purpose:

Prepare future CVE enrichment.

---

## Search Order

Always follow this order.

---

### Level 1

META-INF/maven/**/pom.properties

Confidence:

HIGH

---

### Level 2

BuildConfig.smali

Look for:

VERSION_NAME
VERSION_CODE

Confidence:

HIGH

---

### Level 3

Known SDK constants.

Example:

const-string "22.0.1"

Confidence:

MEDIUM

---

### Level 4

Resource strings.

Example:

res/values/strings.xml

Confidence:

LOW-MEDIUM

---

### Level 5

Metadata files.

Confidence:

LOW

---

## Output

sdk_version

sdk_version_source

sdk_version_confidence

Values:

high
medium
low
none

---

## Failure Case

Version not found.

Store:

sdk_version = null

sdk_version_confidence = none

---

# 9. SDK Ecosystem Mapping Algorithm

Purpose:

Prepare future CVE enrichment.

---

Store:

sdk_ecosystem

sdk_identifier

---

Examples

Firebase

sdk_ecosystem:

maven

sdk_identifier:

com.google.firebase:firebase-common

---

Bytedance

sdk_ecosystem:

custom

sdk_identifier:

com.bytedance.sdk

---

Never force PURL generation here.

That belongs to CVE enrichment.

---

# 10. PII API Detection Algorithm

Purpose:

Detect sensitive data collection.

---

High-confidence API families:

GAID

Android_ID

Location

Contacts

Camera

Microphone

IMEI

Bluetooth

Clipboard

SMS

CallLog

---

Detection Strategy

Compile regexes once.

Scan method invocations.

Normalize into API family.

Example:

AdvertisingIdClient

↓

GAID

---

Store:

finding_type = pii_api

finding_subtype = GAID

normalized_value = GAID

---

Metadata:

calling package
method signature

---

# 11. Secret Detection Algorithm

Purpose:

Find embedded secrets.

---

Targets:

API Keys

AWS Keys

JWTs

OAuth Tokens

High Entropy Tokens

Firebase URLs

Google API Keys

---

Detection Strategy

Regex based.

Entropy based.

---

Output

finding_type = secret

finding_subtype = aws_key

normalized_value = aws_key

---

Metadata

entropy
pattern_name
provider

---

# 12. Endpoint Detection Algorithm

Purpose:

Identify network infrastructure.

---

Targets

Domains

URLs

IPs

Hosts

Region-specific endpoints

---

Normalization

https://api.example.com/v1

↓

api.example.com

---

Output

finding_type = endpoint

normalized_value = api.example.com

---

Metadata

protocol
port
is_ip

---

# 13. Geo Logic Detection Algorithm

Purpose:

Identify region-specific code paths.

Secondary feature.

Not a primary objective.

---

High Confidence Patterns

Locale.getCountry()

Locale.getDefault()

BuildConfig.REGION

BuildConfig.COUNTRY

TelephonyManager.getNetworkCountryIso()

SIM Country

MCC

MNC

---

Do NOT use:

IN

US

zh

en

alone.

Those create noise.

---

Output

finding_type = geo_logic

finding_subtype = country_check

---

Metadata

pattern
condition

---

# 14. Resource Scanning Algorithm

Scan:

res/values/*.xml

res/xml/*.xml

assets/*.json

assets/*.txt

other text resources

---

Targets:

Secrets

Endpoints

SDK Metadata

Version Strings

Geo Strings

---

Use same extraction logic.

---

# 15. Deduplication Algorithm

Goal:

Avoid duplicate rows.

---

Dedup Key

(sample_id,
finding_type,
normalized_value)

---

Example

api.example.com

appears 50 times.

Output:

ONE row.

---

Store:

occurrence_count = 50

source_file_count = 50

---

Implementation

Dictionary:

key:

(sample_id,
finding_type,
normalized_value)

value:

FindingAggregate

---

# 16. finding_metadata Design

Purpose:

Avoid sparse schemas.

Store JSON.

---

Endpoint Example

{
"protocol":"https",
"port":443
}

---

Secret Example

{
"entropy":4.8,
"pattern":"aws_key"
}

---

PII Example

{
"api_family":"GAID",
"calling_sdk":"com.applovin"
}

---

# 17. Performance Strategy

Version 1

Use:

compiled regexes

parallel workers

smali text scanning

---

Do NOT use:

AST parsing

androguard

LIEF

unless scaling becomes a problem.

---

# 18. Aggregation Strategy

Per sample:

SDK Evidence Aggregate

Finding Aggregate

Version Aggregate

---

Write once at end.

Avoid repeated CSV writes.

---

# 19. Validation Rules

SDK Validation

Valid sdk_name

Valid prefix

Valid ecosystem

Valid version confidence

---

Finding Validation

Valid finding_type

Valid confidence

Valid metadata JSON

occurrence_count > 0

---

# 20. Future CVE Integration

Input:

sdk_name

sdk_version

sdk_version_confidence

sdk_ecosystem

sdk_identifier

---

Future CVE Stage

Will:

Generate PURLs when possible.

Query CVE snapshot.

Write:

sdk_cve_enrichment.csv

---

DEX stage does NOT perform this work.

It only prepares the required inputs.
