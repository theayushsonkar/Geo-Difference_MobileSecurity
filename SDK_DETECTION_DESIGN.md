# SDK Detection Design

This document defines the SDK detection engine for the future DEX/static-analysis stage while keeping the existing manifest SDK table as the single SDK output table.

It does not implement detection logic. It specifies inputs, matching rules, aggregation behavior, edge cases, and the intended SDK universe.

## Scope

The detection engine should support two sources of SDK evidence:

- Manifest evidence from `AndroidManifest.xml`
- DEX/code evidence from smali and related static-analysis artifacts

The output remains a single SDK table, `manifest_sdks.csv`, with enriched fields for both manifest and DEX evidence.

## Curated SDK Universe

The curated SDK catalog is the human-maintained SDK universe used by both manifest and DEX stages.

Known Maven-backed SDKs should use:

- `sdk_ecosystem = "maven"`
- `sdk_identifier = <best known Maven coordinate>`

SDKs that cannot be mapped reliably to Maven should use:

- `sdk_ecosystem = "custom"`
- `sdk_identifier = <best known stable identifier>`

### Current curated entries

- Google Play Services
  - `sdk_prefix = com.google.android.gms`
  - `sdk_ecosystem = maven`
  - `sdk_identifier = com.google.android.gms:play-services-basement`
- Firebase
  - `sdk_prefix = com.google.firebase`
  - `sdk_ecosystem = maven`
  - `sdk_identifier = com.google.firebase:firebase-common`
- AndroidX
  - `sdk_prefix = androidx`
  - `sdk_ecosystem = maven`
  - `sdk_identifier = androidx.core:core`
- Google Play Core
  - `sdk_prefix = com.google.android.play`
  - `sdk_ecosystem = maven`
  - `sdk_identifier = com.google.android.play:core`
- Play Billing
  - `sdk_prefix = com.android.billingclient`
  - `sdk_ecosystem = maven`
  - `sdk_identifier = com.android.billingclient:billing`
- AppLovin MAX
  - `sdk_prefix = com.applovin`
  - `sdk_ecosystem = maven`
  - `sdk_identifier = com.applovin.max`
- ironSource / LevelPlay
  - `sdk_prefix = com.ironsource`
  - `sdk_ecosystem = custom`
  - `sdk_identifier = com.ironsource.sdk`
- Unity Ads
  - `sdk_prefix = com.unity3d.ads`
  - `sdk_ecosystem = maven`
  - `sdk_identifier = com.unity3d.ads:unity-ads`
- Facebook SDK
  - `sdk_prefix = com.facebook`
  - `sdk_ecosystem = maven`
  - `sdk_identifier = com.facebook.android:facebook-core`
- Sentry
  - `sdk_prefix = io.sentry`
  - `sdk_ecosystem = maven`
  - `sdk_identifier = io.sentry:sentry-android-core`
- Glide
  - `sdk_prefix = com.bumptech.glide`
  - `sdk_ecosystem = maven`
  - `sdk_identifier = com.github.bumptech.glide:glide`
- Unity Engine
  - `sdk_prefix = com.unity3d.player`
  - `sdk_ecosystem = custom`
  - `sdk_identifier = com.unity3d.player`

### Requested additions for the shared SDK universe

These should be part of the same curated universe used by both manifest and DEX stages:

- ByteDance / Pangle
  - `sdk_prefix = com.bytedance`
  - `sdk_ecosystem = custom`
  - `sdk_identifier = com.bytedance.sdk`
  - vendor country: `CN`
  - vendor region: `east_asia`
  - category: `ad_network`
  - smali aliases: `com/bytedance`, `com/bytedance/sdk`, `com/ss/android`, `com/pangle`
- Mintegral
  - `sdk_prefix = com.mbridge`
  - `sdk_ecosystem = custom`
  - `sdk_identifier = com.mbridge`
  - vendor country: `CN`
  - vendor region: `east_asia`
  - category: `ad_network`
  - smali aliases: `com/mbridge`, `com/mbridge/msdk`

### Catalog review rules

- Prefer Maven coordinates when they are stable and widely recognized.
- Use `custom` only when no reliable Maven coordinate exists.
- Keep the catalog small and curated.
- Do not auto-map every SDK to a PURL.
- Preserve vendor country, vendor region, and SDK category metadata when known.

## Inputs

The detection engine should consume these inputs per sample:

- `SampleRecord`
- Parsed manifest tree
- Manifest meta-data entries
- Smali file paths and class descriptors
- Resource XML files
- Optional string pools or decoded string artifacts

The engine should produce:

- Enriched SDK rows
- Aggregated evidence counts
- Trace evidence for debugging and auditability

## Data Structures

The engine should work with these logical structures:

- `SampleRecord` for sample metadata
- `SDKCatalogEntry` for curated SDK definitions
- `SDKEvidence` for one evidence item
- `SDKAggregate` for one deduplicated SDK row candidate
- `SDKRecord` for final serialized output

## How Smali Files Are Discovered

DEX-stage SDK detection should discover smali artifacts by scanning the extracted application directory for:

- `smali/`
- `smali_classes2/`
- `smali_classes3/`
- additional `smali_classesN/` folders
- any other decoded smali directories present in the sample root

Discovery should be based on directory presence and file extension checks, not assumptions about a fixed number of DEX splits.

## Package Name Conversion

Smali class descriptors should be normalized into dotted package names by:

- removing the leading `L` from a class descriptor
- removing the trailing `;`
- replacing `/` with `.`

Examples:

- `Lcom/bytedance/sdk/openadsdk/TTAdConfig;` -> `com.bytedance.sdk.openadsdk.TTAdConfig`
- `Lio/sentry/android/core/SentryInitProvider;` -> `io.sentry.android.core.SentryInitProvider`

The engine should also preserve the original smali path as evidence because package normalization is lossy.

## SDK Matching

SDK matching should compare evidence against the curated catalog using multiple signals:

- Manifest package names and manifest component names
- Smali package paths
- Smali class descriptors
- Resource or string evidence when available

Matching should be prefix-based with curated aliases. Each catalog entry can match by:

- canonical SDK prefix
- smali aliases
- optional manifest package prefixes

## Why Longest-Prefix Matching Is Needed

Longest-prefix matching is necessary because many SDKs share broad namespace roots.

Examples:

- `com.google.android.gms` contains many subpackages
- `com.bytedance` may cover multiple product families
- `com.mbridge` may match both SDK framework classes and deeper feature namespaces

Without longest-prefix matching, a broad parent SDK could absorb evidence that belongs to a more specific child SDK, or duplicate rows could be created for one SDK family.

The engine should therefore select the most specific curated match among all candidates.

## Evidence Count

`evidence_count` should count all matched evidence items supporting the same SDK within the same app.

That means:

- one app may contribute many evidence points to one SDK row
- repeated matches from different files or classes should increase the count
- repeated matches from the same source should still count as multiple occurrences if they are distinct evidence hits

The final output should reflect the total support for that SDK, not only the first hit.

## Aggregation Rules

Multiple matches for the same SDK should be aggregated into one SDK row per logical SDK identity.

Aggregation should combine:

- manifest evidence
- smali evidence
- native evidence when added later
- string evidence when added later

A single SDK row should keep:

- the strongest primary evidence source
- the best version candidate, if any
- the best-known SDK identifier
- the total evidence count

## Updating Existing SDK Rows

If the same SDK is detected from both manifest and DEX evidence:

- reuse the same logical SDK identity
- update detection flags such as `detected_manifest` and `detected_smali`
- merge evidence counts
- preserve the strongest version source
- keep the best-known identifier and ecosystem information

The row should remain a single record rather than duplicating SDK entries by source.

## Creating DEX-Only SDK Rows

If an SDK is found only from DEX evidence:

- create one SDK row for that app and SDK identity
- set `detected_smali = true`
- leave `detected_manifest = false`
- set `detection_source_primary` according to the strongest available source
- leave version fields empty when no reliable version can be derived

DEX-only SDK rows should still use the same output table and schema.

## Edge Cases

- A single SDK may appear in multiple split DEX files.
- One package prefix may match several catalog entries; choose the most specific prefix.
- Some SDKs have no version artifacts at all.
- Some SDKs expose multiple potential identifiers; keep the best known one, not all of them.
- Some prefixes are broad enough to match application code as well as vendor code; rely on curated aliases and evidence weighting.
- Some SDKs are present in manifest only, DEX only, or both.
- Some SDKs may be custom/vendor-specific and should not be forced into Maven coordinates.

## Complexity Analysis

Let:

- `S` be the number of smali files or class entries
- `C` be the number of curated SDK catalog entries
- `E` be the number of evidence hits

A straightforward prefix-based matcher is approximately:

- discovery: `O(S)`
- matching: `O(E * C)` in the naive form

If catalog entries are indexed by prefix length or prefix trie, matching can be reduced substantially.

Because the catalog is intended to stay small and curated, a simple linear match is acceptable initially.

## Pseudocode

```text
for each sample:
    load manifest evidence
    discover smali files
    collect code evidence from manifest, smali, strings, and native artifacts
    build candidate SDK matches from curated catalog

    for each evidence item:
        find all matching catalog entries
        choose the longest / most specific prefix match
        normalize to one SDK identity
        if SDK aggregate does not exist:
            create new aggregate
        update aggregate:
            increment evidence_count
            add source file to source set
            add evidence snippet
            merge evidence flags
            preserve best version candidate
            preserve best identifier and ecosystem

    for each SDK aggregate:
        emit one SDKRecord
        set detection flags
        set evidence_count
        set sdk_version fields if reliable
        set sdk_identifier and sdk_ecosystem
        serialize row into manifest_sdks.csv
```

## Notes on the Current State

- The current code already has a manifest-only SDK database and a curated catalog stub.
- `ByteDance / Pangle` and `Mintegral` exist in the older manifest-only database but are not yet present in the curated catalog.
- This document defines how the shared SDK universe should behave when DEX detection is implemented.

## Non-Goals

- No CVE lookup
- No PURL enforcement
- No automatic dependency resolution
- No separate manifest SDK table
- No separate DEX SDK table
- No implementation of the detector itself

## Expected Outcome

When implemented, both manifest and DEX stages should feed the same SDK universe and emit a single, enriched `manifest_sdks.csv` table.

The DEX stage should add depth to detection, not fragment the model.
