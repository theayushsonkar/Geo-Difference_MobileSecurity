# FlowDroid Geo-Logic Knowledge Acquisition Report

- **Official FlowDroid Source**: `SourcesAndSinks.txt` (develop branch)
> *Note*: `knowledge_base/raw/flowdroid/AndroidSources.txt` is simply a local copy of FlowDroid's official `SourcesAndSinks.txt`. FlowDroid does not officially ship an `AndroidSources.txt` file.

- **Number of APIs parsed**: 263
- **Imported rules (FlowDroid retained)**: 7
- **Number discarded**: 246
- **Manual rules added**: 18
- **Total Rules in Database**: 24

## Category Distribution
- **Telephony**: 8
- **Country Detection**: 4
- **Locale**: 3
- **Location**: 3
- **Region Detection**: 3
- **Timezone**: 2
- **Language**: 1

## Subcategory Distribution
- **Provider**: 5
- **MCC**: 3
- **SIM Country**: 3
- **GPS**: 3
- **Locale**: 2
- **Country**: 2
- **Timezone**: 2
- **Network Country**: 1
- **Language**: 1
- **Region**: 1
- **MNC**: 1

## Known Limitations
- The importer uses heuristic matching to distinguish Geo Logic from other FlowDroid sources.
- Many geo-inference techniques rely on reflection or specific `Build` and `System` properties which are not natively categorized as sources by default FlowDroid datasets.

## Provenance
- **Imported rules (FlowDroid)**: 7
- **Manual rules**: 17

## Reasons for Manual Additions
Manual additions were required to capture geo-inference APIs that FlowDroid's base `SourcesAndSinks.txt` lacks, particularly utility classes like `Locale`, `TimeZone`, `SystemProperties`, and structural properties such as `BuildConfig.REGION` which represent logical side-channels rather than explicit platform permissioned sources.
