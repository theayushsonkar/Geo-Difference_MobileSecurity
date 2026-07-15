# PScout (DroidPerm) Repository Analysis

## Repository Overview
The repository downloaded into `knowledge_base/raw/pscout/` is **DroidPerm** (developed by Oregon State University), a static analysis tool designed to detect permission checks and sensitive API usage in Android applications. Instead of raw plain-text mapping files like Axplorer, DroidPerm is a full Java analysis framework built on top of Soot. It includes both its own analysis source code and its permission definition datasets.

## Dataset Organization
The root directory consists of:
- `src/`: Java source code for the DroidPerm analysis engine (Soot-based call graph traversal, permission miners, XML parsers).
- `config/`: The actual permission mapping datasets, stored primarily as XML configuration files.
- `eval/`: Notes, markdown summaries, and evaluation results.
- `lib/`, `doc/`: Dependencies and documentation.

## Parser Classes
The DroidPerm pipeline utilizes several provider classes in `src/org/oregonstate/droidperm/perm/` to read the mappings:
- `XMLPermissionDefProvider`: Uses `JAXB` to deserialize XML mapping files into Java objects.
- `TxtPermissionDefProvider`: Parses the legacy custom plain-text format (`perm-def-default.txt`).
- `AggregatePermDefProvider`: Combines multiple definition sources together.
- `PermissionDef`: The canonical Java class (`jaxb_out.PermissionDef`) representing an API and its associated permissions.

## Data Files
The actual permission mappings are explicitly located in the `config/` directory.

**1. XML Files (Primary Source)**
- `perm-def-API-23.xml` (API 23 mappings)
- `perm-def-API-25.xml` (API 25 mappings)
- `perm-def-manual.xml` (Manually curated edge cases / framework APIs)
- `perm-def-play-services.xml` (GMS mappings)
- `javadoc-perm-def-API-23.xml` (Mappings mined from Javadoc)

**XML Format:**
```xml
<permissionDef className="android.accounts.AccountManager" target="android.accounts.Account[] getAccounts()" targetKind="Method">
    <permission name="android.permission.GET_ACCOUNTS"/>
</permissionDef>
```
- Provides distinct attributes for `className`, `target` (return type + method name + parameters), and `targetKind`.
- Contains explicitly defined `<permission>` tags.

**2. TXT File (Secondary Source)**
- `perm-def-default.txt`: A legacy text format containing mappings for specific methods not easily captured by automated extraction.
- **Format**: `<android.location.LocationManager: void removeProximityAlert(...)> -> ACCESS_COARSE_LOCATION`

## Recommended Import Strategy
**Option A: Import XML Directly (Recommended)**
**Why:** 
The XML files (`perm-def-API-*.xml` and `perm-def-manual.xml`) are highly structured and completely unambiguous. Because the `className` and `target` (method signature) are already split into separate attributes by DroidPerm's JAXB schema, Python's native `xml.etree.ElementTree` can parse these files trivially with zero regex guessing. Furthermore, the XML files cleanly separate mappings by Android API version (e.g., API-23, API-25), aligning perfectly with our existing `supported_android_versions` schema.

*We should ignore the TXT format unless strictly necessary, as the XML files contain the authoritative, structured outputs.*

## Known Limitations
- The dataset only explicitly defines versions for API-23 and API-25, so we will lack exact API boundary precision for older or newer versions (unlike Axplorer's API-16 through API-25 coverage).
- GMS mappings exist in `perm-def-play-services.xml`, which we should skip during the PScout phase and handle separately during the later GMS importer phase.
- Some mappings define `targetKind="Field"`, which we must handle correctly since the canonical schema supports fields but previous importers focused primarily on methods.
