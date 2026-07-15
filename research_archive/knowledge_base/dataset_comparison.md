# Axplorer vs PScout Comparative Analysis

## Quantitative Analysis
- **Total Axplorer APIs:** 2731
- **Total PScout APIs:** 195
- **Common (Overlap) APIs:** 3
- **Axplorer Unique APIs:** 2728 (99.9%)
- **PScout Unique APIs:** 192 (98.5%)
- **Overlap % (vs Axplorer):** 0.1%
- **Overlap % (vs PScout):** 1.5%

## Qualitative Differences
Among the 3 common APIs:
- **Permission Mismatches:** 0 APIs map to different permissions across datasets.
- **Category Mismatches:** 0 APIs map to different privacy categories.

### Examples of Mismatches
- None detected in overlap.

## Strengths and Weaknesses

**Strengths of Axplorer:**
- Extremely large coverage spanning a wide range of Android versions (API 16 to 25).
- Highly granular detection of obscure Android internal frameworks and methods.

**Weaknesses of Axplorer:**
- Prone to over-approximation; sometimes maps APIs to permissions tangentially related.
- High number of "Unknown" categories due to obscure permissions being mapped.

**Strengths of PScout:**
- Very precise permission extraction derived from semantic call graph analysis (Soot).
- Includes Field-level permission triggers (e.g. `CONTENT_URI`), which Axplorer heavily misses.
- Accurate differentiation between `Read` and `Write` operations for content providers.

**Weaknesses of PScout:**
- Considerably smaller API coverage.
- Limited strict version bounding compared to Axplorer's robust per-API slicing.

## Recommendation for Future Merge
When designing the `Database Merger`:
1. **Union over Intersection:** We should take the union of both datasets to maximize coverage.
2. **Conflict Resolution:** If an API exists in both datasets with *differing* permissions, we should aggregate (union) the permissions instead of overriding one source with another. The merged record's `sources` list should include `["Axplorer", "PScout"]`.
3. **Version Bounds Preservation:** We must carefully union the `supported_android_versions` array to preserve the chronological knowledge from both Axplorer's granular maps and PScout's sparse maps.
