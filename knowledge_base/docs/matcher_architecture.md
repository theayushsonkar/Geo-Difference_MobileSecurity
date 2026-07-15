# Matcher Architecture
## Unified Matcher Framework

### Architecture Diagram
```mermaid
flowchart TD
    E[ManifestFeatureExtractor] -->|uses| MF[MatcherFactory]
    MF -->|initializes & caches| CM[CacheManager]
    MF -->|provides| PM[PrivacyMatcher]
    MF -->|provides| SM[SecretMatcher]
    MF -->|provides| GM[GeoMatcher]
    PM -.->|implements| BM[BaseMatcher]
    SM -.->|implements| BM[BaseMatcher]
    GM -.->|implements| BM[BaseMatcher]
    
    PM -->|returns| PF[PrivacyFinding]
    SM -->|returns| SF[SecretFinding]
    GM -->|returns| GF[GeoFinding]
    
    PF -.->|inherits| BF[BaseFinding]
    SF -.->|inherits| BF[BaseFinding]
    GF -.->|inherits| BF[BaseFinding]
```

### Lifecycle & Initialization
1. **Orchestration**: During startup, `MatcherFactory.initialize()` is called exactly once.
2. **Initialization**: The factory pulls `PrivacyMatcher`, `SecretMatcher`, and `GeoMatcher`. Each matcher immediately triggers `initialize()` to safely build their underlying pattern detectors (e.g., Aho-Corasick automaton, Regex sets).
3. **Caching**: Memory-intensive resources like the loaded automata, Regex engines, and statistical maps are globally cached using `CacheManager`.
4. **Invocation**: `ManifestFeatureExtractor` pulls pre-warmed singletons directly via `factory.privacy()`, guaranteeing zero runtime construction overhead per scan.

### BaseMatcher Implementation
The `BaseMatcher` interface ensures structural guarantees across:
- `initialize()`: Safely populate engines.
- `search(text)`: O(N) evaluation over targets returning strictly typed schema lists (inheriting `BaseFinding`).
- `statistics()`: Insight tracing for debugging.
- `close()`: Resource teardown when scaling architectures require explicit GC collection.

### Design Rationale
Previously, detectors evolved sequentially resulting in fractured schema outputs, un-orchestrated initialization events, and duplicated I/O loading patterns.
The new unified architecture resolves this by wrapping all detection primitives inside the centralized `MatcherFactory`.

The scanner architecture is now **production-ready** and permanently **FROZEN**.
