# External Datasets and Tools Used in the Pipeline

| Phase | Purpose | External Dataset / Tool | Official Link | How it is Used |
| :--- | :--- | :--- | :--- | :--- |
| **1. APK Acquisition** | Download APKs | Google Play Scraper / apkeep | [Google Play Scraper](https://github.com/JoMingyu/google-play-scraper)<br>[apkeep](https://github.com/EFForg/apkeep) | Download APK/XAPK files. |
| **2. APK Decoding** | Decode APK | Apktool | [Apktool](https://github.com/iBotPeaches/Apktool) | Decode APKs to extract `AndroidManifest.xml`, resources, Smali, `META-INF`, native libraries, etc. |
| **3. Manifest Analysis** | Parse manifest | Python `xml.etree.ElementTree` | [Python docs](https://docs.python.org/3/library/xml.etree.elementtree.html) | Parse `AndroidManifest.xml` to extract permissions, components, intents, exported flags, SDK versions, network configuration, queries, etc. |
| **4. Privacy API Detection** | Detect privacy‑sensitive Android APIs | Axplorer + PScout + Google Play Services (AARs) | [Axplorer](https://github.com/reddr/axplorer)<br>[PScout](https://security.csl.toronto.edu/pscout/)<br>[Google Maven Repository](https://maven.google.com/) | Offline: Import Android framework APIs from Axplorer and PScout, extract privacy APIs from selected Google Play Services AARs downloaded from the Google Maven Repository, deterministically merge them into `privacy_apis.csv`, then build an Aho‑Corasick automaton to scan Smali API invocations. |
| **5. Secret Detection** | Detect hardcoded secrets | TruffleHog | [TruffleHog](https://github.com/trufflesecurity/trufflehog) | Offline: Import RE2‑based secret detection patterns into `secret_patterns.csv`. Runtime: Compile supported regexes and scan Smali/string constants. |
| **6. Geo‑Logic Detection** | Detect country/region inference logic | FlowDroid SourcesAndSinks + Manual Rules | [FlowDroid](https://github.com/secure-software-engineering/FlowDroid) | Offline: Extract geo‑related Android APIs from `SourcesAndSinks.txt`, combine them with manually curated rules, generate `geo_logic.csv`, and scan Smali using generated regexes. |
| **7. SDK Detection** | Detect embedded SDKs | LibScan + FallbackDetector | [LibScan](https://github.com/wyf295/LibScan) | **LibScan:** Structural library identification using code similarity.<br>**FallbackDetector:** Uses package prefixes, manifest declarations, `META-INF` metadata, and known Smali namespaces to detect commercial SDKs missed by LibScan. Results are merged into a unified SDK inventory. |
| **8. SDK Canonicalization** | Normalize SDK identities | `sdk_metadata.csv` (Custom) | — | Resolve aliases, package prefixes, and alternate names into one canonical SDK name. |
| **9. Tracker Detection** | Identify trackers | Exodus Privacy | [Exodus Privacy GitHub](https://github.com/Exodus-Privacy)<br>[Exodus API](https://reports.exodus-privacy.eu.org/api/trackers) | Offline: Convert tracker definitions into `exodus_trackers.csv`. Runtime: Perform deterministic longest‑prefix lookup on detected SDK packages to attach tracker metadata. |
| **10. SDK Metadata Enrichment** | Attach SDK information | `sdk_metadata.csv` (Custom) | — | Enrich SDKs with vendor, category, country, aliases, ecosystem, CPE, etc. |
| **11. CVE Detection** | Detect vulnerable SDKs | National Vulnerability Database (NVD) | [NVD](https://nvd.nist.gov/)<br>[NVD Data Feeds](https://nvd.nist.gov/vuln/data-feeds) | Match SDK CPE and version against NVD to identify known vulnerabilities. |
| **12. Static Analysis Output** | Aggregate findings | Internal Matcher Framework | — | Aggregate Privacy APIs, Secrets, Geo Logic, SDKs, Trackers, and CVEs into CSV outputs. |
| **13. PCAP Capture** | Capture per-app network traffic | PCAPdroid | [PCAPdroid](https://github.com/emanuele-f/PCAPdroid) | Installed on device via ADB; captures UID-filtered raw `.pcap` files during a 60-second automated Monkey UI session per app. |
| **14. Packet Parsing** | Parse raw frames | `dpkt` | [PyPI](https://pypi.org/project/dpkt/) | Decodes Ethernet/IP/TCP/UDP frames to extract DNS query/response payloads and TLS ClientHello SNI extensions. |
| **15. Network Tracker Detection** | Identify tracker domains | Exodus Privacy + EasyPrivacy | [Exodus Privacy](https://github.com/Exodus-Privacy)<br>[EasyPrivacy](https://easylist.to/) | Offline: Merge both datasets into a unified suffix trie (47,000+ rules). Runtime: `TrackerMatcher` performs longest-suffix domain lookup to identify and attribute tracker endpoints. |
| **16. GeoIP Attribution** | Map IPs to countries and ASNs | MaxMind GeoLite2 | [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) | `GeoLite2-Country.mmdb` and `GeoLite2-ASN.mmdb` used offline to resolve destination IPs to hosting country codes and ISP organizations with an in-process LRU cache. |
| **17. DNS Resolver Attribution** | Identify canonical DNS providers | dnscrypt-resolvers | [DNSCrypt/dnscrypt-resolvers](https://github.com/DNSCrypt/dnscrypt-resolvers) | Offline: Parse the official public resolver list to extract IPs and metadata for 14 canonical providers (Google, Cloudflare, etc.). Runtime: `DNSResolverMatcher` performs O(1) IP lookup. |
| **18. PII Detection** | Detect personal data leaks in traffic | Custom rules + Microsoft Presidio patterns | [Microsoft Presidio](https://github.com/microsoft/presidio) | Offline: Merge 15 high-confidence custom patterns (IMEI, IPv4, UUID, location coordinates, etc.) with 4 Presidio patterns into `pii_patterns.csv`. Runtime: `PIIMatcher` applies a compiled master-regex with field-specific validators (Luhn, E.164, RFC standards) to eliminate false positives. |

## Notes

-   **Axplorer:** Android framework permission → API mappings.
-   **PScout:** Android permission → API mappings across multiple
    Android versions.
-   **Google Play Services (AARs):** Privacy-related APIs extracted from
    selected Google Play Services AAR artifacts downloaded from the
    Google Maven Repository.
-   **FlowDroid:** Source of Android privacy-sensitive APIs
    (`SourcesAndSinks.txt`), from which geo-related APIs are extracted.
-   **TruffleHog:** Source of secret-detection regex patterns.
-   **LibScan:** Library identification using structural code
    similarity.
-   **Exodus Privacy:** Tracker metadata (package prefixes, tracker
    categories, network signatures).
-   **NVD:** Official CVE database used for vulnerability matching.
-   **PCAPdroid:** On-device packet capture filtered by Android UID;
    no root required.
-   **MaxMind GeoLite2:** Offline IP geolocation database; no API calls
    at runtime.
-   **EasyPrivacy:** Domain-level tracker blocklist; vendor/category
    metadata not guaranteed for all entries.
-   **dnscrypt-resolvers:** Canonical public resolver registry with
    DoH/DoT/DNSCrypt flags.
-   **Microsoft Presidio:** Industry-standard PII recognizer patterns
    used as a secondary, lower-confidence source.
