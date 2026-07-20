# Knowledge Base Limitations

This document outlines the known constraints and technical boundaries of the deterministic enrichment modules used in the Geo-Difference Mobile Security analysis pipeline. It is intended to contextualize the metrics and scope of the output datasets for research and thesis writing.

## Tracker Knowledge Base

- **Dataset Coverage:** Built deterministically from the Exodus Privacy and EasyPrivacy datasets. Only domains present in these authoritative sources are classified as trackers.
- **Upstream Coverage Gaps:** Some telemetry endpoints (e.g., `firebaseremoteconfig.googleapis.com`) are absent from both upstream datasets and therefore remain unmatched.
- **Metadata Availability:** EasyPrivacy is a domain blocklist rather than a tracker catalog. Domains originating solely from EasyPrivacy may not contain vendor or category metadata, although they are still correctly identified as tracker domains.

## GeoLite2 Knowledge Base

- **Database Coverage:** Some IP prefixes have valid ASN information but no associated country record in the GeoLite2 databases. These resolve successfully at the ASN level while leaving the country field empty.
- **Private Network Traffic:** Emulator-generated PCAPs contain substantial RFC1918 traffic. These addresses are intentionally classified as `PRIVATE` and may dominate geographic statistics unless filtered during analysis.

## DNS Resolver Knowledge Base

- **Capture Environment Limitation:** Android emulator networking typically forwards DNS queries through a local DHCP-assigned resolver before forwarding them upstream. Consequently, public resolver attribution from emulator PCAPs is inherently limited.
- **Resolver Attribution:** Public DNS providers are only identified when their IP addresses are directly observable in captured traffic (e.g., hardcoded public DNS, DoH, or DoT connections).

## PII Knowledge Base

- **Pattern Validation:** Most identifiers (e.g., IMEI, ICCID, IPv4, UUID, phone numbers) are validated using deterministic algorithms in addition to regex matching. Patterns without publicly available validation algorithms (e.g., UK NHS numbers) rely solely on format matching and may produce occasional false positives.
- **No Semantic Context:** The engine performs deterministic byte-matching. It cannot infer whether a matched IPv4 address in a DNS Name field is an intentional telemetry leak or a standard networking routine. False positives require manual context-aware review.

## General Limitations

- The enrichment pipeline is deterministic and signature-based. It does not employ machine learning, probabilistic inference, or heuristic risk scoring.
- Encrypted TLS payloads are never decrypted or inspected.
- Knowledge Base coverage depends on the completeness of the underlying public datasets.
- Results should therefore be interpreted as lower-bound observations rather than exhaustive measurements.
