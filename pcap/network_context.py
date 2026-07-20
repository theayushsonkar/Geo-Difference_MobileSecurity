"""
NetworkContext for the PCAP Analysis Engine.
Acts as a Dependency Injection container for all Knowledge Base matchers.
"""
from dataclasses import dataclass
from typing import Optional

from pcap.matchers.tracker_matcher import TrackerMatcher
from pcap.matchers.geo_mapper import GeoMapper
from pcap.matchers.dns_resolver_matcher import DNSResolverMatcher
from pcap.matchers.pii_matcher import PIIMatcher

@dataclass(frozen=True)
class NetworkContext:
    """
    Thread-safe, read-only Dependency Injection container for matchers.
    Instantiated once per pipeline run by the KBMasterManager.
    """
    tracker_matcher: Optional[TrackerMatcher] = None
    geo_mapper: Optional[GeoMapper] = None
    dns_resolver_matcher: Optional[DNSResolverMatcher] = None
    pii_matcher: Optional[PIIMatcher] = None
