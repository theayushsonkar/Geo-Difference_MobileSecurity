"""
tracker_matcher.py
──────────────────
Matches domain names against a database of known ad networks, trackers,
and analytics SDKs using deterministic longest-suffix matching.
"""

import ipaddress
import logging
from dataclasses import dataclass
from typing import Iterable
from functools import lru_cache

from pcap.constants import TRACKER_DOMAINS

# Set up logger
logger = logging.getLogger("tracker_matcher")
_TRACKER_DB_SIZE = len(TRACKER_DOMAINS)


@dataclass
class TrackerMatch:
    """Represents the metadata returned when matching a domain to a known SDK/tracker."""
    matched: bool
    sdk_name: str
    vendor_country: str
    sdk_category: str
    matched_suffix: str
    canonical_vendor: str


# ─────────────────────────────────────────────────────────────────────────────
# CANONICAL VENDOR DICTIONARY MAP
# Maps specific SDK sub-brands/CDNs/services to their parent/canonical vendor.
# ─────────────────────────────────────────────────────────────────────────────
CANONICAL_VENDOR_MAP = {
    # ByteDance
    "ByteDance/Pangle": "ByteDance",
    "ByteDance CDN": "ByteDance",
    "ByteDance": "ByteDance",
    # Mintegral
    "Mintegral": "Mintegral",
    # AppLovin
    "AppLovin": "AppLovin",
    "AppLovin CDN": "AppLovin",
    # Vungle
    "Vungle/Liftoff": "Vungle",
    "Vungle Ads": "Vungle",
    "Vungle Metrics": "Vungle",
    "Liftoff": "Liftoff",
    # Moloco
    "Moloco": "Moloco",
    "Moloco DSP": "Moloco",
    # BidMachine
    "BidMachine": "BidMachine",
    # Google / DoubleClick / DV360
    "Google DV360": "Google",
    "Google Ads": "Google",
    # Amazon
    "Amazon APS": "Amazon",
    "Amazon APS EU": "Amazon",
    "Amazon A9": "Amazon",
    "Amazon Tungsten": "Amazon",
    # BidSwitch
    "BidSwitch RTB": "BidSwitch",
    # DoubleVerify
    "DoubleVerify": "DoubleVerify",
    # Moat / Oracle
    "Oracle Moat": "Oracle",
    # Chartboost
    "Chartboost": "Chartboost",
    # MobileFuse
    "MobileFuse": "MobileFuse",
    # Ogury
    "Ogury": "Ogury",
    # Presage
    "Presage": "Presage",
    # InMobi
    "InMobi": "InMobi",
    "InMobi CDN": "InMobi",
    "InMobi Supply": "InMobi",
    "InMobi Telemetry": "InMobi",
    # IronSource
    "IronSource": "IronSource",
    # PubNative
    "PubNative/HyBid": "PubNative",
    # Fyber
    "Fyber": "Fyber",
    # InnerActive
    "InnerActive": "InnerActive",
    "InnerActive WV": "InnerActive",
    # Smaato
    "Smaato": "Smaato",
    "Smaato SDK Files": "Smaato",
    # Attribution
    "Adjust": "Adjust",
    "AppsFlyer": "AppsFlyer",
    "Singular": "Singular",
    "Branch": "Branch",
    "Kochava": "Kochava",
    # Firebase
    "Firebase": "Firebase",
    "Firebase RTDB": "Firebase",
    "Firebase Hosting": "Firebase",
    "Firebase FCM": "Firebase",
    # Crashlytics
    "Crashlytics": "Crashlytics",
    # Facebook / Meta
    "Facebook": "Facebook",
    "Facebook CDN": "Facebook",
    "Facebook Graph API": "Facebook",
    "Facebook Ad Sync": "Facebook",
    # Data Brokers
    "Epsilon (data broker)": "Epsilon",
    "Acxiom": "Acxiom",
    "Experian": "Experian",
}


def get_canonical_vendor(sdk_name: str) -> str:
    """Returns the canonical parent vendor name for a given SDK/tracker name."""
    if not sdk_name:
        return ""
    return CANONICAL_VENDOR_MAP.get(sdk_name, sdk_name)


def _is_ip_address(val: str) -> bool:
    """Returns True if the string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(val)
        return True
    except ValueError:
        return False


def _normalize_domain(domain: str) -> str:
    """Normalizes domain strings by stripping whitespace, lowercasing, and removing trailing dots."""
    if not isinstance(domain, str):
        return ""
    normalized = domain.strip().lower()
    if normalized.endswith("."):
        normalized = normalized[:-1]
    return normalized


@lru_cache(maxsize=4096)
def _get_match_metadata(domain: str) -> tuple[bool, str, str, str, str]:
    """
    Finds the longest matching suffix in TRACKER_DOMAINS for the given domain.
    Returns:
        tuple (matched, sdk_name, vendor_country, sdk_category, matched_suffix)
    """
    best_suffix = ""
    best_metadata = ("", "", "")
    best_len = -1

    for suffix, metadata in TRACKER_DOMAINS.items():
        # A domain matches if it is exactly the suffix or if it ends with "." + suffix
        if domain == suffix or domain.endswith("." + suffix):
            if len(suffix) > best_len:
                best_len = len(suffix)
                best_suffix = suffix
                best_metadata = metadata

    if best_len != -1:
        return True, best_metadata[0], best_metadata[1], best_metadata[2], best_suffix
    
    return False, "", "", "", ""


def match_domain(domain: str) -> TrackerMatch:
    """
    Checks if a domain name matches a known tracker domain prefix/suffix.
    Uses longest-suffix matching.
    
    Args:
        domain: The domain name to match.
        
    Returns:
        A TrackerMatch object containing SDK metadata.
    """
    normalized = _normalize_domain(domain)
    
    # Exclude empty values, IP addresses, etc.
    if not normalized or _is_ip_address(normalized):
        if normalized and _is_ip_address(normalized):
            logger.debug("Skipping IP address matching: %s", normalized)
        return TrackerMatch(
            matched=False,
            sdk_name="",
            vendor_country="",
            sdk_category="",
            matched_suffix="",
            canonical_vendor=""
        )

    matched, sdk_name, vendor_country, sdk_category, matched_suffix = _get_match_metadata(normalized)
    canonical_vendor = get_canonical_vendor(sdk_name)

    if matched:
        logger.debug("Matched domain '%s' to tracker '%s' (suffix: '%s')", normalized, sdk_name, matched_suffix)
    else:
        logger.debug("Domain '%s' unmatched", normalized)

    return TrackerMatch(
        matched=matched,
        sdk_name=sdk_name,
        vendor_country=vendor_country,
        sdk_category=sdk_category,
        matched_suffix=matched_suffix,
        canonical_vendor=canonical_vendor
    )


def match_domains(domains: Iterable[str]) -> dict[str, TrackerMatch]:
    """
    Batches domain matching to avoid redundant computations for duplicate domains.
    
    Args:
        domains: An iterable of domain strings.
        
    Returns:
        A dict mapping original domain string input to its TrackerMatch result.
    """
    results: dict[str, TrackerMatch] = {}
    matched_count = 0
    unmatched_count = 0

    for dom in domains:
        if dom not in results:
            match = match_domain(dom)
            results[dom] = match
            if match.matched:
                matched_count += 1
            else:
                unmatched_count += 1

    logger.info("Batch match completed: %d domains matched, %d domains unmatched.", matched_count, unmatched_count)
    return results
