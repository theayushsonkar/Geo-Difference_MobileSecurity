import json
from pathlib import Path

# Load Canonical Vendor Map
_VENDOR_MAP_PATH = Path(__file__).parent / "metadata" / "canonical_vendor_map.json"
_CANONICAL_VENDOR_MAP = {}
if _VENDOR_MAP_PATH.exists():
    with open(_VENDOR_MAP_PATH, "r", encoding="utf-8") as f:
        _CANONICAL_VENDOR_MAP = json.load(f)

CATEGORY_NORMALIZATION_MAP = {
    "Advertisement": "Advertising",
    "Crash reporting": "Crash Reporting"
}

def resolve_canonical_vendor(vendor: str) -> str:
    """Resolves a raw vendor name to its parent corporate entity based on keyword mapping."""
    if not vendor or vendor == "Unknown":
        return ""
    lower_vendor = vendor.lower()
    for canonical, keywords in _CANONICAL_VENDOR_MAP.items():
        for kw in keywords:
            if kw in lower_vendor:
                return canonical
    return vendor.split()[0]

def resolve_canonical_category(category: str) -> str:
    """Normalizes the category name to a stable taxonomy format."""
    if not category or category == "Unknown":
        return ""
    # Capitalize the first letter for consistency (e.g., 'Analytics' -> 'Analytics')
    # and map known variations.
    return CATEGORY_NORMALIZATION_MAP.get(category, category)

# Load Canonical DNS Provider Map
_DNS_PROVIDER_MAP_PATH = Path(__file__).parent / "metadata" / "canonical_dns_provider_map.json"
_CANONICAL_DNS_PROVIDER_MAP = {}
if _DNS_PROVIDER_MAP_PATH.exists():
    with open(_DNS_PROVIDER_MAP_PATH, "r", encoding="utf-8") as f:
        _CANONICAL_DNS_PROVIDER_MAP = json.load(f)

def resolve_canonical_dns_provider(provider: str) -> str:
    """Resolves a raw DNS provider name to its canonical entity."""
    if not provider or provider == "Unknown":
        return "Community"
    lower_provider = provider.lower()
    for canonical, keywords in _CANONICAL_DNS_PROVIDER_MAP.items():
        for kw in keywords:
            if kw in lower_provider:
                return canonical
    return "Community"
