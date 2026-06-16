"""
CVE Versioning Module

This module implements safe version string parsing and range evaluation logic
to determine if a detected Android SDK version falls within the boundaries
of a CVE's affected version range.
"""

from __future__ import annotations

import logging
from packaging.version import InvalidVersion, Version

# Create module logger
logger = logging.getLogger(__name__)


def parse_version_safe(version: str | None) -> Version | None:
    """
    Safely converts a version string into a Version object.
    
    Args:
        version: The version string to parse, or None.
        
    Returns:
        A packaging.version.Version object if parsing succeeds, otherwise None.
        
    Examples:
        >>> parse_version_safe("20.4.1")
        <Version('20.4.1')>
        >>> parse_version_safe("  20.4.1  ")
        <Version('20.4.1')>
        >>> parse_version_safe(None)
        None
        >>> parse_version_safe("")
        None
        >>> parse_version_safe("not-a-version")
        None
    """
    if version is None:
        return None
    cleaned = version.strip()
    if not cleaned:
        return None
    try:
        return Version(cleaned)
    except InvalidVersion:
        logger.debug("Failed to parse invalid version string: '%s'", version)
        return None


def version_in_range(
    sdk_version: str,
    version_start_including: str | None = None,
    version_start_excluding: str | None = None,
    version_end_including: str | None = None,
    version_end_excluding: str | None = None,
) -> bool:
    """
    Determine whether a SDK version falls inside a single NVD version range.
    
    Rule 1: If sdk_version cannot be parsed, return False.
    Rule 2: Missing boundaries mean unbounded (None means no limit).
    
    Args:
        sdk_version: The SDK version string to evaluate.
        version_start_including: Lower bound inclusive version string.
        version_start_excluding: Lower bound exclusive version string.
        version_end_including: Upper bound inclusive version string.
        version_end_excluding: Upper bound exclusive version string.
        
    Returns:
        True if affected (falls within the range), False otherwise.
        
    Examples:
        # Inclusive boundaries
        >>> version_in_range("20.0.0", version_start_including="20.0.0")
        True
        >>> version_in_range("1.5.0", version_start_including="1.0.0", version_end_including="2.0.0")
        True
        
        # Exclusive boundaries
        >>> version_in_range("20.0.0", version_start_excluding="20.0.0")
        False
        >>> version_in_range("2.0.0", version_start_including="1.0.0", version_end_excluding="2.0.0")
        False
        
        # Missing boundaries (unbounded)
        >>> version_in_range("5.0.0", version_end_excluding="6.2.2")
        True
        >>> version_in_range("100.0.0", version_start_including="1.0.0")
        True
        
        # Invalid SDK version
        >>> version_in_range("not-a-version", version_start_including="1.0.0")
        False
    """
    parsed_sdk = parse_version_safe(sdk_version)
    if parsed_sdk is None:
        logger.debug("SDK version '%s' could not be parsed. Evaluation returning False.", sdk_version)
        return False

    logger.debug(
        "Evaluating SDK version %s against range [start_inc=%s, start_exc=%s, end_inc=%s, end_exc=%s]",
        sdk_version,
        version_start_including,
        version_start_excluding,
        version_end_including,
        version_end_excluding,
    )

    # Check lower bounds
    if version_start_including is not None:
        start_inc = parse_version_safe(version_start_including)
        if start_inc is None or parsed_sdk < start_inc:
            return False

    if version_start_excluding is not None:
        start_exc = parse_version_safe(version_start_excluding)
        if start_exc is None or parsed_sdk <= start_exc:
            return False

    # Check upper bounds
    if version_end_including is not None:
        end_inc = parse_version_safe(version_end_including)
        if end_inc is None or parsed_sdk > end_inc:
            return False

    if version_end_excluding is not None:
        end_exc = parse_version_safe(version_end_excluding)
        if end_exc is None or parsed_sdk >= end_exc:
            return False

    return True


def has_real_version_constraints(version_ranges: list[dict]) -> bool:
    """
    Checks if there is at least one version range dictionary that contains at least
    one of the NVD version boundary keys.
    
    Args:
        version_ranges: A list of version range dictionaries.
        
    Returns:
        True if at least one valid boundary key exists, False otherwise.
    """
    if not version_ranges:
        return False
    boundary_keys = {
        "versionStartIncluding",
        "versionStartExcluding",
        "versionEndIncluding",
        "versionEndExcluding",
    }
    for r in version_ranges:
        if not isinstance(r, dict):
            continue
        if any(r.get(key) is not None for key in boundary_keys):
            return True
    return False


def matches_any_range(sdk_version: str, version_ranges: list[dict]) -> bool:
    """
    Determines whether a SDK version falls inside any of the NVD version ranges.
    
    Strict matching policy: If version_ranges is empty (no range information),
    returns False.
    
    Args:
        sdk_version: The SDK version string to evaluate.
        version_ranges: A list of version range dictionaries containing boundary keys.
        
    Returns:
        True if the SDK version matches any of the ranges, False otherwise.
        
    Examples:
        # Multiple ranges
        >>> ranges = [
        ...     {"versionStartIncluding": "1.0.0", "versionEndExcluding": "2.0.0"},
        ...     {"versionStartIncluding": "3.0.0", "versionEndExcluding": "4.0.0"}
        ... ]
        >>> matches_any_range("1.5.0", ranges)
        True
        >>> matches_any_range("2.5.0", ranges)
        False
        >>> matches_any_range("3.5.0", ranges)
        True
        
        # Empty ranges list (no version range information)
        >>> matches_any_range("1.5.0", [])
        False
    """
    if not version_ranges or not has_real_version_constraints(version_ranges):
        return False

    logger.debug("Evaluating SDK version %s against %d version ranges", sdk_version, len(version_ranges))

    for r in version_ranges:
        if not isinstance(r, dict):
            continue
        # Skip ranges that don't have any actual boundaries
        boundary_keys = {
            "versionStartIncluding",
            "versionStartExcluding",
            "versionEndIncluding",
            "versionEndExcluding",
        }
        if not any(r.get(key) is not None for key in boundary_keys):
            continue

        if version_in_range(
            sdk_version=sdk_version,
            version_start_including=r.get("versionStartIncluding"),
            version_start_excluding=r.get("versionStartExcluding"),
            version_end_including=r.get("versionEndIncluding"),
            version_end_excluding=r.get("versionEndExcluding"),
        ):
            return True

    return False


if __name__ == "__main__":
    # Configure simple logging to stdout for manual test
    logging.basicConfig(level=logging.DEBUG)
    
    print("Running versioning manual verification...")
    
    # 1. parse_version_safe
    print("\n1. Testing parse_version_safe:")
    print(f"'20.4.1' -> {parse_version_safe('20.4.1')}")
    print(f"' 20.4.1 ' -> {parse_version_safe(' 20.4.1 ')}")
    print(f"None -> {parse_version_safe(None)}")
    print(f"'' -> {parse_version_safe('')}")
    print(f"'invalid' -> {parse_version_safe('invalid')}")
    
    # 2. version_in_range
    print("\n2. Testing version_in_range:")
    print(f"SDK 20.4.1, >=20.0.0, <21.0.0 -> {version_in_range('20.4.1', version_start_including='20.0.0', version_end_excluding='21.0.0')}")
    print(f"SDK 20.0.0, >=20.0.0, <21.0.0 -> {version_in_range('20.0.0', version_start_including='20.0.0', version_end_excluding='21.0.0')}")
    print(f"SDK 21.0.0, >=20.0.0, <21.0.0 -> {version_in_range('21.0.0', version_start_including='20.0.0', version_end_excluding='21.0.0')}")
    print(f"SDK 20.0.0, >20.0.0, <21.0.0 -> {version_in_range('20.0.0', version_start_excluding='20.0.0', version_end_excluding='21.0.0')}")
    print(f"SDK 20.0.1, >20.0.0, <21.0.0 -> {version_in_range('20.0.1', version_start_excluding='20.0.0', version_end_excluding='21.0.0')}")
    
    # Unbounded checks
    print(f"SDK 5.0.0, <6.2.2 -> {version_in_range('5.0.0', version_end_excluding='6.2.2')}")
    print(f"SDK 6.2.2, <6.2.2 -> {version_in_range('6.2.2', version_end_excluding='6.2.2')}")
    print(f"SDK 1.0.0, >=1.0.0 -> {version_in_range('1.0.0', version_start_including='1.0.0')}")
    print(f"SDK 100.0.0, >=1.0.0 -> {version_in_range('100.0.0', version_start_including='1.0.0')}")
    
    # 3. matches_any_range
    print("\n3. Testing matches_any_range:")
    test_ranges = [
        {"versionStartIncluding": "1.0.0", "versionEndExcluding": "2.0.0"},
        {"versionStartIncluding": "3.0.0", "versionEndExcluding": "4.0.0"}
    ]
    print(f"SDK 1.5.0 in ranges -> {matches_any_range('1.5.0', test_ranges)}")
    print(f"SDK 2.5.0 in ranges -> {matches_any_range('2.5.0', test_ranges)}")
    print(f"SDK 3.5.0 in ranges -> {matches_any_range('3.5.0', test_ranges)}")
    print(f"SDK 1.5.0 in [] -> {matches_any_range('1.5.0', [])}")
