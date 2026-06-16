"""
CVE analysis module for Android APK research pipeline.
"""

from __future__ import annotations

from .schemas import (
    CoverageRecord,
    CVEMatch,
    CVERecord,
    SDKRecord,
)

__all__ = [
    "SDKRecord",
    "CVERecord",
    "CVEMatch",
    "CoverageRecord",
]
