"""
sdk_detection — standalone SDK detection pipeline.

Public API:
    build_inventory(apk_dir, run_id) -> SDKInventory
"""

from sdk_detection.inventory import build_inventory
from sdk_detection.models import SDKInventory, SDKRecord, DetectedLibrary

__all__ = ["build_inventory", "SDKInventory", "SDKRecord", "DetectedLibrary"]
