"""
TrackerEnricher component for the SDK detection pipeline.
Reads the compiled Exodus tracker prefixes and enriches DetectedLibrary objects.
"""

import csv
import logging
from pathlib import Path
from typing import List, Dict, Optional, Tuple

from sdk_detection.models import SDKRecord

logger = logging.getLogger(__name__)

class TrackerEnricher:
    """
    Loads exodus_trackers.csv once into memory and uses deterministic
    longest-prefix lookup to match and enrich detected SDKs.
    """
    
    _instance = None
    
    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self, csv_path: Optional[Path] = None):
        if csv_path is None:
            # Default path relative to this file
            base_dir = Path(__file__).resolve().parent.parent
            csv_path = base_dir / "knowledge_base" / "metadata" / "exodus_trackers.csv"
            
        self.csv_path = csv_path
        self._prefix_to_tracker: Dict[str, dict] = {}
        self._sorted_prefixes: List[str] = []
        self._loaded = False
        self._load_metadata()

    def _load_metadata(self):
        """Load the tracker CSV once into memory."""
        if self._loaded:
            return
            
        if not self.csv_path.exists():
            logger.warning(f"TrackerEnricher: {self.csv_path} not found. Enrichment will be disabled.")
            return

        try:
            with open(self.csv_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    prefix = row["package_prefix"].strip().lower()
                    self._prefix_to_tracker[prefix] = {
                        "tracker_name": row["tracker_name"],
                        "tracker_categories": row["categories"],
                        "network_signature": row.get("network_signature", ""),
                        "website": row.get("website", "")
                    }
                    
            # Sort by length descending, then lexicographical for determinism
            self._sorted_prefixes = sorted(
                self._prefix_to_tracker.keys(), 
                key=lambda p: (-len(p), p)
            )
            self._loaded = True
            logger.info(f"TrackerEnricher: Loaded {len(self._sorted_prefixes)} prefixes from {self.csv_path.name}")
        except Exception as e:
            logger.error(f"TrackerEnricher: Failed to load {self.csv_path}: {e}")

    @property
    def is_available(self) -> bool:
        return self._loaded

    def _find_longest_prefix(self, target_package: str) -> Optional[dict]:
        """
        Find the longest matching prefix for the target package.
        Since self._sorted_prefixes is sorted by length descending, the first match
        is guaranteed to be the longest prefix.
        """
        if not target_package:
            return None
            
        target_package = target_package.lower()
        for prefix in self._sorted_prefixes:
            if target_package.startswith(prefix):
                return self._prefix_to_tracker[prefix]
        return None

    def enrich(self, records: List[SDKRecord]) -> None:
        """
        Match each record against the Exodus dataset using longest-prefix lookup,
        and directly mutate the tracker fields in the SDKRecord.
        """
        if not self._loaded:
            return
            
        for record in records:
            package = record.package or ""
            match_info = self._find_longest_prefix(package)
            
            if match_info:
                record.is_tracker = True
                record.tracker_name = match_info["tracker_name"]
                record.tracker_categories = match_info["tracker_categories"]
                record.network_signature = match_info["network_signature"]
                record.website = match_info["website"]
            else:
                record.is_tracker = False
                record.tracker_name = ""
                record.tracker_categories = ""
                record.network_signature = ""
                record.website = ""
