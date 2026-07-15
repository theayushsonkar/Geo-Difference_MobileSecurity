"""
MetadataLoader — reads sdk_metadata.csv and provides enrichment lookups.

Reads ONLY the metadata columns (vendor, country, region, category,
sdk_identifier, sdk_ecosystem, cpe). Detection columns (sdk_prefix,
smali_aliases) are the FallbackDetector's concern.

Usage:
    loader = MetadataLoader()
    meta = loader.get("Firebase")   # -> SDKMeta or None
    loader.enrich(sdk_record)       # mutates record in place
"""

from __future__ import annotations

import csv
import logging
from pathlib import Path
from typing import Dict, Optional

from sdk_detection.models import SDKMeta, SDKRecord

logger = logging.getLogger(__name__)

_DEFAULT_CSV = Path(__file__).parent / "metadata" / "sdk_metadata.csv"

# Metadata columns owned by this loader (others ignored)
_META_COLS = {
    "sdk_name", "vendor", "vendor_country_code", "vendor_region_group",
    "sdk_category", "sdk_identifier", "sdk_ecosystem", "cpe",
}


class MetadataLoader:
    """
    Loads sdk_metadata.csv at construction time.
    Thread-safe for reads after __init__.
    """

    def __init__(self, csv_path: Path = _DEFAULT_CSV) -> None:
        self._db: Dict[str, SDKMeta] = {}
        self._load(csv_path)

    def _load(self, path: Path) -> None:
        if not path.exists():
            logger.error("sdk_metadata.csv not found at %s — enrichment disabled", path)
            return
        try:
            with open(path, newline="", encoding="utf-8") as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    name = (row.get("sdk_name") or "").strip()
                    if not name:
                        continue
                    if name in self._db:
                        logger.warning("Duplicate sdk_name in CSV: %r — keeping first", name)
                        continue
                    self._db[name] = SDKMeta(
                        sdk_name=name,
                        vendor=row.get("vendor", "").strip(),
                        vendor_country_code=row.get("vendor_country_code", "").strip(),
                        vendor_region_group=row.get("vendor_region_group", "").strip(),
                        sdk_category=row.get("sdk_category", "").strip(),
                        sdk_identifier=row.get("sdk_identifier", "").strip(),
                        sdk_ecosystem=row.get("sdk_ecosystem", "custom").strip() or "custom",
                        cpe=row.get("cpe", "").strip(),
                    )
            logger.debug("MetadataLoader: loaded %d SDK entries", len(self._db))
        except Exception as exc:
            logger.error("Failed to load sdk_metadata.csv: %s — enrichment disabled", exc)

    def get(self, sdk_name: str) -> Optional[SDKMeta]:
        """Return SDKMeta for an exact canonical sdk_name, or None."""
        return self._db.get(sdk_name)

    def enrich(self, record: SDKRecord) -> None:
        """
        Mutate record in place with metadata from the CSV.
        Fields already set on the record are NOT overwritten.
        No-op if sdk_name is not found in the database.
        """
        meta = self._db.get(record.sdk_name)
        if meta is None:
            return
        if not record.vendor:
            record.vendor = meta.vendor
        if not record.vendor_country_code:
            record.vendor_country_code = meta.vendor_country_code
        if not record.vendor_region_group:
            record.vendor_region_group = meta.vendor_region_group
        if not record.sdk_category:
            record.sdk_category = meta.sdk_category
        if not record.sdk_identifier:
            record.sdk_identifier = meta.sdk_identifier
        if record.sdk_ecosystem == "custom" and meta.sdk_ecosystem:
            record.sdk_ecosystem = meta.sdk_ecosystem
        if not record.cpe:
            record.cpe = meta.cpe

    def enrich_all(self, records: list) -> None:
        """Enrich a list of SDKRecord objects in place."""
        for rec in records:
            self.enrich(rec)
