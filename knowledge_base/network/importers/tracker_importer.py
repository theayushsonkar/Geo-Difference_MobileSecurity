import json
from pathlib import Path
from typing import List, Generator

from knowledge_base.network.schemas.kb_schemas import NormalizedTracker
from knowledge_base.network.utils import resolve_canonical_vendor, resolve_canonical_category

class ExodusTrackerImporter:
    """Importer for Exodus Privacy dataset format."""
    
    def __init__(self, raw_path: Path):
        self.raw_path = raw_path

    def process(self) -> Generator[NormalizedTracker, None, None]:
        """Parses the raw JSON into NormalizedTracker models."""
        if not self.raw_path.exists():
            return
            
        with open(self.raw_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        # Assuming Exodus format: {"trackers": {"1": {"name": "Google Ads", "network_signature": "doubleclick.net|googleadservices.com", "categories": ["Advertisement"]}}}
        trackers = data.get("trackers", {})
        for t_id, t_info in trackers.items():
            vendor = t_info.get("name", "")
            if vendor == "Unknown":
                vendor = ""
            canonical_vendor = resolve_canonical_vendor(vendor)
            categories = t_info.get("categories", [])
            raw_category = categories[0] if categories else ""
            category = resolve_canonical_category(raw_category)
            
            signatures = t_info.get("network_signature", "")
            if not signatures:
                continue
                
            for domain in signatures.split("|"):
                domain = domain.strip().lower()
                if domain:
                    # Strip escaping if present
                    domain = domain.replace("\\.", ".")
                    yield NormalizedTracker(
                        domain_suffix=domain,
                        vendor=vendor,
                        canonical_vendor=canonical_vendor,
                        category=category,
                        source_dataset="Exodus",
                        source_version=""
                    )
