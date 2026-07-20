import csv
import json
import hashlib
import time
from pathlib import Path
from typing import List, Dict, Set

from knowledge_base.network.schemas.kb_schemas import NormalizedTracker
from knowledge_base.network.importers.tracker_importer import ExodusTrackerImporter
from knowledge_base.network.importers.easyprivacy_importer import EasyPrivacyImporter

class TrackerBuilder:
    """Builds the final processed tracker dataset and statistics from multiple sources."""
    
    def __init__(self, raw_dir: Path, processed_dir: Path, metadata_dir: Path):
        self.raw_dir = raw_dir
        self.processed_dir = processed_dir
        self.metadata_dir = metadata_dir
        self.processed_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_dir.mkdir(parents=True, exist_ok=True)

    def build(self) -> None:
        start_time = time.time()
        
        # 1. Ingest
        exodus_importer = ExodusTrackerImporter(self.raw_dir / "exodus" / "trackers.json")
        exodus_models = list(exodus_importer.process())
        
        easyprivacy_importer = EasyPrivacyImporter(self.raw_dir / "easyprivacy" / "easyprivacy.txt")
        easyprivacy_models = list(easyprivacy_importer.process())
        
        raw_rows_per_dataset = {
            "Exodus": len(exodus_models),
            "EasyPrivacy": len(easyprivacy_models)
        }
        
        all_models = exodus_models + easyprivacy_models
        
        # 2. Conflict Resolution (Deduplication)
        unique_trackers: Dict[str, NormalizedTracker] = {}
        conflicts_resolved = 0
        duplicates_removed = 0
        
        # We will process Exodus first since it has higher priority for Android-specific metadata
        for model in all_models:
            domain = model.domain_suffix
            if domain in unique_trackers:
                existing = unique_trackers[domain]
                
                # Check for exact duplicate vs conflict
                is_duplicate = (existing.category == model.category and 
                                existing.vendor == model.vendor and
                                existing.source_dataset == model.source_dataset)
                
                if is_duplicate:
                    duplicates_removed += 1
                else:
                    conflicts_resolved += 1
                    
                # Conflict resolution:
                # Prefer Exodus vendor/category. 
                # If Exodus lacks a field (empty) and EasyPrivacy provides it, use EasyPrivacy.
                if existing.source_dataset == "Exodus" and model.source_dataset == "EasyPrivacy":
                    if not existing.vendor and model.vendor:
                        existing.vendor = model.vendor
                    if not existing.canonical_vendor and model.canonical_vendor:
                        existing.canonical_vendor = model.canonical_vendor
                    if not existing.category and model.category:
                        existing.category = model.category
                elif existing.source_dataset == "EasyPrivacy" and model.source_dataset == "Exodus":
                    # Exodus takes precedence
                    new_vendor = model.vendor if model.vendor else existing.vendor
                    new_canonical = model.canonical_vendor if model.canonical_vendor else existing.canonical_vendor
                    new_category = model.category if model.category else existing.category
                    
                    existing.vendor = new_vendor
                    existing.canonical_vendor = new_canonical
                    existing.category = new_category
                    existing.source_dataset = "Exodus,EasyPrivacy" # or just keep Exodus as primary
                    
                # We can track combined source dataset if needed, but let's just keep the primary source or combine them.
                if model.source_dataset not in existing.source_dataset:
                    existing.source_dataset = existing.source_dataset + "," + model.source_dataset
            else:
                unique_trackers[domain] = model
                
        # 3. Output CSV
        csv_path = self.processed_dir / "trackers.csv"
        
        unique_vendors: Set[str] = set()
        unique_categories: Set[str] = set()
        contribution = {}
        
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            fieldnames = ['domain_suffix', 'vendor', 'canonical_vendor', 'category', 'source_dataset', 'source_version']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for domain in sorted(unique_trackers.keys()):
                t = unique_trackers[domain]
                row = {
                    'domain_suffix': t.domain_suffix,
                    'vendor': t.vendor,
                    'canonical_vendor': t.canonical_vendor,
                    'category': t.category,
                    'source_dataset': t.source_dataset,
                    'source_version': t.source_version
                }
                writer.writerow(row)
                
                if t.vendor:
                    unique_vendors.add(t.vendor)
                if t.category:
                    unique_categories.add(t.category)
                    
                for src in t.source_dataset.split(","):
                    contribution[src] = contribution.get(src, 0) + 1
                
        # 4. Generate Hash
        sha256_hash = hashlib.sha256()
        with open(csv_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        final_hash = sha256_hash.hexdigest()
        
        # 5. Generate Statistics
        duration_ms = int((time.time() - start_time) * 1000)
        stats = {
            "raw_rows_per_dataset": raw_rows_per_dataset,
            "imported_rows": len(all_models),
            "duplicates_removed": duplicates_removed,
            "conflicts_resolved": conflicts_resolved,
            "unique_domains": len(unique_trackers),
            "unique_vendors": len(unique_vendors),
            "unique_categories": len(unique_categories),
            "contribution": contribution,
            "generation_duration_ms": duration_ms
        }
        
        stats_path = self.processed_dir / ".stats_tracker.json"
        with open(stats_path, 'w', encoding='utf-8') as f:
            json.dump(stats, f, indent=4)
            
        # 6. Update Metadata (Provenance)
        metadata_path = self.metadata_dir / "metadata.json"
        metadata = {}
        if metadata_path.exists():
            with open(metadata_path, 'r', encoding='utf-8') as f:
                try:
                    metadata = json.load(f)
                except json.JSONDecodeError:
                    pass
                
        # Find easyprivacy version
        easyprivacy_version = "Unknown"
        if easyprivacy_models:
            easyprivacy_version = easyprivacy_models[0].source_version
            
        metadata["trackers"] = {
            "datasets": {
                "Exodus": {
                    "version": "1.0",
                    "download_url": "https://reports.exodus-privacy.eu.org/api/trackers"
                },
                "EasyPrivacy": {
                    "version": easyprivacy_version,
                    "download_url": "https://easylist.to/easylist/easyprivacy.txt"
                }
            },
            "builder_version": "2.0",
            "generation_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "license": "MIT",
            "sha256": final_hash
        }
        
        with open(metadata_path, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=4)

if __name__ == "__main__":
    network_dir = Path(__file__).parent.parent
    kb_dir = network_dir.parent
    builder = TrackerBuilder(
        raw_dir=kb_dir / "raw",
        processed_dir=network_dir / "processed",
        metadata_dir=network_dir / "metadata"
    )
    builder.build()
