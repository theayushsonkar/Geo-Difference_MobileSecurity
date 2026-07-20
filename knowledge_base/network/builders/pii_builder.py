import csv
import json
import time
from pathlib import Path
from typing import Dict

from knowledge_base.network.schemas.kb_schemas import NormalizedPIIPattern
from knowledge_base.network.importers.pii_importer import PIIImporter

class PIIBuilder:
    """Builds the final processed PII dataset."""
    
    def __init__(self, raw_dir: Path, processed_dir: Path, metadata_dir: Path):
        self.raw_dir = raw_dir
        self.processed_dir = processed_dir
        self.metadata_dir = metadata_dir
        self.processed_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_dir.mkdir(parents=True, exist_ok=True)

    def build(self) -> None:
        start_time = time.time()
        
        unique_patterns: Dict[str, NormalizedPIIPattern] = {}
        
        # 1. Load Presidio rules first (MEDIUM confidence)
        presidio_path = self.raw_dir / "pii" / "presidio_rules.csv"
        if presidio_path.exists():
            importer = PIIImporter(presidio_path, default_dataset="Presidio", default_confidence="MEDIUM")
            for model in importer.process():
                unique_patterns[model.pattern_name] = model
                
        # 2. Load Android-specific rules (HIGH confidence, overwrites MEDIUM)
        android_path = self.raw_dir / "pii" / "pii_rules.csv"
        if android_path.exists():
            importer = PIIImporter(android_path, default_dataset="Android Docs", default_confidence="HIGH")
            for model in importer.process():
                unique_patterns[model.pattern_name] = model
                
        csv_path = self.processed_dir / "pii_patterns.csv"
        
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            fieldnames = ['pattern_name', 'category', 'regex', 'source_reference', 'source_dataset', 'confidence']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for name in sorted(unique_patterns.keys()):
                t = unique_patterns[name]
                row = {
                    'pattern_name': t.pattern_name,
                    'category': t.category,
                    'regex': t.regex,
                    'source_reference': t.source_reference,
                    'source_dataset': t.source_dataset,
                    'confidence': t.confidence
                }
                writer.writerow(row)
                
        meta_path = self.metadata_dir / "pii_metadata.json"
        metadata = {
            "version": "1.1",
            "build_timestamp": int(time.time()),
            "build_duration_sec": round(time.time() - start_time, 2),
            "total_patterns": len(unique_patterns),
            "categories": len(set(r.category for r in unique_patterns.values() if r.category)),
            "high_confidence_count": sum(1 for r in unique_patterns.values() if r.confidence == "HIGH"),
            "medium_confidence_count": sum(1 for r in unique_patterns.values() if r.confidence == "MEDIUM")
        }
        
        with open(meta_path, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=4)
