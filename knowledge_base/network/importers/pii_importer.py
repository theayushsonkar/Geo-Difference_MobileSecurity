import csv
from pathlib import Path
from typing import Generator
import logging

from knowledge_base.network.schemas.kb_schemas import NormalizedPIIPattern

logger = logging.getLogger(__name__)

class PIIImporter:
    """Importer for PII regex patterns."""
    
    def __init__(self, csv_path: Path, default_dataset: str = "Manual", default_confidence: str = "HIGH"):
        self.csv_path = csv_path
        self.default_dataset = default_dataset
        self.default_confidence = default_confidence

    def process(self) -> Generator[NormalizedPIIPattern, None, None]:
        if not self.csv_path.exists():
            logger.warning(f"PII rules file not found: {self.csv_path}")
            return
            
        with open(self.csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                yield NormalizedPIIPattern(
                    pattern_name=row.get("pattern_name", "").strip(),
                    category=row.get("category", "").strip(),
                    regex=row.get("regex", "").strip(),
                    source_reference=row.get("source_reference", "").strip(),
                    source_dataset=row.get("source_dataset", self.default_dataset),
                    confidence=row.get("confidence", self.default_confidence)
                )
