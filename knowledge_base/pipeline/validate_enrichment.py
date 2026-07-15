"""Validation script for the Knowledge Enrichment Engine."""
import csv
from knowledge_base.pipeline.knowledge_enrichment import KnowledgeEnrichmentEngine
from knowledge_base.config import PROCESSED_DIR
from knowledge_base.logger import get_logger

logger = get_logger(__name__)

def run_validation() -> None:
    """Validates the output of the enrichment engine."""
    logger.info("Starting enrichment validation...")
    
    engine = KnowledgeEnrichmentEngine()
    enriched_records = engine.enrich()
    
    canonical_path = PROCESSED_DIR / "privacy_apis.csv"
    canonical_records = {}
    
    with open(canonical_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            canonical_records[row["record_id"]] = row
            
    if len(enriched_records) != len(canonical_records):
        logger.error(f"Record count mismatch! Canonical: {len(canonical_records)}, Enriched: {len(enriched_records)}")
        return
        
    immutables_changed = 0
    categories_assigned = 0
    
    for rec in enriched_records:
        canon = canonical_records.get(rec.record_id)
        if not canon:
            logger.error(f"Unknown record_id injected: {rec.record_id}")
            continue
            
        # Verify immutable fields
        if (rec.framework != canon["framework"] or 
            rec.package_name != canon["package_name"] or 
            rec.class_name != canon["class_name"] or 
            rec.method_name != canon["method_name"] or 
            rec.api_type != canon["api_type"]):
            immutables_changed += 1
            
        if rec.category != canon["category"]:
            categories_assigned += 1
            
    if immutables_changed > 0:
        logger.error(f"Validation FAILED: {immutables_changed} records had immutable identity fields changed!")
    else:
        logger.info("Immutable fields perfectly preserved.")
        
    logger.info(f"Total APIs Enriched with new categories: {categories_assigned}")
    logger.info("Validation COMPLETE.")

if __name__ == "__main__":
    run_validation()
