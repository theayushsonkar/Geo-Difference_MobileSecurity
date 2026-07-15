"""Database Merger.

Merges Axplorer, PScout, and Google Play Services datasets into a single
canonical database (`privacy_apis.csv`).
"""
import csv
import json
import re
import pathlib
import datetime
import uuid
from typing import Dict, List, Tuple, Any, Set
from copy import deepcopy

from knowledge_base.schemas.privacy_api_schema import PrivacyAPIRecord
from knowledge_base.config import PROCESSED_DIR, BUILD_OUTPUTS_DIR
from knowledge_base.logger import get_logger
from knowledge_base.utils.csv_utils import write_csv

logger = get_logger(__name__)

class DatabaseMerger:
    """Merges disparate privacy API datasets deterministically."""

    def __init__(self) -> None:
        self.axplorer_csv = BUILD_OUTPUTS_DIR / "axplorer_import.csv"
        self.pscout_csv = BUILD_OUTPUTS_DIR / "pscout_import.csv"
        self.gms_csv = BUILD_OUTPUTS_DIR / "gms_import.csv"
        
        self.output_csv = PROCESSED_DIR / "privacy_apis.csv"
        self.stats_csv = PROCESSED_DIR / "merge_statistics.csv"
        
        self.merged_records: Dict[Tuple[str, str, str, str, str], PrivacyAPIRecord] = {}
        
        # We need a meta tracker because dataclasses can't inherently hold Sets cleanly
        # and we need to track conflict resolution over time.
        self.meta: Dict[Tuple[str, str, str, str, str], Dict[str, Any]] = {}

        self.stats = {
            "axplorer_records": 0,
            "pscout_records": 0,
            "gms_records": 0,
            "total_inputs": 0,
            "merged_records": 0,
            "duplicate_merge_operations": 0,
            "permission_conflicts": 0,
            "category_conflicts": 0,
            "unknown_categories": 0,
            "framework_distribution": {}
        }

    def validate_inputs(self) -> None:
        """Ensures all required input files exist."""
        for path in [self.axplorer_csv, self.pscout_csv, self.gms_csv]:
            if not path.exists():
                logger.error(f"Missing required dataset: {path}")
                raise FileNotFoundError(f"Cannot merge. Missing {path}")

    def normalize_string(self, s: str) -> str:
        """Strips and collapses spaces."""
        if not s:
            return ""
        return re.sub(r'\s+', ' ', s.strip())

    def parse_list(self, s: str) -> List[Any]:
        """Parses a JSON list string gracefully."""
        if not s:
            return []
        try:
            val = json.loads(s)
            if isinstance(val, list):
                return val
            return [val]
        except Exception:
            return []

    def merge_row(self, row: Dict[str, str], source_name: str) -> None:
        """Processes a single row from an input CSV."""
        # Normalize Identity
        framework = self.normalize_string(row.get("framework", ""))
        pkg = self.normalize_string(row.get("package_name", ""))
        cls = self.normalize_string(row.get("class_name", ""))
        method = self.normalize_string(row.get("method_name", ""))
        api_type = self.normalize_string(row.get("api_type", ""))
        
        if not framework or not pkg or not cls or not method or not api_type:
            return
            
        key = (framework, pkg, cls, method, api_type)
        
        row_sources = self.parse_list(row.get("sources", ""))
        row_source_versions = self.parse_list(row.get("source_versions", ""))
        row_android_versions = self.parse_list(row.get("supported_android_versions", ""))
        
        row_perm_str = row.get("permission", "")
        row_perms = [p.strip() for p in row_perm_str.split(",")] if row_perm_str else []
        row_perms = [p for p in row_perms if p]
        
        row_cat = row.get("category", "").strip()
        row_subcat = row.get("subcategory", "").strip()
        row_notes = row.get("notes", "").strip()
        row_doc_url = row.get("documentation_url", "").strip()
        
        if key not in self.merged_records:
            # First time seeing this API
            import_timestamp = row.get("import_timestamp", "")
            
            canonical_string = f"privacy-api://{framework}/{pkg}/{cls}/{method}/{api_type}"
            record_id = str(uuid.uuid5(uuid.NAMESPACE_URL, canonical_string))
            
            record = PrivacyAPIRecord(
                record_id=record_id,
                category=row_cat,
                subcategory=row_subcat,
                framework=framework,
                package_name=pkg,
                class_name=cls,
                method_name=method,
                api_name=self.normalize_string(row.get("api_name", "")),
                api_type=api_type,
                permission="",
                sources=[],
                source_versions=[],
                supported_android_versions=[],
                import_timestamp=import_timestamp,
                min_android_api=None,
                max_android_api=None,
                confidence="",
                deprecated=str(row.get("deprecated", "False")).lower() == "true",
                documentation_url=row_doc_url,
                notes=""
            )
            
            self.merged_records[key] = record
            
            self.meta[key] = {
                "sources": set(row_sources),
                "source_versions": set(row_source_versions),
                "android_versions": set(row_android_versions),
                "permissions": set(row_perms),
                "category": row_cat if row_cat else "Unknown",
                "subcategory": row_subcat if row_subcat else "Unknown",
                "notes": [row_notes] if row_notes else [],
                "doc_url": row_doc_url
            }
        else:
            self.stats["duplicate_merge_operations"] += 1
            meta = self.meta[key]
            
            meta["sources"].update(row_sources)
            meta["source_versions"].update(row_source_versions)
            meta["android_versions"].update(row_android_versions)
            meta["permissions"].update(row_perms)
            
            # Category merging
            existing_cat = meta["category"]
            new_cat = row_cat if row_cat else "Unknown"
            
            if existing_cat == "Unknown" and new_cat != "Unknown":
                meta["category"] = new_cat
            elif existing_cat != "Unknown" and new_cat != "Unknown" and existing_cat != new_cat:
                logger.warning(f"Category conflict for {pkg}.{cls}.{method}: {existing_cat} vs {new_cat}")
                self.stats["category_conflicts"] += 1
                
            # Subcategory merging
            existing_subcat = meta["subcategory"]
            new_subcat = row_subcat if row_subcat else "Unknown"
            
            if existing_subcat == "Unknown" and new_subcat != "Unknown":
                meta["subcategory"] = new_subcat
            elif existing_subcat != "Unknown" and new_subcat != "Unknown" and existing_subcat != new_subcat:
                logger.warning(f"Subcategory conflict for {pkg}.{cls}.{method}: {existing_subcat} vs {new_subcat}")
                
            if row_notes and row_notes not in meta["notes"]:
                meta["notes"].append(row_notes)
                
            if row_doc_url and not meta["doc_url"]:
                meta["doc_url"] = row_doc_url

    def process_file(self, path: pathlib.Path, stat_key: str, source_name: str) -> None:
        """Processes a single dataset."""
        logger.info(f"Processing {path.name}")
        with open(path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                self.stats[stat_key] += 1
                self.stats["total_inputs"] += 1
                self.merge_row(row, source_name)

    def finalize_records(self) -> List[PrivacyAPIRecord]:
        """Constructs the final deduplicated records with resolved metadata."""
        final_list = []
        
        for key in sorted(self.merged_records.keys()):
            record = self.merged_records[key]
            meta = self.meta[key]
            
            sources = sorted(list(meta["sources"]))
            record.sources = sources
            record.source_versions = sorted(list(meta["source_versions"]))
            
            android_versions = sorted(list(meta["android_versions"]))
            record.supported_android_versions = android_versions
            
            if android_versions:
                record.min_android_api = min(android_versions)
                record.max_android_api = max(android_versions)
                
            record.permission = ", ".join(sorted(list(meta["permissions"])))
            
            record.category = meta["category"]
            record.subcategory = meta["subcategory"]
            
            if record.category == "Unknown":
                self.stats["unknown_categories"] += 1
                
            record.notes = "; ".join(meta["notes"])
            record.documentation_url = meta["doc_url"]
            
            # Confidence Calculation
            source_count = len(sources)
            if source_count >= 3:
                record.confidence = "VERY_HIGH"
            elif source_count == 2:
                record.confidence = "HIGH"
            else:
                record.confidence = "MEDIUM"
                
            fw = record.framework
            self.stats["framework_distribution"][fw] = self.stats["framework_distribution"].get(fw, 0) + 1
            
            final_list.append(record)
            
        self.stats["merged_records"] = len(final_list)
        return final_list

    def write_stats(self) -> None:
        """Writes the merge statistics."""
        with open(self.stats_csv, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["metric", "value"])
            for k, v in self.stats.items():
                if k == "framework_distribution":
                    for fw, count in v.items():
                        writer.writerow([f"fw_{fw}", count])
                else:
                    writer.writerow([k, v])
        logger.info("Merge statistics written.")

    def run(self) -> None:
        """Main execution flow."""
        logger.info("Database Merger started.")
        self.validate_inputs()
        
        self.process_file(self.axplorer_csv, "axplorer_records", "Axplorer")
        self.process_file(self.pscout_csv, "pscout_records", "PScout")
        self.process_file(self.gms_csv, "gms_records", "Google Play Services")
        
        final_records = self.finalize_records()
        write_csv(self.output_csv, final_records)
        self.write_stats()
        
        logger.info(f"Database Merger completed successfully. {len(final_records)} canonical records saved.")

if __name__ == "__main__":
    merger = DatabaseMerger()
    merger.run()
