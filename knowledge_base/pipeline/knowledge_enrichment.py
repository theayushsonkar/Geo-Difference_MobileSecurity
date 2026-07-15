"""Knowledge Enrichment Engine.

Enriches the canonical privacy APIs deterministically in-memory
using rules from classification_rules.csv. Does not modify canonical
identity or persist any intermediate databases.
"""
import csv
import json
import re
from typing import List, Dict, Any, Tuple
import copy
from knowledge_base.schemas.privacy_api_schema import PrivacyAPIRecord
from knowledge_base.logger import get_logger
from knowledge_base.config import PROCESSED_DIR, METADATA_DIR

logger = get_logger(__name__)

class KnowledgeEnrichmentEngine:
    """Deterministic in-memory enrichment engine for canonical APIs."""
    
    def __init__(self) -> None:
        self.rules_path = METADATA_DIR / "classification_rules.csv"
        self.apis_path = PROCESSED_DIR / "privacy_apis.csv"
        
        self.method_rules: Dict[str, List[Dict[str, str]]] = {}
        self.class_rules: Dict[str, List[Dict[str, str]]] = {}
        self.package_rules: Dict[str, List[Dict[str, str]]] = {}
        self.keyword_rules: List[Tuple[re.Pattern, Dict[str, str]]] = []
        
        self.records: List[PrivacyAPIRecord] = []

    def _parse_list(self, s: str) -> List[Any]:
        if not s:
            return []
        try:
            val = json.loads(s)
            if isinstance(val, list):
                return val
            return [val]
        except Exception:
            return []

    def load_apis(self) -> None:
        """Loads canonical APIs into memory."""
        if not self.apis_path.exists():
            logger.error(f"Missing canonical database: {self.apis_path}")
            raise FileNotFoundError(f"Missing {self.apis_path}")
            
        with open(self.apis_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                rec = PrivacyAPIRecord(
                    record_id=row.get("record_id", ""),
                    category=row.get("category", ""),
                    subcategory=row.get("subcategory", ""),
                    framework=row.get("framework", ""),
                    package_name=row.get("package_name", ""),
                    class_name=row.get("class_name", ""),
                    method_name=row.get("method_name", ""),
                    api_name=row.get("api_name", ""),
                    api_type=row.get("api_type", ""),
                    permission=row.get("permission", ""),
                    sources=self._parse_list(row.get("sources", "")),
                    source_versions=self._parse_list(row.get("source_versions", "")),
                    supported_android_versions=self._parse_list(row.get("supported_android_versions", "")),
                    import_timestamp=row.get("import_timestamp", ""),
                    min_android_api=int(row["min_android_api"]) if row.get("min_android_api") else None,
                    max_android_api=int(row["max_android_api"]) if row.get("max_android_api") else None,
                    confidence=row.get("confidence", ""),
                    documentation_url=row.get("documentation_url", ""),
                    deprecated=str(row.get("deprecated", "")).lower() == "true",
                    notes=row.get("notes", "")
                )
                self.records.append(rec)
        logger.info(f"Loaded {len(self.records)} APIs for enrichment.")

    def load_rules(self) -> None:
        """Loads and organizes classification rules."""
        if not self.rules_path.exists():
            logger.error(f"Missing rule metadata: {self.rules_path}")
            raise FileNotFoundError(f"Missing {self.rules_path}")
            
        with open(self.rules_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            required = {"level", "pattern", "category", "subcategory", "confidence", "notes"}
            if not required.issubset(set(reader.fieldnames or [])):
                missing = required - set(reader.fieldnames or [])
                raise ValueError(f"Malformed rules CSV. Missing columns: {missing}")
                
            for row in reader:
                level = row["level"].strip().lower()
                pattern = row["pattern"].strip()
                
                if not pattern:
                    continue
                    
                if level == "method":
                    self.method_rules.setdefault(pattern, []).append(row)
                elif level == "class":
                    self.class_rules.setdefault(pattern, []).append(row)
                elif level == "package":
                    self.package_rules.setdefault(pattern, []).append(row)
                elif level == "keyword":
                    try:
                        regex = re.compile(pattern)
                        self.keyword_rules.append((regex, row))
                    except re.error as e:
                        logger.warning(f"Invalid regex '{pattern}': {e}")
                else:
                    logger.warning(f"Unknown rule level: {level}")
                    
        total = sum(len(x) for x in [self.method_rules, self.class_rules, self.package_rules, self.keyword_rules])
        logger.info(f"Loaded {total} classification rules.")

    def apply_rules(self, api: PrivacyAPIRecord, rules: List[Dict[str, str]]) -> bool:
        """Attempts to apply a set of matching rules to an API.
        
        Returns True if a rule successfully enriched the record.
        """
        if not rules:
            return False
            
        if len(rules) == 1:
            r = rules[0]
            api.category = r.get("category", api.category)
            api.subcategory = r.get("subcategory", api.subcategory)
            api.confidence = r.get("confidence", api.confidence)
            notes = r.get("notes", "").strip()
            if notes:
                existing_notes = api.notes.split("; ") if api.notes else []
                if notes not in existing_notes:
                    existing_notes.append(notes)
                    api.notes = "; ".join(existing_notes)
            return True
            
        # Conflict check
        categories = set(r.get("category") for r in rules if r.get("category"))
        subcategories = set(r.get("subcategory") for r in rules if r.get("subcategory"))
        
        if len(categories) > 1 or len(subcategories) > 1:
            logger.warning(f"Conflict on {api.package_name}.{api.class_name}.{api.method_name}. Categories: {categories}")
            # Do not enrich category/subcategory on conflict
            existing_notes = api.notes.split("; ") if api.notes else []
            existing_notes.append(f"CONFLICT: {categories}")
            api.notes = "; ".join(existing_notes)
            return False
        else:
            # All match, just apply the first one
            r = rules[0]
            api.category = r.get("category", api.category)
            api.subcategory = r.get("subcategory", api.subcategory)
            api.confidence = r.get("confidence", api.confidence)
            return True

    def enrich(self) -> List[PrivacyAPIRecord]:
        """Runs the enrichment pipeline."""
        self.load_rules()
        self.load_apis()
        
        enriched = []
        for api in self.records:
            # Create a shallow copy to modify metadata without touching canonical structure references
            rec = copy.copy(api)
            
            pkg = rec.package_name
            cls = rec.class_name
            method = rec.method_name
            
            full_method = f"{pkg}.{cls}.{method}"
            full_class = f"{pkg}.{cls}"
            full_pkg = pkg
            
            # 1. Method rules
            if self.apply_rules(rec, self.method_rules.get(full_method, [])):
                enriched.append(rec)
                continue
                
            # 2. Class rules
            if self.apply_rules(rec, self.class_rules.get(full_class, [])):
                enriched.append(rec)
                continue
                
            # 3. Package rules
            if self.apply_rules(rec, self.package_rules.get(full_pkg, [])):
                enriched.append(rec)
                continue
                
            # 4. Keyword rules
            matched_keyword_rules = []
            for regex, rule in self.keyword_rules:
                if regex.search(full_method):
                    matched_keyword_rules.append(rule)
                    
            if matched_keyword_rules:
                self.apply_rules(rec, matched_keyword_rules)
                
            enriched.append(rec)
            
        logger.info(f"Enriched {len(enriched)} records.")
        return enriched

if __name__ == "__main__":
    engine = KnowledgeEnrichmentEngine()
    records = engine.enrich()
