import csv
import re
import os
from knowledge_base.schemas.geo_rule_schema import GeoRule

class GeoRuleLoader:
    _cache = None
    
    @classmethod
    def load_rules(cls, csv_path="knowledge_base/metadata/geo_logic.csv", use_cache=True):
        if use_cache and cls._cache is not None:
            return cls._cache
            
        if not os.path.exists(csv_path):
            raise FileNotFoundError(f"Geo logic file not found at {csv_path}")
            
        rules = []
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                rule_id = row.get("rule_id", "")
                pkg = row.get("package_name", "")
                cls_name = row.get("class_name", "")
                method = row.get("method_name", "")
                
                # Generate Canonical Search Token / Regex
                if cls_name and method:
                    if method.isupper():
                        regex_str = rf"(?i)\b{re.escape(cls_name)}\.{re.escape(method)}\b"
                    else:
                        # Allow optional class name (Java dot or Smali semicolon) to differentiate common method names
                        regex_str = rf"(?i)(?:{re.escape(cls_name)}[;\.])?{re.escape(method)}\b"
                else:
                    # Fallback to method name
                    regex_str = rf"(?i)\b{re.escape(method)}\b"
                    
                compiled = None
                supported = True
                
                try:
                    compiled = re.compile(regex_str)
                except re.error:
                    supported = False
                    
                rule = GeoRule(
                    rule_id=rule_id,
                    package_name=pkg,
                    class_name=cls_name,
                    method_name=method,
                    category=row.get("category", ""),
                    subcategory=row.get("subcategory", ""),
                    confidence=row.get("confidence", ""),
                    source=row.get("source", ""),
                    notes=row.get("notes", ""),
                    compiled_pattern=compiled,
                    supported=supported
                )
                rules.append(rule)
                
        if use_cache:
            cls._cache = tuple(rules) # Immutable collection
        return tuple(rules)
