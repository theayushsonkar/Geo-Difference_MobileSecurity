"""Database Validation Script."""
import csv
import os
import json
from collections import Counter
from knowledge_base.logger import get_logger
from knowledge_base.config import PROCESSED_DIR

logger = get_logger(__name__)

def run_validation():
    csv_path = PROCESSED_DIR / "privacy_apis.csv"
    
    if not csv_path.exists():
        logger.error(f"Missing merged database: {csv_path}")
        return
        
    total_records = 0
    missing_framework = 0
    missing_pkg = 0
    missing_cls = 0
    missing_method = 0
    missing_api_type = 0
    empty_source = 0
    invalid_ranges = 0
    duplicate_perms = 0
    duplicate_versions = 0
    empty_ids = 0
    
    composite_keys = set()
    duplicate_keys = set()
    
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row_num, row in enumerate(reader, start=2):
            total_records += 1
            
            fw = row.get("framework", "")
            pkg = row.get("package_name", "")
            cls = row.get("class_name", "")
            method = row.get("method_name", "")
            api_type = row.get("api_type", "")
            
            if not fw: missing_framework += 1
            if not pkg: missing_pkg += 1
            if not cls: missing_cls += 1
            if not method: missing_method += 1
            if not api_type: missing_api_type += 1
            if not row.get("record_id", ""): empty_ids += 1
            
            key = (fw, pkg, cls, method, api_type)
            if key in composite_keys:
                duplicate_keys.add(key)
            else:
                composite_keys.add(key)
                
            sources = row.get("sources", "[]")
            if sources == "[]" or not sources:
                empty_source += 1
                
            # Permission dup check
            perms = row.get("permission", "")
            if perms:
                perm_list = [p.strip() for p in perms.split(",")]
                if len(perm_list) != len(set(perm_list)):
                    duplicate_perms += 1
                    
            # Version dup and range check
            versions = row.get("supported_android_versions", "[]")
            if versions != "[]":
                try:
                    v_list = json.loads(versions)
                    if len(v_list) != len(set(v_list)):
                        duplicate_versions += 1
                        
                    if len(v_list) > 0:
                        min_api = int(row.get("min_android_api", 0) or 0)
                        max_api = int(row.get("max_android_api", 0) or 0)
                        
                        if min_api > max_api:
                            invalid_ranges += 1
                except Exception:
                    pass
                    
    report = [
        "# Privacy Database Validation Report",
        "",
        f"- **Total Canonical Records:** {total_records}",
        "",
        "## Integrity Checks",
        f"- **Missing Framework:** {missing_framework}",
        f"- **Missing Package:** {missing_pkg}",
        f"- **Missing Class:** {missing_cls}",
        f"- **Missing Method:** {missing_method}",
        f"- **Missing API Type:** {missing_api_type}",
        f"- **Empty Sources:** {empty_source}",
        f"- **Duplicate Merge Keys:** {len(duplicate_keys)}",
        f"- **Duplicate Permissions within Record:** {duplicate_perms}",
        f"- **Duplicate Android Versions within Record:** {duplicate_versions}",
        f"- **Invalid API Version Ranges (Min > Max):** {invalid_ranges}",
        f"- **Empty Record IDs:** {empty_ids}"
    ]
    
    out_md = PROCESSED_DIR / "privacy_database_validation.md"
    with open(out_md, "w", encoding="utf-8") as f:
        f.write("\n".join(report))
        
    logger.info(f"Database validation complete. Report saved to {out_md}")

if __name__ == "__main__":
    run_validation()
