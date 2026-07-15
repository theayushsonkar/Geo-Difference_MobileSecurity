"""PScout Validation Script."""
import csv
import json
import os
from collections import Counter
from knowledge_base.logger import get_logger

logger = get_logger(__name__)

def run_validation():
    csv_path = r"d:\New folder\Geo-Difference_MobileSecurity\knowledge_base\build_outputs\pscout_import.csv"
    
    if not os.path.exists(csv_path):
        logger.error(f"File not found: {csv_path}")
        return
        
    total_rows = 0
    unique_permissions = set()
    unique_packages = set()
    unique_classes = set()
    unique_methods = set()
    categories = Counter()
    
    missing_fields = []
    min_max_violations = []
    supported_versions_violations = []
    
    composite_keys = set()
    duplicate_keys = set()

    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row_num, row in enumerate(reader, start=2):
            total_rows += 1
            
            perm = row.get("permission", "")
            pkg = row.get("package_name", "")
            cls = row.get("class_name", "")
            method = row.get("method_name", "")
            cat = row.get("category", "")
            
            unique_permissions.add(perm)
            unique_packages.add(pkg)
            unique_classes.add(cls)
            unique_methods.add(method)
            categories[cat] += 1
            
            if not pkg or not cls or not method:
                missing_fields.append((row_num, pkg, cls, method))
            
            min_api = row.get("min_android_api", "")
            max_api = row.get("max_android_api", "")
            if min_api and max_api:
                if int(min_api) > int(max_api):
                    min_max_violations.append(row_num)
                    
            supported = row.get("supported_android_versions", "[]")
            try:
                versions = json.loads(supported)
                if versions != sorted(list(set(versions))):
                    supported_versions_violations.append(row_num)
            except:
                pass
                
            key = (row.get("framework", ""), pkg, cls, method, perm)
            if key in composite_keys:
                duplicate_keys.add(key)
            else:
                composite_keys.add(key)
                
    report = [
        "# PScout Importer Validation Report",
        "",
        f"- **Total Rows:** {total_rows}",
        f"- **Unique Permissions:** {len(unique_permissions)}",
        f"- **Unique Packages:** {len(unique_packages)}",
        f"- **Unique Classes:** {len(unique_classes)}",
        f"- **Unique Methods:** {len(unique_methods)}",
        "",
        "## Category Distribution",
    ]
    
    for cat, count in categories.most_common():
        report.append(f"- {cat}: {count}")
        
    report.extend([
        "",
        "## Consistency Checks",
        f"- **Unknown Category Count:** {categories.get('Unknown', 0)}",
        f"- **Missing package/class/method count:** {len(missing_fields)}",
        f"- **min_android_api > max_android_api violations:** {len(min_max_violations)}",
        f"- **Unsorted or duplicate supported_android_versions:** {len(supported_versions_violations)}",
        f"- **Duplicate composite keys remaining:** {len(duplicate_keys)}",
    ])
    
    out_md = r"d:\New folder\Geo-Difference_MobileSecurity\knowledge_base\processed\pscout_validation_report.md"
    with open(out_md, "w", encoding="utf-8") as f:
        f.write("\n".join(report))
        
    logger.info(f"Validation successful, report generated at {out_md}")

if __name__ == "__main__":
    run_validation()
