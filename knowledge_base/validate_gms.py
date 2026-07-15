"""GMS Validation Script."""
import csv
import os
from collections import Counter
from knowledge_base.logger import get_logger

logger = get_logger(__name__)

def run_validation():
    csv_path = r"d:\New folder\Geo-Difference_MobileSecurity\knowledge_base\build_outputs\gms_import.csv"
    manifest_path = r"d:\New folder\Geo-Difference_MobileSecurity\knowledge_base\build_outputs\gms_manifest.csv"
    
    if not os.path.exists(csv_path) or not os.path.exists(manifest_path):
        logger.error("Missing output CSVs.")
        return
        
    total_records = 0
    unique_packages = set()
    unique_classes = set()
    unique_methods = set()
    
    missing_fields = []
    duplicate_keys = set()
    composite_keys = set()
    
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row_num, row in enumerate(reader, start=2):
            total_records += 1
            
            pkg = row.get("package_name", "")
            cls = row.get("class_name", "")
            method = row.get("method_name", "")
            
            unique_packages.add(pkg)
            unique_classes.add(cls)
            unique_methods.add(method)
            
            if not pkg or not cls or not method:
                missing_fields.append((row_num, pkg, cls, method))
                
            key = (pkg, cls, method)
            if key in composite_keys:
                duplicate_keys.add(key)
            else:
                composite_keys.add(key)
                
    manifest_rows = []
    with open(manifest_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            manifest_rows.append(row)
            
    report = [
        "# Google Play Services (GMS) Validation Report",
        "",
        "## Summary",
        f"- **Artifacts Processed:** {len(manifest_rows)}",
        f"- **Public APIs Imported:** {total_records}",
        f"- **Unique Packages:** {len(unique_packages)}",
        f"- **Unique Classes:** {len(unique_classes)}",
        f"- **Unique Methods:** {len(unique_methods)}",
        "",
        "## Manifest Breakdown",
        "| Artifact | Version | Classes | Methods | Fields | Records Generated |",
        "|---|---|---|---|---|---|"
    ]
    
    for row in manifest_rows:
        report.append(f"| {row['artifact']} | {row['version']} | {row['classes']} | {row['methods']} | {row['fields']} | {row['records_generated']} |")
        
    report.extend([
        "",
        "## Consistency Checks",
        f"- **Missing package/class/method count:** {len(missing_fields)}",
        f"- **Duplicate composite keys remaining:** {len(duplicate_keys)}",
    ])
    
    out_md = r"d:\New folder\Geo-Difference_MobileSecurity\knowledge_base\processed\gms_validation_report.md"
    with open(out_md, "w", encoding="utf-8") as f:
        f.write("\n".join(report))
        
    logger.info(f"Validation successful, report generated at {out_md}")

if __name__ == "__main__":
    run_validation()
