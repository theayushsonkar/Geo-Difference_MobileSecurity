import os
import csv
import sys

def validate_geo_logic():
    csv_path = os.path.join("knowledge_base", "metadata", "geo_logic.csv")
    
    if not os.path.exists(csv_path):
        print(f"Error: {csv_path} does not exist.")
        sys.exit(1)
        
    rule_ids = set()
    apis = set()
    errors = []
    previous_id = ""
    
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        
        expected_fields = ["rule_id", "package_name", "class_name", "method_name", "category", "subcategory", "confidence", "source", "notes"]
        if reader.fieldnames != expected_fields:
            errors.append(f"Invalid schema: expected {expected_fields}, got {reader.fieldnames}")
            
        for i, row in enumerate(reader):
            line = i + 2
            
            rid = row.get("rule_id", "")
            pkg = row.get("package_name", "")
            cls = row.get("class_name", "")
            method = row.get("method_name", "")
            cat = row.get("category", "")
            src = row.get("source", "")
            conf = row.get("confidence", "")
            
            if not rid:
                errors.append(f"Line {line}: missing rule_id")
            elif rid in rule_ids:
                errors.append(f"Line {line}: duplicate rule_id '{rid}'")
            rule_ids.add(rid)
            
            if not pkg.strip():
                errors.append(f"Line {line}: missing package_name")
            if not cls.strip():
                errors.append(f"Line {line}: missing class_name")
            if not method.strip():
                errors.append(f"Line {line}: missing method_name")
            if not cat.strip():
                errors.append(f"Line {line}: missing category")
            if not row.get("subcategory", "").strip():
                errors.append(f"Line {line}: missing subcategory")
            if not src.strip():
                errors.append(f"Line {line}: missing source")
            if src == "Manual" and not row.get("notes", "").strip():
                errors.append(f"Line {line}: missing notes for Manual rule")
                
            if conf not in ("HIGH", "VERY_HIGH"):
                errors.append(f"Line {line}: invalid confidence '{conf}'")
                
            api_sig = f"{pkg}.{cls}->{method}"
            if api_sig in apis:
                errors.append(f"Line {line}: duplicate API signature '{api_sig}'")
            apis.add(api_sig)
            
            current_tuple = (cat, row.get("subcategory", ""), pkg, cls, method)
            if previous_id:
                if current_tuple < previous_id:
                    errors.append(f"Line {line}: non-deterministic ordering. {current_tuple} comes after {previous_id}")
            previous_id = current_tuple
            
    if errors:
        print("Validation Failed with the following errors:")
        for e in errors:
            print(f" - {e}")
        sys.exit(1)
        
    print("Validation Passed Successfully.")
    sys.exit(0)

if __name__ == "__main__":
    validate_geo_logic()
