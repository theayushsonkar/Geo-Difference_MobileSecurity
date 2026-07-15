import csv
import re
import sys
import os

def validate_trufflehog():
    csv_path = os.path.join("knowledge_base", "metadata", "secret_patterns.csv")
    
    if not os.path.exists(csv_path):
        print(f"Error: {csv_path} does not exist.")
        sys.exit(1)
        
    pattern_ids = set()
    regexes = set()
    
    errors = []
    
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        
        # Check schema
        expected_fields = ["pattern_id", "provider", "secret_type", "regex", "severity", "verification_supported", "source", "notes"]
        if reader.fieldnames != expected_fields:
            errors.append(f"Invalid schema: expected {expected_fields}, got {reader.fieldnames}")
            
        previous_pid = ""
            
        for i, row in enumerate(reader):
            line = i + 2
            
            pid = row.get("pattern_id", "")
            provider = row.get("provider", "")
            stype = row.get("secret_type", "")
            regex = row.get("regex", "")
            severity = row.get("severity", "")
            
            if not provider.strip():
                errors.append(f"Line {line}: missing provider")
                
            if not stype.strip():
                errors.append(f"Line {line}: missing secret type")
                
            if not regex.strip():
                errors.append(f"Line {line}: missing regex")
                
            if severity not in ("HIGH", "MEDIUM", "LOW", "UNKNOWN"):
                errors.append(f"Line {line}: invalid severity '{severity}'")
                
            if pid in pattern_ids:
                errors.append(f"Line {line}: duplicate pattern_id '{pid}'")
            if not pid or pid.startswith('_'):
                errors.append(f"Line {line}: missing detector name in pattern_id '{pid}'")
                
            if previous_pid and pid < previous_pid:
                errors.append(f"Line {line}: non-deterministic ordering, '{pid}' comes after '{previous_pid}'")
            previous_pid = pid
            
            pattern_ids.add(pid)
            
            if regex in regexes:
                errors.append(f"Line {line}: duplicate regex")
            regexes.add(regex)
            
            # Removed Python re compilation check because TruffleHog RE2 syntax 
            # (like \z or (?i) inline) cannot be safely validated verbatim in Python.
                
    if errors:
        print("Validation Failed with the following errors:")
        for e in errors:
            print(f" - {e}")
        sys.exit(1)
    else:
        print("Validation Passed Successfully.")
        sys.exit(0)

if __name__ == "__main__":
    validate_trufflehog()
