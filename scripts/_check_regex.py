import csv, re
from pathlib import Path

# Test proper CSV parsing of processed output
f = Path('knowledge_base/network/processed/pii_patterns.csv')
with open(f, newline='', encoding='utf-8') as fh:
    for row in csv.DictReader(fh):
        regex = row['regex']
        try:
            re.compile(regex)
            print(f"OK:  {row['pattern_name']} | len={len(regex)} | conf={row['confidence']}")
        except re.error as e:
            print(f"BAD: {row['pattern_name']} -> {e}")
            print(f"  raw regex: {repr(regex)}")
