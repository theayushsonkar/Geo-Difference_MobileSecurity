"""
Loader and validator for sample_index.csv.
"""

import csv
import hashlib
import os
import re
import sys
from typing import List, Set, Tuple

from .constants import get_region
from .models import SampleRecord


def load_sample_index(path: str) -> Tuple[List[SampleRecord], str]:
    """Load and validate sample_index.csv. Returns (records, index_sha256)."""
    with open(path, "rb") as f:
        raw = f.read()
    index_sha256 = hashlib.sha256(raw).hexdigest()

    records = []
    seen_ids: Set[str] = set()
    errors = []
    sha_pat = re.compile(r"^[a-fA-F0-9]{64}$")

    with open(path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row_num, row in enumerate(reader, start=2):
            sid = row.get("sample_id", "").strip()
            if not sid:
                errors.append(f"Row {row_num}: missing sample_id")
                continue
            if sid in seen_ids:
                errors.append(f"Row {row_num}: duplicate sample_id '{sid}'")
                continue
            seen_ids.add(sid)

            apk_hash = row.get("apk_sha256", "").strip()
            if not sha_pat.match(apk_hash):
                errors.append(f"Row {row_num}: invalid apk_sha256 '{apk_hash}'")
                continue

            src = row.get("source_path", "").strip()
            if not os.path.exists(src):
                errors.append(f"Row {row_num}: source_path not found: '{src}'")
                continue

            cc = row.get("app_country_code", "").strip().upper()
            rg = row.get("app_region_group", "").strip()
            if not rg:
                rg = get_region(cc)

            records.append(SampleRecord(
                sample_id=sid,
                package_name=row.get("package_name", "").strip(),
                app_country_code=cc,
                source_path=src,
                apk_sha256=apk_hash.lower(),
                app_country_name=row.get("app_country_name", "").strip(),
                app_region_group=rg,
                app_store=row.get("app_store", "").strip(),
                collection_batch=row.get("collection_batch", "").strip(),
                notes=row.get("notes", "").strip(),
            ))

    if errors:
        print(f"[WARN] {len(errors)} validation error(s) in sample index:", file=sys.stderr)
        for e in errors[:20]:
            print(f"  {e}", file=sys.stderr)

    return records, index_sha256
