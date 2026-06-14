"""
output.py
─────────
CSV and JSON writers, along with foreign key validation logic.
"""

import csv
import json
import os
from typing import Any, Dict, List

try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False

from .schema import (
    APP_COLUMNS,
    BOOL_COLUMNS,
    COMPONENT_COLUMNS,
    INT_COLUMNS,
    NETWORK_COLUMNS,
    PERMISSION_COLUMNS,
    SDK_COLUMNS,
    _normalize_rows,
)


def _write_csv(path: str, rows: List[Dict[str, Any]], columns: List[str]):
    rows = _normalize_rows(rows, columns)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if HAS_PANDAS:
        df = pd.DataFrame(rows, columns=columns)
        for col in columns:
            if col in BOOL_COLUMNS:
                df[col] = df[col].astype("boolean")
            elif col in INT_COLUMNS:
                df[col] = df[col].astype("Int64")
            else:
                df[col] = df[col].astype("string")
        df.to_csv(path, index=False, na_rep="")
        return
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: ("" if v is None else v) for k, v in row.items()})


def _validate_foreign_keys(app_rows, child_tables: Dict[str, List[Dict[str, Any]]]):
    app_ids = {r["sample_id"] for r in app_rows}
    for table_name, rows in child_tables.items():
        missing = sorted({r.get("sample_id", "") for r in rows} - app_ids)
        if missing:
            raise ValueError(f"{table_name} has sample_id values missing from manifest_apps.csv: {missing[:5]}")


def write_outputs(output_dir: str, results: List[Dict[str, Any]], trace: Dict[str, Any]):
    app_rows = [r["app"] for r in results]
    sdk_rows = [row for r in results for row in r["sdks"]]
    component_rows = [row for r in results for row in r["components"]]
    permission_rows = [row for r in results for row in r["permissions"]]
    network_rows = [row for r in results for row in r["network_domains"]]

    _validate_foreign_keys(app_rows, {
        "manifest_sdks.csv": sdk_rows,
        "manifest_components.csv": component_rows,
        "manifest_permissions.csv": permission_rows,
        "manifest_network_domains.csv": network_rows,
    })

    os.makedirs(output_dir, exist_ok=True)
    _write_csv(os.path.join(output_dir, "manifest_apps.csv"), app_rows, APP_COLUMNS)
    _write_csv(os.path.join(output_dir, "manifest_sdks.csv"), sdk_rows, SDK_COLUMNS)
    _write_csv(os.path.join(output_dir, "manifest_components.csv"), component_rows, COMPONENT_COLUMNS)
    _write_csv(os.path.join(output_dir, "manifest_permissions.csv"), permission_rows, PERMISSION_COLUMNS)
    _write_csv(os.path.join(output_dir, "manifest_network_domains.csv"), network_rows, NETWORK_COLUMNS)

    with open(os.path.join(output_dir, "manifest_trace.json"), "w", encoding="utf-8") as f:
        json.dump(trace, f, indent=2, sort_keys=True, ensure_ascii=False)
