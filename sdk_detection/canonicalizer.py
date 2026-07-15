"""
Canonicalizer — maps raw detector names to canonical sdk_name.

Different detectors emit different names for the same SDK:
    LibScan     → "com.bytedance"
    Fallback    → "ByteDance/Pangle"
    Exodus      → "pangle"

The Canonicalizer resolves all of these to the single canonical sdk_name
defined in sdk_metadata.csv, using the `aliases` column as the lookup table.

Rules:
    1. If the raw name exactly matches a canonical sdk_name → return as-is.
    2. If the raw name matches any alias (case-insensitive) → return the
       canonical sdk_name for that alias.
    3. If the raw name starts with a known sdk_prefix (case-insensitive) →
       return the canonical sdk_name for that prefix.
    4. Otherwise → return the raw name unchanged (pass-through, never blocks).

Usage:
    canon = Canonicalizer()
    name = canon.resolve("com.bytedance")   # → "ByteDance/Pangle"
    name = canon.resolve("unknown_sdk")     # → "unknown_sdk"
"""

from __future__ import annotations

import csv
import logging
from pathlib import Path
from typing import Dict

logger = logging.getLogger(__name__)

_DEFAULT_CSV = Path(__file__).parent / "metadata" / "sdk_metadata.csv"


class Canonicalizer:
    """
    Builds a reverse alias index from sdk_metadata.csv at construction time.
    Thread-safe for reads after __init__.
    """

    def __init__(self, csv_path: Path = _DEFAULT_CSV) -> None:
        # Maps lowercase alias/prefix → canonical sdk_name
        self._alias_index: Dict[str, str] = {}
        # Maps lowercase sdk_prefix → canonical sdk_name (rule 3 fallback)
        self._prefix_index: Dict[str, str] = {}
        # Exact canonical names set (rule 1 fast path)
        self._canonical_names: set = set()
        self._load(csv_path)

    def _load(self, path: Path) -> None:
        if not path.exists():
            logger.error("sdk_metadata.csv not found at %s — canonicalization disabled", path)
            return
        try:
            with open(path, newline="", encoding="utf-8") as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    name = (row.get("sdk_name") or "").strip()
                    if not name:
                        continue
                    self._canonical_names.add(name)

                    # Rule 3: sdk_prefix as a prefix lookup
                    prefix = (row.get("sdk_prefix") or "").strip().lower()
                    if prefix and prefix not in self._prefix_index:
                        self._prefix_index[prefix] = name
                    # Also index it as an alias (exact match)
                    if prefix and prefix not in self._alias_index:
                        self._alias_index[prefix] = name

                    # Rule 2: aliases column
                    raw_aliases = (row.get("aliases") or "").strip()
                    for alias in raw_aliases.split(";"):
                        alias = alias.strip().lower()
                        if not alias:
                            continue
                        if alias in self._alias_index:
                            existing = self._alias_index[alias]
                            if existing != name:
                                logger.warning(
                                    "Alias %r maps to both %r and %r — keeping %r",
                                    alias, existing, name, existing,
                                )
                        else:
                            self._alias_index[alias] = name

            logger.debug(
                "Canonicalizer: %d canonical names, %d aliases, %d prefixes",
                len(self._canonical_names),
                len(self._alias_index),
                len(self._prefix_index),
            )
        except Exception as exc:
            logger.error("Failed to load canonicalizer index: %s", exc)

    def resolve(self, raw: str) -> str:
        """
        Resolve a raw detector name to its canonical sdk_name.

        Never raises. Unknown names pass through unchanged.
        """
        if not raw:
            return raw

        # Rule 1: already canonical
        if raw in self._canonical_names:
            return raw

        raw_l = raw.lower()

        # Rule 2: exact alias match
        if raw_l in self._alias_index:
            return self._alias_index[raw_l]

        # Rule 3: prefix match (raw starts with a known sdk_prefix)
        best_match = ""
        best_len = -1
        for prefix, canonical in self._prefix_index.items():
            if raw_l == prefix or raw_l.startswith(prefix + ".") or raw_l.startswith(prefix + "/"):
                if len(prefix) > best_len:
                    best_len = len(prefix)
                    best_match = canonical
        if best_match:
            return best_match

        # Rule 4: pass-through
        return raw
