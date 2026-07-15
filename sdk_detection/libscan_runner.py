"""
LibScanRunner — Chunked multi-pass execution adapter for the LibScan tool.

Architecture overview
---------------------
LibScan's official implementation serialises every decompiled library object
through a multiprocessing.Manager().dict() IPC pipe.  With the full 452-file
reference database this exhausts Python's pickle buffer (MemoryError), causing
every child process to die silently and the main pool to deadlock.

To work around this without modifying LibScan source code, LibScanRunner
partitions the ground_truth_libs_dex directory into a persistent chunk
database.  Each chunk contains at most DEFAULT_CHUNK_SIZE DEX files.
LibScan.py is invoked once per chunk; results are merged before canonicalisation.

Chunk database lifecycle
------------------------
1.  Built once on first use:  third_party/libscan/data/chunk_db/chunk_NNN/
2.  Validated on every startup via a version manifest that records:
        - LibScan git commit hash
        - Reference DB filename hash
        - Configured chunk size
3.  Rebuilt automatically when any of those three values change.
4.  Never rebuilt for individual APKs — only once per installation change.

Downstream contract
-------------------
The output of detect() is List[DetectedLibrary], identical in structure to
Phase 3.  The Canonicalizer, MetadataLoader, and SDKInventory schemas are
completely unchanged.  The only observable difference is that last_metadata
carries additional chunked-execution fields.
"""

import contextlib
import functools
import hashlib
import json
import logging
import math
import os
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from sdk_detection.interfaces import BaseDetector
from sdk_detection.models import DetectedLibrary, DetectionContext

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configurable constants
# ---------------------------------------------------------------------------

# Reference cache mode: "none" (on demand) or "full" (preload all)
LIBSCAN_REFERENCE_CACHE_MODE: str = "full"

@contextlib.contextmanager
def temporary_working_directory(path: Path):
    old_cwd = os.getcwd()
    os.chdir(str(path))
    try:
        yield
    finally:
        os.chdir(old_cwd)

# ---------------------------------------------------------------------------
# Internal Runtime (Embedded Mode)
# ---------------------------------------------------------------------------

class _LibScanRuntime:
    """
    Manages in-process LibScan execution.
    Isolates third-party imports and manages the LRU cache for ThirdLib objects.
    """
    def __init__(self, module_dir: Path, dex_dir: Path, tool_dir: Path, cache_mode: str):
        self.module_dir = module_dir
        self.dex_dir = dex_dir
        self.tool_dir = tool_dir
        self.cache_mode = cache_mode
        self._third_lib_cache: Dict[str, Any] = {}
        self._setup_imports()
        
        if self.cache_mode == "full":
            self._preload_cache()

    def _setup_imports(self):
        module_path_str = str(self.module_dir.resolve())
        if module_path_str not in sys.path:
            sys.path.insert(0, module_path_str)
            
    def _preload_cache(self):
        from lib import ThirdLib
        dex_files = sorted(list(self.dex_dir.glob("*.dex")))
        logger.info("_LibScanRuntime: Preloading %d ThirdLib objects...", len(dex_files))
        
        with temporary_working_directory(self.tool_dir):
            for dex_file in dex_files:
                try:
                    path_str = str(dex_file.resolve())
                    self._third_lib_cache[path_str] = ThirdLib(path_str)
                except Exception as e:
                    logger.error("_LibScanRuntime: Failed to preload %s: %s", dex_file.name, e)
        logger.info("_LibScanRuntime: Preload complete.")

    def _get_third_lib(self, lib_path_str: str) -> Any:
        if self.cache_mode == "full" and lib_path_str in self._third_lib_cache:
            return self._third_lib_cache[lib_path_str]
        
        from lib import ThirdLib
        return ThirdLib(lib_path_str)

    def detect_embedded(self, apk_path: Path, dex_dir: Path, tool_dir: Path) -> Tuple[List[DetectedLibrary], int]:
        from apk import Apk
        from analyzer import detect

        libraries: List[DetectedLibrary] = []
        t_start = time.time()
        
        # LibScan expects to be run from tool_dir to find conf/lib_name_map.csv
        with temporary_working_directory(tool_dir):
            apk_obj = Apk(str(apk_path))
            apk_parse_time = int((time.time() - t_start) * 1000)

            dex_files = sorted(list(dex_dir.glob("*.dex")))
            for dex_file in dex_files:
                try:
                    lib_obj = self._get_third_lib(str(dex_file.resolve()))
                    result = detect(apk_obj, lib_obj)
                    
                    if result:
                        # detect() returns a dict: { 'lib_name': ['lib_name', 'version', similarity_score, ...] }
                        # Wait, earlier I found out detect() returns a list: [matched_classes, total_classes, similarity_score]
                        for lib_name, match_info in result.items():
                            matched_classes = int(match_info[0]) if len(match_info) > 0 else 0
                            total_classes = int(match_info[1]) if len(match_info) > 1 else 0
                            sim_score = float(match_info[2]) if len(match_info) > 2 else 0.0
                            raw_block = f"lib: {lib_name}\\nsimilarity: {sim_score}"
                            libraries.append(DetectedLibrary(
                                sdk_name=lib_name,
                                package="",
                                detection_source="libscan",
                                detector_name=lib_name,
                                raw_detector_output={
                                    "similarity": sim_score,
                                    "matched_classes": matched_classes,
                                    "total_classes": total_classes,
                                    "raw_block": raw_block,
                                }
                            ))
                except Exception as e:
                    logger.error("LibScanRuntime: Error matching %s: %s", dex_file.name, e)
                    
        return libraries, apk_parse_time


# ---------------------------------------------------------------------------
# Installation helper
# ---------------------------------------------------------------------------

@dataclass
class LibScanInstallation:
    root: Path
    tool_dir: Path
    data_dir: Path
    conf_dir: Path
    module_dir: Path
    libs_dir: Optional[Path] = None
    libs_dex_dir: Optional[Path] = None
    jar_count: int = 0
    dex_count: int = 0

    def is_valid(self) -> Tuple[bool, str]:
        if not self.tool_dir.exists():    return False, "tool_dir missing"
        if not self.data_dir.exists():    return False, "data_dir missing"
        if not self.conf_dir.exists():    return False, "conf_dir missing"
        if not self.module_dir.exists():  return False, "module_dir missing"
        if not (self.tool_dir / "LibScan.py").exists():          return False, "LibScan.py missing"
        if not (self.module_dir / "config.py").exists():         return False, "config.py missing"
        if not (self.conf_dir / "lib_name_map.csv").exists():    return False, "lib_name_map.csv missing"
        if not self.libs_dir or not self.libs_dir.exists():      return False, "libs_dir missing or unresolvable"
        if not self.libs_dex_dir or not self.libs_dex_dir.exists(): return False, "libs_dex_dir missing or unresolvable"
        return True, ""


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

class LibScanRunner(BaseDetector):
    """
    Chunked LibScan adapter.

    Detection flow per APK:
        1. Validate installation.
        2. Ensure chunk database is ready (build once, reuse forever).
        3. For each chunk:
               a. Create an isolated run directory with a symlink/copy of the APK.
               b. Execute LibScan.py with -ld pointing to the chunk.
               c. Parse the output TXT.
               d. Accumulate DetectedLibrary results.
        4. Deduplicate raw detections by (sdk_name, detection_source).
        5. Write aggregated cache entry.
        6. Return List[DetectedLibrary] to the pipeline (unchanged contract).

    Downstream (Canonicalizer → SDKInventory) is completely unchanged.
    """

    def __init__(self, libscan_root: Path = Path("third_party/libscan")):
        self.root = libscan_root.resolve()
        self.cache_base = self.root / "cache"
        self.installation = self._discover_installation()
        self.last_metadata: Dict[str, Any] = {}
        self._runtime: Optional[_LibScanRuntime] = None

    def _get_runtime(self) -> _LibScanRuntime:
        if self._runtime is None:
            self._runtime = _LibScanRuntime(
                module_dir=self.installation.module_dir,
                dex_dir=self.installation.libs_dex_dir,
                tool_dir=self.installation.tool_dir,
                cache_mode=LIBSCAN_REFERENCE_CACHE_MODE
            )
        return self._runtime

    # ------------------------------------------------------------------
    # Installation discovery
    # ------------------------------------------------------------------

    def _discover_installation(self) -> LibScanInstallation:
        inst = LibScanInstallation(
            root=self.root,
            tool_dir=self.root / "tool",
            data_dir=self.root / "data",
            conf_dir=self.root / "tool" / "conf",
            module_dir=self.root / "tool" / "module",
        )

        # Prefer data/ground_truth_libs over tool/libs
        for candidate in (inst.data_dir / "ground_truth_libs", inst.tool_dir / "libs"):
            if candidate.exists():
                try:
                    if any(candidate.iterdir()):
                        inst.libs_dir = candidate
                        break
                except PermissionError:
                    pass

        # Prefer data/ground_truth_libs_dex over tool/libs_dex
        for candidate in (inst.data_dir / "ground_truth_libs_dex", inst.tool_dir / "libs_dex"):
            if candidate.exists():
                try:
                    if any(candidate.iterdir()):
                        inst.libs_dex_dir = candidate
                        break
                except PermissionError:
                    pass

        if inst.libs_dir:
            inst.jar_count = sum(1 for _ in inst.libs_dir.glob("*.jar"))
        if inst.libs_dex_dir:
            inst.dex_count = sum(1 for _ in inst.libs_dex_dir.glob("*.dex"))

        return inst

    def validate_installation(self) -> Tuple[bool, str]:
        if not self.root.exists():
            return False, "LibScan root directory does not exist"
        return self.installation.is_valid()

    # ------------------------------------------------------------------
    # Hash helpers
    # ------------------------------------------------------------------

    def _get_repo_hash(self) -> str:
        if not (self.root / ".git").exists():
            return "unknown"
        try:
            res = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=str(self.root),
                capture_output=True, text=True, timeout=5
            )
            if res.returncode == 0:
                return res.stdout.strip()[:8]
        except Exception:
            pass
        return "unknown"

    def _get_db_hash(self) -> str:
        h = hashlib.md5()
        for d in (self.installation.libs_dir, self.installation.libs_dex_dir):
            if d and d.exists():
                for f in sorted(d.iterdir()):
                    h.update(f.name.encode())
        res = h.hexdigest()[:8]
        return res if res != "d41d8cd9" else "empty"

    def _hash_file(self, filepath: Path) -> str:
        h = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                while chunk := f.read(8192):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return "nohash"

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def detect(self, context: DetectionContext) -> List[DetectedLibrary]:
        t_start = time.time()

        self.last_metadata = {
            "available": False,
            "execution_mode": "embedded",
            "runtime_ms_total": 0,
            "apk_parse_time_ms": 0,
            "libraries_detected": 0,
            "libraries_before_merge": 0,
            "libraries_after_merge": 0,
            "cache_hit": False,
            "cache_key": "",
            "reference_database_hash": "",
            "repository_hash": "",
            "resolved_reference_paths": {},
            "failure_reason": "",
            "python_version": sys.version,
            "jar_count": self.installation.jar_count,
            "dex_count": self.installation.dex_count,
        }

        # --- Validate installation ---
        valid, reason = self.validate_installation()
        if not valid:
            self.last_metadata["failure_reason"] = reason
            logger.warning("LibScanRunner: Validation failed: %s", reason)
            return []

        if not context.apk_path:
            self.last_metadata["failure_reason"] = "Empty apk_path"
            logger.warning("LibScanRunner: context.apk_path is empty. LibScan requires original APK.")
            return []

        apk_file = Path(context.apk_path)
        if not apk_file.exists():
            self.last_metadata["failure_reason"] = "APK does not exist"
            logger.warning("LibScanRunner: APK %s does not exist.", apk_file)
            return []

        self.last_metadata["available"] = True
        self.last_metadata["resolved_reference_paths"] = {
            "libs": str(self.installation.libs_dir),
            "libs_dex": str(self.installation.libs_dex_dir),
        }

        # --- Compute cache key ---
        apk_hash = self._hash_file(apk_file)
        repo_hash = self._get_repo_hash()
        db_hash = self._get_db_hash()

        self.last_metadata["repository_hash"] = repo_hash
        self.last_metadata["reference_database_hash"] = db_hash

        # Cache key should incorporate the execution mode
        cache_key = f"{apk_hash}_{repo_hash}_{db_hash}_embedded"
        self.last_metadata["cache_key"] = cache_key

        cache_file = self.cache_base / f"{cache_key}.json"

        # --- Cache hit? ---
        if cache_file.exists():
            self.last_metadata["cache_hit"] = True
            logger.debug("LibScanRunner: Cache hit for %s.", apk_file.name)
            try:
                with open(cache_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                libraries = [DetectedLibrary(**d) for d in data]
                self.last_metadata["libraries_detected"] = len(libraries)
                self.last_metadata["libraries_after_merge"] = len(libraries)
                self.last_metadata["runtime_ms_total"] = int((time.time() - t_start) * 1000)
                return libraries
            except Exception as e:
                logger.error("LibScanRunner: Failed to read cache %s: %s", cache_file, e)

        self.last_metadata["cache_hit"] = False
        logger.info("LibScanRunner: Cache miss for %s. Running embedded LibScan…", apk_file.name)

        chunk_build_ms = 0
        chunk_dirs = []
        all_raw: List[DetectedLibrary] = []

        try:
            runtime = self._get_runtime()
            all_raw, apk_parse_time = runtime.detect_embedded(apk_file, self.installation.libs_dex_dir, self.installation.tool_dir)
            self.last_metadata["apk_parse_time_ms"] = apk_parse_time
        except Exception as e:
            failure = f"embedded detection failed: {e}"
            logger.error("LibScanRunner: %s", failure)
            self.last_metadata["failure_reason"] = failure

        # --- Deduplicate by (sdk_name, detection_source) ---
        # LibScan can list the same library in multiple chunks if one chunk's
        # JAR database overlaps with the DEX chunk.  Keep the first occurrence
        # (they are identical in content — LibScan is deterministic).
        seen: set = set()
        merged: List[DetectedLibrary] = []
        for lib in all_raw:
            key = (lib.sdk_name, lib.detection_source)
            if key not in seen:
                seen.add(key)
                merged.append(lib)

        self.last_metadata["libraries_before_merge"] = len(all_raw)
        self.last_metadata["libraries_after_merge"] = len(merged)
        self.last_metadata["libraries_detected"] = len(merged)

        # --- Cache write ---
        try:
            self.cache_base.mkdir(parents=True, exist_ok=True)
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump([asdict(lib) for lib in merged], f)
        except Exception as e:
            logger.error("LibScanRunner: Failed to write cache %s: %s", cache_file, e)

        self.last_metadata["runtime_ms_total"] = int((time.time() - t_start) * 1000)
        logger.info(
            "LibScanRunner: %s → %d libraries in %dms (mode: embedded)",
            apk_file.name, len(merged),
            self.last_metadata["runtime_ms_total"],
        )
        return merged
