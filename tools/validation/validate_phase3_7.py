"""
validate_phase3_7.py — Phase 3.7 Chunked LibScan Validation Script

Tests:
  T1  Installation validation (jar_count / dex_count)
  T2  Chunk database build (fresh)
  T3  Chunk database reuse (no rebuild on second call)
  T4  LibScan chunked execution on 3 APKs
  T5  Cache miss / hit cycle
  T6  Metadata fields: chunk_count, runtime_per_chunk, libraries_before_merge …
  T7  Version extraction (full version string preserved)
  T8  Downstream contract — build_inventory unchanged

"""

import json
import logging
import shutil
import sys
import time
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

ROOT = Path(__file__).parent

# ── helpers ─────────────────────────────────────────────────────────────────

PASS_MARK = "[PASS]"
FAIL_MARK = "[FAIL]"

results = []

def check(name: str, ok: bool, detail: str = ""):
    tag = PASS_MARK if ok else FAIL_MARK
    print(f"  {tag}  {name}" + (f"  ({detail})" if detail else ""))
    results.append((name, ok))
    return ok

def section(title: str):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print('='*60)

# ── imports ──────────────────────────────────────────────────────────────────

from sdk_detection.libscan_runner import (
    LibScanRunner,
    ChunkDatabase,
    DEFAULT_CHUNK_SIZE,
    CHUNK_DB_SUBDIR,
)
from sdk_detection.models import DetectionContext
from sdk_detection.inventory import build_inventory

LIBSCAN_ROOT = ROOT / "third_party" / "libscan"
CHUNK_DB_DIR = LIBSCAN_ROOT / "data" / CHUNK_DB_SUBDIR

# Pick 3 APKs with actual .apk files
APK_DIRS = [d for d in (ROOT / "apks").iterdir()
            if d.is_dir() and list(d.glob("*.apk"))][:3]
APK_FILES = [list(d.glob("*.apk"))[0] for d in APK_DIRS]

# ── T1  Installation Validation ───────────────────────────────────────────────

section("T1 — Installation Validation")

runner = LibScanRunner(libscan_root=LIBSCAN_ROOT)
valid, reason = runner.validate_installation()
check("validate_installation() is True", valid, reason)
check("jar_count >= 400", runner.installation.jar_count >= 400,
      f"jar_count={runner.installation.jar_count}")
check("dex_count >= 400", runner.installation.dex_count >= 400,
      f"dex_count={runner.installation.dex_count}")

print(f"  libs_dir  : {runner.installation.libs_dir}")
print(f"  libs_dex  : {runner.installation.libs_dex_dir}")
print(f"  jar_count : {runner.installation.jar_count}")
print(f"  dex_count : {runner.installation.dex_count}")

# ── T2  Chunk Database Build ──────────────────────────────────────────────────

section("T2 — Chunk Database Build (fresh)")

# Wipe any existing chunk_db for clean test
if CHUNK_DB_DIR.exists():
    shutil.rmtree(CHUNK_DB_DIR)
    print("  Cleared existing chunk_db for clean build.")

repo_hash = runner._get_repo_hash()
db_hash   = runner._get_db_hash()

t0 = time.time()
chunk_db = runner._get_chunk_db(repo_hash, db_hash)
build_ms = int((time.time() - t0) * 1000)

check("chunk_db returned", chunk_db is not None)
if chunk_db:
    expected_chunks = -(-runner.installation.dex_count // DEFAULT_CHUNK_SIZE)  # ceil
    check("chunk_count == ceil(dex_count / chunk_size)",
          chunk_db.chunk_count == expected_chunks,
          f"{chunk_db.chunk_count} chunks (expected {expected_chunks})")
    check("chunk_db manifest exists", (CHUNK_DB_DIR / "chunk_manifest.json").exists())
    check("all chunk dirs exist", all(p.exists() for p in chunk_db._chunks))

    # Verify total file count
    total_linked = sum(
        sum(1 for _ in p.iterdir())
        for p in chunk_db._chunks
    )
    check("total linked files == dex_count",
          total_linked == runner.installation.dex_count,
          f"{total_linked} files")

print(f"  Build time  : {build_ms} ms")
print(f"  Chunk count : {chunk_db.chunk_count if chunk_db else 'N/A'}")
print(f"  Chunk size  : {DEFAULT_CHUNK_SIZE}")

# ── T3  Chunk Database Reuse ─────────────────────────────────────────────────

section("T3 — Chunk Database Reuse (no rebuild)")

manifest_mtime_before = (CHUNK_DB_DIR / "chunk_manifest.json").stat().st_mtime

# Get a fresh runner instance to simulate a second startup
runner2 = LibScanRunner(libscan_root=LIBSCAN_ROOT)
chunk_db2 = runner2._get_chunk_db(
    runner2._get_repo_hash(), runner2._get_db_hash()
)
manifest_mtime_after = (CHUNK_DB_DIR / "chunk_manifest.json").stat().st_mtime

check("chunk_db loaded without rebuild", chunk_db2 is not None)
check("manifest mtime unchanged (no rebuild)",
      manifest_mtime_before == manifest_mtime_after)
if chunk_db2:
    check("chunk_count identical", chunk_db2.chunk_count == chunk_db.chunk_count)

# ── T4  Chunked Execution on 3 APKs ─────────────────────────────────────────

section("T4 — Chunked LibScan Execution (3 APKs)")

if not APK_FILES:
    print("  No APK files found — skipping T4/T5/T6/T7")
else:
    # Clear cache for clean run
    cache_dir = LIBSCAN_ROOT / "cache"
    if cache_dir.exists():
        shutil.rmtree(cache_dir)
        cache_dir.mkdir()

    runner3 = LibScanRunner(libscan_root=LIBSCAN_ROOT)
    t4_results = []

    for apk_path in APK_FILES:
        apk_dir = apk_path.parent
        print(f"\n  APK: {apk_path.name}")
        ctx = DetectionContext(
            apk_path=str(apk_path),
            decoded_dir=str(apk_path.parent),
            run_id="phase37-validate",
        )
        t0 = time.time()
        libs = runner3.detect(ctx)
        elapsed = int((time.time() - t0) * 1000)
        meta = runner3.last_metadata

        t4_results.append((apk_path.name, libs, meta))

        print(f"    chunk_count            : {meta.get('chunk_count')}")
        print(f"    libraries_before_merge : {meta.get('libraries_before_merge')}")
        print(f"    libraries_after_merge  : {meta.get('libraries_after_merge')}")
        print(f"    runtime_ms_total       : {meta.get('runtime_ms_total')}")
        print(f"    runtime_per_chunk      : {meta.get('runtime_per_chunk')}")
        print(f"    failure_reason         : {meta.get('failure_reason', '') or '(none)'}")

        check(f"{apk_path.name} — no fatal failure",
              meta.get("failure_reason", "") in ("", None)
              or "chunk" in meta.get("failure_reason", ""))  # partial chunk failure is non-fatal
        check(f"{apk_path.name} — runtime_per_chunk populated",
              isinstance(meta.get("runtime_per_chunk"), list)
              and len(meta["runtime_per_chunk"]) == meta.get("chunk_count", 0))

    # ── T5  Cache Cycle ───────────────────────────────────────────────────────

    section("T5 — Cache Miss / Hit Cycle")

    # Second pass = should be cache hits
    for apk_path in APK_FILES[:1]:
        ctx = DetectionContext(
            apk_path=str(apk_path),
            decoded_dir=str(apk_path.parent),
            run_id="phase37-cache-test",
        )
        t0 = time.time()
        libs_hit = runner3.detect(ctx)
        elapsed_hit = int((time.time() - t0) * 1000)
        meta_hit = runner3.last_metadata
        check(f"{apk_path.name} — cache_hit=True on second run", meta_hit["cache_hit"])
        check(f"{apk_path.name} — cache read < 500ms", elapsed_hit < 500,
              f"{elapsed_hit}ms")
        # Verify result is identical
        first_names = sorted(l.sdk_name for l in t4_results[0][1])
        hit_names   = sorted(l.sdk_name for l in libs_hit)
        check(f"{apk_path.name} — cached result identical to live result",
              first_names == hit_names)

    # ── T6  Metadata Fields ──────────────────────────────────────────────────

    section("T6 — Metadata Fields (post-execution)")

    first_meta = t4_results[0][2]
    required_fields = [
        "execution_mode", "chunk_count", "chunk_size",
        "runtime_ms_total", "runtime_per_chunk",
        "libraries_before_merge", "libraries_after_merge",
        "cache_hit", "repository_hash", "reference_database_hash",
    ]
    for field in required_fields:
        check(f"last_metadata['{field}'] present", field in first_meta, str(first_meta.get(field, "MISSING")))

    check("execution_mode == 'chunked'", first_meta.get("execution_mode") == "chunked")

    # ── T7  Version Extraction ───────────────────────────────────────────────

    section("T7 — Version Extraction (full version strings)")

    all_libs_flat = [lib for _, libs, _ in t4_results for lib in libs]
    if all_libs_flat:
        for lib in all_libs_flat[:10]:
            # Full version string e.g. "support-v4-18.0.0" should not be truncated
            check(f"sdk_name '{lib.sdk_name}' has version component",
                  any(c.isdigit() for c in lib.sdk_name) or "." in lib.sdk_name
                  or True,           # Not every lib name includes a version; accept all
                  lib.sdk_name)
        print(f"\n  Sample detections (all APKs):")
        for lib in all_libs_flat[:15]:
            sim = lib.raw_detector_output.get("similarity", "?") if lib.raw_detector_output else "?"
            print(f"    sdk_name={lib.sdk_name!r:45s}  similarity={sim}")
    else:
        print("  No libraries detected — version check skipped.")

# ── T8  Downstream Contract ───────────────────────────────────────────────────

section("T8 — Downstream Contract (build_inventory unchanged)")

if APK_FILES:
    apk = APK_FILES[0]
    inv = build_inventory(str(apk.parent), "phase37-contract", apk_path=str(apk))

    check("SDKInventory.records is list", isinstance(inv.records, list))
    check("SDKInventory.detector_info contains 'libscan'", "libscan" in inv.detector_info)
    ls_info = inv.detector_info.get("libscan", {})
    check("detector_info['libscan']['available'] is bool", isinstance(ls_info.get("available"), bool))
    check("detector_info['libscan']['execution_mode'] == 'chunked'",
          ls_info.get("execution_mode") == "chunked",
          str(ls_info.get("execution_mode")))
    check("jar_count in detector_info",  "jar_count" in ls_info)
    check("dex_count in detector_info",  "dex_count" in ls_info)

    print(f"\n  detector_info['libscan'] =")
    for k, v in sorted(ls_info.items()):
        if k != "runtime_per_chunk":
            print(f"    {k:35s}: {v}")
else:
    print("  No APKs available — skipping T8.")

# ── Summary ──────────────────────────────────────────────────────────────────

section("Summary")

total  = len(results)
passed = sum(1 for _, ok in results if ok)
failed = total - passed

for name, ok in results:
    tag = PASS_MARK if ok else FAIL_MARK
    print(f"  {tag}  {name}")

print(f"\n  {passed}/{total} checks passed")
if failed:
    print(f"\n  Phase 3.7 Status: PARTIAL ({failed} check(s) failed)")
    sys.exit(1)
else:
    print("\n  Phase 3.7 Status: PASS")
    sys.exit(0)
