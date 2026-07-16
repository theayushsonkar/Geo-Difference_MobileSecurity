"""
validate_libscan_embedded.py — Phase 3.10 Proof of Concept

This script verifies whether LibScan can be imported and executed as a Python
library instead of via external CLI subprocesses. It measures runtime, memory,
and object reuse safety.
"""
import os
import sys
import time
from pathlib import Path

# Add LibScan module to path to allow internal imports to resolve correctly
ROOT = Path(__file__).parent.resolve()
LIBSCAN_MODULE = ROOT / "third_party/libscan/tool/module"
sys.path.insert(0, str(LIBSCAN_MODULE))

print("=== Task 1: Importing LibScan Modules ===")
try:
    from apk import Apk
    from lib import ThirdLib
    from analyzer import detect
    print("[PASS] Successfully imported Apk, ThirdLib, and detect.")
except ImportError as e:
    print(f"[FAIL] Failed to import: {e}")
    sys.exit(1)

try:
    import psutil
    has_psutil = True
    process = psutil.Process(os.getpid())
    def get_ram_mb():
        return process.memory_info().rss / (1024 * 1024)
except ImportError:
    has_psutil = False
    def get_ram_mb(): return 0.0

# ── Setup ─────────────────────────────────────────────────────────────
APK_PATH = ROOT / "apks/com.maxbupa.healthapp/com.maxbupa.healthapp.apk"
APK_PATH_2 = ROOT / "bench_tiny_chunk/tiny.dex"  # We'll pretend this is a second APK
LIBS_DIR = ROOT / "third_party/libscan/data/ground_truth_libs_dex"
lib_files = sorted(list(LIBS_DIR.glob("*.dex")))

# LibScan expects to be run from third_party/libscan/tool so it can find conf/
os.chdir(str(LIBSCAN_MODULE.parent))

print(f"\nInitial RAM: {get_ram_mb():.1f} MB")

# ── Task 2: Create One Apk Object ─────────────────────────────────────
print("\n=== Task 2: Create One Apk Object ===")
t0 = time.time()
ram0 = get_ram_mb()
print(f"Parsing APK: {APK_PATH.name} ... (this takes ~200s)")
apk_obj = Apk(str(APK_PATH))
t_apk = time.time() - t0
ram_apk = get_ram_mb()
print(f"[PASS] Apk object created.")
print(f"  Time taken : {t_apk:.1f}s")
print(f"  RAM delta  : +{ram_apk - ram0:.1f} MB  (Total: {ram_apk:.1f} MB)")
print(f"  Classes    : {len(apk_obj.classes_dict)}")

# ── Task 3: Single Library Detection ──────────────────────────────────
print("\n=== Task 3: Single Library Detection ===")
target_lib = lib_files[0]
print(f"Loading reference lib: {target_lib.name}")
t0 = time.time()
lib_obj = ThirdLib(str(target_lib))
t_lib = time.time() - t0
print(f"  Time to parse lib: {t_lib:.3f}s")

print("Running detect()...")
t0 = time.time()
result = detect(apk_obj, lib_obj)
t_det = time.time() - t0
print(f"[PASS] Detection complete in {t_det:.3f}s")
print(f"  Result: {result}")

# ── Task 4: APK Object Reuse ──────────────────────────────────────────
print("\n=== Task 4: APK Object Reuse (20 libraries) ===")
print("Reusing the identical apk_obj against 20 reference libraries...")
ram_before = get_ram_mb()
t0 = time.time()
matches = 0
for i in range(1, min(21, len(lib_files))):
    lib_path = lib_files[i]
    temp_lib = ThirdLib(str(lib_path))
    res = detect(apk_obj, temp_lib)
    if res:
        matches += 1
t_reuse = time.time() - t0
ram_after = get_ram_mb()

print(f"[PASS] Successfully processed 20 libs in {t_reuse:.1f}s")
print(f"  Matches found  : {matches}")
print(f"  Avg time/lib   : {t_reuse / 20:.2f}s (parse + detect)")
print(f"  RAM drift      : {ram_after - ram_before:.1f} MB (Expected near 0 if no memory leak)")

# ── Task 5: ThirdLib Reuse ────────────────────────────────────────────
print("\n=== Task 5: ThirdLib Reuse ===")
print(f"Creating a second Apk object: {APK_PATH_2.name}")
try:
    apk_obj_2 = Apk(str(APK_PATH_2))
    print("Running detect() with reused lib_obj from Task 3...")
    res2 = detect(apk_obj_2, lib_obj)
    print(f"[PASS] ThirdLib reused successfully. Result: {res2}")
except Exception as e:
    print(f"[FAIL] ThirdLib reuse failed: {e}")

# ── Task 9: ThirdLib Cache Feasibility Extrapolation ──────────────────
print("\n=== Task 9: ThirdLib Cache Feasibility ===")
print("Loading 20 ThirdLib objects to extrapolate full DB cost...")
ram_start = get_ram_mb()
t0 = time.time()
cache = []
for i in range(20):
    cache.append(ThirdLib(str(lib_files[i])))
t_cache = time.time() - t0
ram_end = get_ram_mb()

cost_per_lib_mb = (ram_end - ram_start) / 20
cost_per_lib_s = t_cache / 20
est_total_mb = cost_per_lib_mb * 452
est_total_s = cost_per_lib_s * 452

print(f"  Avg RAM per ThirdLib  : {cost_per_lib_mb:.2f} MB")
print(f"  Avg Time per ThirdLib : {cost_per_lib_s:.2f} s")
print(f"  Extrapolated 452 DB   : ~{est_total_mb:.1f} MB RAM, ~{est_total_s:.1f}s Initialization")

print("\n=== POC Execution Complete ===")
