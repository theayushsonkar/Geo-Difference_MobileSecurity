import sys
import os
import shutil
import time
from pathlib import Path

# Fix python path
ROOT = Path(__file__).parent.resolve()
sys.path.insert(0, str(ROOT))

import sdk_detection.libscan_runner as ls_module
from sdk_detection.libscan_runner import LibScanRunner
from sdk_detection.models import DetectionContext

APK_PATH = ROOT / "apks/com.maxbupa.healthapp/com.maxbupa.healthapp.apk"
CACHE_DIR = ROOT / "third_party/libscan/cache"

def clear_cache():
    if CACHE_DIR.exists():
        shutil.rmtree(CACHE_DIR)
    print("[*] Cache cleared.")

def run_mode(mode: str) -> tuple:
    print(f"\n=====================================")
    print(f"Running mode: {mode}")
    print(f"=====================================")
    
    ls_module.LIBSCAN_MODE = mode
    clear_cache()
    
    runner = LibScanRunner()
    context = DetectionContext(apk_path=str(APK_PATH), decoded_dir="", run_id="benchmark")
    
    t0 = time.time()
    results = runner.detect(context)
    t_total = time.time() - t0
    
    metadata = runner.last_metadata
    
    print(f"Done in {t_total:.1f}s")
    print(f"Total libs found: {len(results)}")
    if mode == "embedded":
        print(f"APK Parse time: {metadata.get('apk_parse_time_ms', 0) / 1000:.1f}s")
        
    sorted_libs = sorted([lib.sdk_name for lib in results])
    return sorted_libs, metadata, t_total

def main():
    if not APK_PATH.exists():
        print(f"APK not found: {APK_PATH}")
        sys.exit(1)
        
    print("Phase 3.11 Regression Validation")
    
    libs_embedded, meta_embedded, time_embedded = run_mode("embedded")
    libs_subprocess, meta_subprocess, time_subprocess = run_mode("subprocess")
    
    print("\n\n=== Validation Report ===")
    print("--- Behavioral Match ---")
    if libs_embedded == libs_subprocess:
        print("[PASS] Both modes detected the exact same libraries.")
    else:
        print("[FAIL] Mismatch detected!")
        print("Embedded  :", libs_embedded)
        print("Subprocess:", libs_subprocess)
        
    print("\n--- Performance Comparison ---")
    print(f"Subprocess Runtime : {time_subprocess:.1f}s")
    print(f"Embedded Runtime   : {time_embedded:.1f}s")
    
    if time_subprocess > 0:
        speedup = time_subprocess / time_embedded
        print(f"Speedup            : {speedup:.2f}x faster")
        
    print("\n--- Metadata Example (Embedded) ---")
    import pprint
    pprint.pprint(meta_embedded)
    
if __name__ == "__main__":
    main()
