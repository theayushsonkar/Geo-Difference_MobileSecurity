import sys
import os
import time
import psutil
from pathlib import Path

ROOT = Path(__file__).parent.resolve()
sys.path.insert(0, str(ROOT))

import sdk_detection.libscan_runner as ls_module
from sdk_detection.libscan_runner import LibScanRunner
from sdk_detection.models import DetectionContext

APK_DIR = ROOT / "apks"

def get_process_memory():
    process = psutil.Process(os.getpid())
    return process.memory_info().rss / (1024 * 1024)

def test_mode(mode: str, apks: list):
    print(f"\n==========================================")
    print(f"Testing Mode: {mode.upper()}")
    print(f"==========================================")
    
    ls_module.LIBSCAN_REFERENCE_CACHE_MODE = mode
    
    cache_dir = ROOT / "third_party/libscan/cache"
    import shutil
    if cache_dir.exists():
        shutil.rmtree(cache_dir)
    
    mem_start = get_process_memory()
    peak_mem = mem_start
    
    t0 = time.time()
    runner = LibScanRunner()
    
    # Force initialization to measure preload time
    _ = runner._get_runtime()
    
    init_time = time.time() - t0
    
    mem_after_init = get_process_memory()
    peak_mem = max(peak_mem, mem_after_init)
    
    print(f"Initialization Time : {init_time:.1f}s")
    print(f"Memory after Init   : {mem_after_init:.1f} MB (Delta: +{mem_after_init - mem_start:.1f} MB)")
    
    for i, apk in enumerate(apks[:2]):
        print(f"\nProcessing APK {i+1}: {apk.name}...")
        
        ctx = DetectionContext(apk_path=str(apk), decoded_dir="", run_id=f"audit_run_{i}")
        
        t1 = time.time()
        runner.detect(ctx)
        run_time = time.time() - t1
        
        mem_after_run = get_process_memory()
        peak_mem = max(peak_mem, mem_after_run)
        
        print(f"  Runtime         : {run_time:.1f}s")
        print(f"  Current Memory  : {mem_after_run:.1f} MB")
        
    print(f"\nFinal Peak Memory for {mode.upper()} mode: {peak_mem:.1f} MB")

def main():
    apks = list(APK_DIR.rglob("*.apk"))[:2]
    if len(apks) < 2:
        print("Need at least 2 APKs for testing.")
        return
        
    print(f"Found APKs: {[a.name for a in apks]}")
    
    # Test "none" mode
    test_mode("none", apks)
    
    # Need to run in a fresh process to get accurate memory readings, but sequential is fine to see the drift.
    # We will test "full" mode
    test_mode("full", apks)

if __name__ == "__main__":
    main()
