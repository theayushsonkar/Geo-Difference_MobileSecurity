import sys
import os
import time
import json
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
    return process.memory_info().rss / (1024 * 1024)  # MB

def main():
    print("=== Phase 3.11 Final Engineering Audit ===")
    
    # 1. Gather APKs
    apks = list(APK_DIR.rglob("*.apk"))[:10]
    if not apks:
        print("No APKs found.")
        return
        
    print(f"[*] Found {len(apks)} APKs for testing.")
    
    runner = LibScanRunner()
    
    total_time = 0
    total_parse_time = 0
    
    peak_memory = 0
    
    print("\n--- Running 10 APKs ---")
    for i, apk in enumerate(apks):
        print(f"\n[{i+1}/10] Processing {apk.name}...")
        
        mem_before = get_process_memory()
        
        context = DetectionContext(apk_path=str(apk), decoded_dir="", run_id=f"audit_{i}")
        
        t0 = time.time()
        results = runner.detect(context)
        t_total = time.time() - t0
        
        mem_after = get_process_memory()
        peak_memory = max(peak_memory, mem_after)
        
        meta = runner.last_metadata
        parse_ms = meta.get("apk_parse_time_ms", 0)
        
        total_time += t_total
        total_parse_time += (parse_ms / 1000)
        
        print(f"  Total Runtime : {t_total:.1f}s")
        print(f"  APK Parse Time: {parse_ms / 1000:.1f}s")
        print(f"  Match Time    : {t_total - (parse_ms / 1000):.1f}s")
        print(f"  Libs Detected : {len(results)}")
        print(f"  Process RAM   : {mem_after:.1f} MB (Delta: {mem_after - mem_before:+.1f} MB)")
        
        if results:
            print("  Raw Output Example:")
            print(f"    {results[0].raw_detector_output}")
            
    print("\n--- LRU Cache Verification ---")
    runtime = runner._get_runtime()
    cache_info = runtime._get_third_lib.cache_info()
    print(f"Cache Hits   : {cache_info.hits}")
    print(f"Cache Misses : {cache_info.misses}")
    print(f"Cache Size   : {cache_info.currsize} / {cache_info.maxsize}")
    
    hit_rate = (cache_info.hits / (cache_info.hits + cache_info.misses)) * 100 if (cache_info.hits + cache_info.misses) > 0 else 0
    print(f"Hit Rate     : {hit_rate:.1f}%")

    print("\n--- Overall Profile ---")
    print(f"Peak Process RAM     : {peak_memory:.1f} MB")
    print(f"Total Time (10 APKs) : {total_time:.1f}s")
    print(f"Avg Time per APK     : {total_time / len(apks):.1f}s")
    print(f"Avg Parse Time / APK : {total_parse_time / len(apks):.1f}s")
    
    print("\nAudit Complete.")

if __name__ == "__main__":
    main()
