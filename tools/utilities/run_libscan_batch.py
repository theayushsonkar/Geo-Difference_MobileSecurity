import sys
import os
import time
from pathlib import Path

ROOT = Path(__file__).parent.resolve()
sys.path.insert(0, str(ROOT))

import sdk_detection.libscan_runner as ls_module
from sdk_detection.libscan_runner import LibScanRunner
from sdk_detection.models import DetectionContext

APK_DIR = ROOT / "apks"

def main():
    print("Starting Batch LibScan Testing...")
    
    # Configure for optimal speed
    ls_module.LIBSCAN_REFERENCE_CACHE_MODE = "full"
    
    # Find all APKs
    all_apks = list(APK_DIR.rglob("*.apk"))
    if not all_apks:
        print("No APKs found in the apks/ directory.")
        return
        
    # Pick a maximum of 50 APKs to test
    apks_to_test = all_apks[:50]
    print(f"Found {len(all_apks)} APKs. Testing {len(apks_to_test)} APKs...\n")
    
    # Initialize runner (this will preload the 452 libraries due to 'full' mode)
    print("Initializing LibScanRunner (preloading reference cache)...")
    t0_init = time.time()
    runner = LibScanRunner()
    
    # Clear the runner's cache directory so it actually runs
    import shutil
    if runner.cache_base.exists():
        shutil.rmtree(runner.cache_base)
        print("Cleared previous LibScan cache.")
        
    _ = runner._get_runtime()  # Force initialization
    print(f"Initialization complete in {time.time() - t0_init:.1f}s\n")
    
    results_summary = []
    
    for i, apk in enumerate(apks_to_test):
        print(f"[{i+1}/{len(apks_to_test)}] Processing {apk.name}...")
        
        ctx = DetectionContext(apk_path=str(apk), decoded_dir="", run_id=f"batch_test_{i}")
        
        t0_run = time.time()
        detected_libs = runner.detect(ctx)
        total_time = time.time() - t0_run
        
        meta = runner.last_metadata
        parse_ms = meta.get("apk_parse_time_ms", 0)
        
        # Sort libraries alphabetically
        lib_names = sorted([lib.sdk_name for lib in detected_libs])
        
        print(f"  -> Found {len(lib_names)} SDKs in {total_time:.1f}s (Parse: {parse_ms/1000:.1f}s)")
        if lib_names:
            print(f"  -> SDKs: {', '.join(lib_names)}")
        print()
        
        results_summary.append({
            "apk_name": apk.name,
            "total_time": total_time,
            "parse_time": parse_ms / 1000,
            "detected": lib_names
        })
        
    # Write a markdown report
    report_path = ROOT / "batch_libscan_results.md"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("# LibScan Batch Test Results\n\n")
        f.write(f"Tested {len(apks_to_test)} APKs using **Full Cache Mode**.\n\n")
        
        for res in results_summary:
            f.write(f"### `{res['apk_name']}`\n")
            f.write(f"- **Total Runtime:** {res['total_time']:.1f}s\n")
            f.write(f"- **APK Parse Time:** {res['parse_time']:.1f}s\n")
            f.write(f"- **SDKs Detected ({len(res['detected'])}):**\n")
            if res['detected']:
                for sdk in res['detected']:
                    f.write(f"  - `{sdk}`\n")
            else:
                f.write("  - *None*\n")
            f.write("\n")
            
    print(f"Done! Results written to {report_path.name}")

if __name__ == "__main__":
    main()
