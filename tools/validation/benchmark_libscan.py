import os
import sys
import time
import subprocess
from pathlib import Path

def print_header(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")

def run_raw_libscan(apk_folder: Path, output_folder: Path):
    cmd = [
        sys.executable, "LibScan.py", "detect_all",
        "-o", str(output_folder.resolve()),
        "-af", str(apk_folder.resolve()),
        "-lf", str(Path("third_party/libscan/data/ground_truth_libs").resolve()),
        "-ld", str(Path("third_party/libscan/data/ground_truth_libs_dex").resolve())
    ]
    env = os.environ.copy()
    dex2jar_path = str(Path("third_party/libscan/tool/module").resolve() / "dex2jar")
    env["PATH"] = dex2jar_path + os.pathsep + env.get("PATH", "")
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    
    t0 = time.time()
    with open("raw_libscan_err.log", "w", encoding="utf-8") as f_err:
        res = subprocess.run(
            cmd,
            cwd="third_party/libscan/tool",
            stdout=subprocess.DEVNULL,
            stderr=f_err,
            timeout=600,
            env=env
        )
    t1 = time.time()
    
    if res.returncode != 0:
        print(f"Raw LibScan failed: {res.stderr}")
    return t1 - t0

def main():
    bench_dir = Path("bench_apks")
    if not bench_dir.exists():
        print("bench_apks does not exist!")
        return
        
    apks = list(bench_dir.glob("*.apk"))
    if not apks:
        print("No APKs found in bench_apks!")
        return
        
    print_header(f"TEST A: Single APK (Raw vs Wrapper)")
    first_apk = apks[0]
    print(f"Using APK: {first_apk.name}")
    
    # 1. Raw LibScan
    raw_output = Path("bench_raw_out")
    raw_output.mkdir(exist_ok=True)
    single_apk_dir = Path("bench_single")
    single_apk_dir.mkdir(exist_ok=True)
    try:
        (single_apk_dir / first_apk.name).symlink_to(first_apk.resolve())
    except OSError:
        import shutil
        shutil.copy2(first_apk, single_apk_dir / first_apk.name)
        
    print("Running Raw LibScan...")
    raw_time = run_raw_libscan(single_apk_dir, raw_output)
    print(f"Raw LibScan runtime: {raw_time:.2f} s")
    
    # 2. Wrapped LibScan
    print("Running Wrapped LibScan (Cache Miss)...")
    from sdk_detection.inventory import build_inventory
    # Clear cache to ensure cache miss
    import shutil
    cache_dir = Path("third_party/libscan/cache")
    if cache_dir.exists():
        shutil.rmtree(cache_dir)
        
    t0 = time.time()
    inv = build_inventory(str(single_apk_dir), "bench-test", apk_path=str(single_apk_dir / first_apk.name))
    wrapped_time = time.time() - t0
    
    libscan_meta = inv.detector_info.get("libscan", {})
    inner_runtime = libscan_meta.get("runtime_ms", 0) / 1000.0
    
    print(f"Wrapped pipeline total runtime: {wrapped_time:.2f} s")
    print(f"LibScanRunner internal detect() runtime: {inner_runtime:.2f} s")
    overhead = wrapped_time - raw_time
    print(f"Total Wrapper Overhead: {overhead:.2f} s")
    
    print_header("TEST B: Batch Execution")
    # Batch raw
    batch_raw_out = Path("bench_batch_out")
    batch_raw_out.mkdir(exist_ok=True)
    print(f"Running Raw LibScan on {len(apks)} APKs...")
    batch_raw_time = run_raw_libscan(bench_dir, batch_raw_out)
    print(f"Raw LibScan Batch runtime: {batch_raw_time:.2f} s ({batch_raw_time/len(apks):.2f} s/APK)")
    
    # Batch wrapped
    print(f"Running Wrapped LibScan on {len(apks)} APKs...")
    if cache_dir.exists():
        shutil.rmtree(cache_dir)
    t0 = time.time()
    for apk in apks:
        build_inventory(str(bench_dir), "bench-batch", apk_path=str(apk))
    batch_wrapped_time = time.time() - t0
    print(f"Wrapped Pipeline Batch runtime: {batch_wrapped_time:.2f} s ({batch_wrapped_time/len(apks):.2f} s/APK)")
    
    print_header("TEST 7: Version Extraction Validation")
    print(f"Checking extracted versions from first APK...")
    for rec in inv.records:
        if rec.detection_source_primary == "libscan" or rec.detection_source == "both":
            print(f"  {rec.sdk_name} -> Version: '{rec.sdk_version}'")
            
if __name__ == "__main__":
    main()
