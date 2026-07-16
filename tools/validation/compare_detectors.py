import sys
import os
import time
import subprocess
from pathlib import Path

ROOT = Path(__file__).parent.resolve()
sys.path.insert(0, str(ROOT))

from sdk_detection.libscan_runner import LibScanRunner
from sdk_detection.fallback_detector import FallbackDetector
from sdk_detection.models import DetectionContext
import sdk_detection.libscan_runner as ls_module

APK_DIR = ROOT / "apks"
DECODED_DIR = ROOT / "decoded"
APKTOOL_JAR = r"D:\Android\platform-tools-latest-windows\platform-tools\apktool.jar"

def decode_apk(apk_path: Path, output_dir: Path):
    if output_dir.exists():
        return True
        
    print(f"Decoding {apk_path.name} with apktool...")
    cmd = [
        "java", "-jar", "-Xmx2048M",
        "-Duser.language=en", "-Dfile.encoding=UTF8",
        APKTOOL_JAR, "d", str(apk_path), "-o", str(output_dir), "-f"
    ]
    
    t0 = time.time()
    res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    print(f"Decoded in {time.time() - t0:.1f}s (return code: {res.returncode})")
    return res.returncode == 0

def main():
    DECODED_DIR.mkdir(exist_ok=True)
    
    ls_module.LIBSCAN_REFERENCE_CACHE_MODE = "full"
    
    apks = list(APK_DIR.rglob("*.apk"))[:20]
    if not apks:
        print("No APKs found.")
        return
        
    print("Initializing Detectors...")
    fallback_det = FallbackDetector()
    libscan_det = LibScanRunner()
    _ = libscan_det._get_runtime() # Preload cache
    
    results = {}
    
    for apk in apks:
        print(f"\n======================================")
        print(f"Processing {apk.name}")
        print(f"======================================")
        
        package_name = apk.stem
        decoded_path = DECODED_DIR / f"{package_name}_decoded"
        
        if not decode_apk(apk, decoded_path):
            print(f"Failed to decode {apk.name}, skipping.")
            continue
            
        print("Collecting manifest and smali evidence for FallbackDetector...")
        ev, meta = fallback_det._collect_manifest_evidence(decoded_path)
        smali = fallback_det._collect_smali_prefixes(decoded_path)
            
        ctx = DetectionContext(
            apk_path=str(apk), 
            decoded_dir=str(decoded_path), 
            run_id=f"compare_{package_name}_{time.time()}", # Unique ID prevents LibScan from caching
            manifest_evidence=ev,
            meta_items=meta,
            smali_prefixes=smali
        )
        
        # Clear LibScan's cache directory so it actually processes the APK
        import shutil
        if libscan_det.cache_base.exists():
            shutil.rmtree(libscan_det.cache_base)
        
        # Run Fallback
        t0 = time.time()
        fb_results = fallback_det.detect(ctx)
        fb_time = time.time() - t0
        fb_set = {lib.sdk_name for lib in fb_results}
        print(f"Fallback detected {len(fb_set)} SDKs in {fb_time:.1f}s")
        
        # Run LibScan
        t0 = time.time()
        ls_results = libscan_det.detect(ctx)
        ls_time = time.time() - t0
        ls_set = {lib.sdk_name for lib in ls_results}
        print(f"LibScan detected {len(ls_set)} SDKs in {ls_time:.1f}s")
        
        only_ls = ls_set - fb_set
        only_fb = fb_set - ls_set
        both = ls_set & fb_set
        
        results[package_name] = {
            "ls_count": len(ls_set),
            "fb_count": len(fb_set),
            "both_count": len(both),
            "only_ls": only_ls,
            "only_fb": only_fb,
            "both": both
        }
        
    # Print the requested table
    print("\n\n" + "="*60)
    print("FINAL COMPARISON TABLE")
    print("="*60)
    print(f"{'APK':<20} | {'LibScan':<10} | {'Fallback':<10} | {'Both':<10}")
    print("-" * 59)
    for pkg, data in results.items():
        print(f"{pkg:<20} | {data['ls_count']:<10} | {data['fb_count']:<10} | {data['both_count']:<10}")
        
    print("\n\n" + "="*60)
    print("SDK DETAILS")
    print("="*60)
    for pkg, data in results.items():
        print(f"\n--- {pkg} ---")
        print(f"Found ONLY by LibScan ({len(data['only_ls'])}):")
        for sdk in sorted(data['only_ls']):
            print(f"  + {sdk}")
            
        print(f"\nFound ONLY by Fallback ({len(data['only_fb'])}):")
        for sdk in sorted(data['only_fb']):
            print(f"  + {sdk}")
            
        print(f"\nFound by BOTH ({len(data['both'])}):")
        for sdk in sorted(data['both']):
            print(f"  + {sdk}")

if __name__ == "__main__":
    main()
