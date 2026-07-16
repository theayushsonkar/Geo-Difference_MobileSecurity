import logging
from pathlib import Path
import time
import json
import shutil
from sdk_detection.libscan_runner import LibScanRunner
from sdk_detection.models import DetectionContext

logging.basicConfig(level=logging.DEBUG)

def run():
    print("\n--- 1. Installation Validation & 2/3. Layout Discovery ---")
    runner = LibScanRunner()
    valid, reason = runner.validate_installation()
    print(f"Is Valid: {valid}")
    if not valid:
        print(f"Reason: {reason}")
    print("Resolved Reference Paths:")
    print(f"  libs_dir: {runner.installation.libs_dir}")
    print(f"  libs_dex_dir: {runner.installation.libs_dex_dir}")

    # Create dummy APK
    scratch_dir = Path("scratch/test_apks")
    scratch_dir.mkdir(parents=True, exist_ok=True)
    apk_path = scratch_dir / "dummy.apk"
    if not apk_path.exists():
        with open(apk_path, "wb") as f:
            f.write(b"dummy apk content")
            
    context = DetectionContext(
        apk_path=str(apk_path),
        decoded_dir=str(scratch_dir),
        run_id="run_1"
    )

    print("\n--- 4. Execution Validation ---")
    # Clean cache
    if runner.cache_base.exists():
        shutil.rmtree(runner.cache_base)
        
    start = time.time()
    results1 = runner.detect(context)
    print(f"Run 1 completed in {time.time()-start:.2f}s")
    print(f"Libraries Detected: {len(results1)}")
    print(f"Metadata: {json.dumps(runner.last_metadata, indent=2)}")
    
    print("\n--- 5. Cache Validation ---")
    start = time.time()
    results2 = runner.detect(context)
    print(f"Run 2 completed in {time.time()-start:.2f}s")
    print(f"Libraries Detected: {len(results2)}")
    print(f"Metadata: {json.dumps(runner.last_metadata, indent=2)}")
    print(f"Cache Hit Expected True, Got: {runner.last_metadata.get('cache_hit')}")

    print("\n--- 6. Failure-Handling Validation ---")
    # Temporarily break LibScan.py
    target = runner.installation.tool_dir / "LibScan.py"
    backup = target.with_suffix(".py.bak")
    target.rename(backup)
    
    try:
        runner_broken = LibScanRunner()
        results3 = runner_broken.detect(context)
        print(f"Libraries Detected: {len(results3)}")
        print(f"Metadata: {json.dumps(runner_broken.last_metadata, indent=2)}")
        print(f"Available Expected False, Got: {runner_broken.last_metadata.get('available')}")
    finally:
        backup.rename(target)

if __name__ == "__main__":
    run()
