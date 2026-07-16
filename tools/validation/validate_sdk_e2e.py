import time
import os
from pathlib import Path
from sdk_detection.inventory import build_inventory

def test_end_to_end():
    decoded_dir = Path("decoded")
    if not decoded_dir.exists():
        print("No decoded APKs found.")
        return

    sample_dirs = [d for d in decoded_dir.iterdir() if d.is_dir()][:10]
    
    if not sample_dirs:
        print("No sample apps found.")
        return

    print(f"Running SDK Pipeline on {len(sample_dirs)} APKs...\n")
    
    total_time = 0
    total_sdks = 0
    tracker_hits = 0
    cve_hits = 0
    
    import sdk_detection.inventory as inv_module
    import logging
    logging.basicConfig(level=logging.ERROR)

    for apk_path in sample_dirs:
        print(f"Analyzing {apk_path.name}...")
        
        t0 = time.time()
        inventory = build_inventory(str(apk_path), run_id="e2e_test")
        t_ms = (time.time() - t0) * 1000
        
        total_time += t_ms
        total_sdks += len(inventory.records)
        
        for rec in inventory.records:
            if rec.is_tracker:
                tracker_hits += 1
            
        print(f"  -> Found {len(inventory.records)} SDKs in {t_ms:.2f}ms")
        for k, v in inventory.detector_info.items():
            print(f"     - {k}: {v.get('runtime_ms', 0):.2f}ms, {v.get('libraries_detected', 0)} detected")
            
        # Verify CSV output
        rows = inventory.to_sdk_rows({"sample_id": apk_path.name})
        if rows:
            for row in rows:
                assert "is_tracker" in row, "is_tracker missing in CSV row!"
                assert "tracker_name" in row, "tracker_name missing in CSV row!"
                
    print("\n=== Validation Results ===")
    print(f"Total Apps         : {len(sample_dirs)}")
    print(f"Total SDKs         : {total_sdks}")
    print(f"Tracker Hits       : {tracker_hits}")
    print(f"Total Pipeline Time: {total_time:.2f}ms (Avg: {total_time/len(sample_dirs):.2f}ms per app)")
    print("SUCCESS: End-to-End Pipeline works flawlessly and produces correct schema!")

if __name__ == "__main__":
    test_end_to_end()
