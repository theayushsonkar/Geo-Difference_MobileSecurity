import os
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from sdk_detection.inventory import build_inventory
from sdk_detection.canonicalizer import Canonicalizer
from sdk_detection.metadata_loader import MetadataLoader
from manifest_scanner.extractor import ManifestFeatureExtractor
from manifest_scanner.models import SampleRecord

def create_mock_apk(apk_dir: Path, manifest_content: str, smali_files: list):
    apk_dir.mkdir(parents=True, exist_ok=True)
    with open(apk_dir / "AndroidManifest.xml", "w", encoding="utf-8") as f:
        f.write(manifest_content)
    
    for sf in smali_files:
        p = apk_dir / sf
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(".class public L" + sf.replace(".smali", "") + ";")

def test_apk(test_name, apk_dir):
    print(f"\n--- Testing {test_name} ---")
    sample = SampleRecord(
        sample_id=test_name,
        package_name="com.test.app",
        app_country_code="US",
        source_path=str(apk_dir),
        apk_sha256="dummyhash"
    )
    
    # 1. Legacy _detect_sdks
    extractor = ManifestFeatureExtractor(sample, "run1")
    extractor.app_row = {"has_smali": True, "package_name": "com.test.app", "app_country_code": "US", "app_region_group": "north_america", "sample_id": test_name}
    extractor.root = True # mock
    extractor.app_el = True # mock
    
    # We must patch extractor's filesystem reading slightly if we want it to work fully,
    # but let's actually just call it and rely on its internal file reading.
    # Actually, extractor requires a proper ET for app_el. Let's parse it correctly.
    import xml.etree.ElementTree as ET
    tree = ET.parse(str(apk_dir / "AndroidManifest.xml"))
    extractor.root = tree.getroot()
    extractor.app_el = extractor.root.find("application")
    
    # We also need to populate _smali_files manually to avoid walking everything
    extractor._smali_files = []
    for root, dirs, files in os.walk(apk_dir):
        for file in files:
            if file.endswith('.smali'):
                extractor._smali_files.append((os.path.join(root, file), os.path.relpath(os.path.join(root, file), apk_dir).lower().replace('\\', '/')))
                
    extractor._detect_sdks()
    
    legacy_rows = extractor.sdk_rows
    legacy_keys = sorted([(r['sdk_name'], r['sdk_prefix']) for r in legacy_rows])
    
    # 2. New build_inventory
    inventory = build_inventory(str(apk_dir), "run1")
    new_rows = inventory.to_sdk_rows(extractor._meta())
    new_keys = sorted([(r['sdk_name'], r['sdk_prefix']) for r in new_rows])
    
    print(f"Legacy SDK count: {len(legacy_rows)}")
    for r in legacy_keys: print(f"  - {r}")
    
    print(f"New SDK count: {len(new_rows)}")
    for r in new_keys: print(f"  - {r}")
    
    if legacy_keys == new_keys:
        print("[OK] Detection match!")
    else:
        print("[FAIL] Detection mismatch!")
        
    return legacy_rows, new_rows

def run_validation():
    test_dir = PROJECT_ROOT / "scratch" / "test_apks"
    test_dir.mkdir(parents=True, exist_ok=True)
    
    # Mock APK 1: Facebook and Firebase via manifest and smali
    manifest1 = """<?xml version="1.0" encoding="utf-8"?>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.app">
        <application>
            <meta-data android:name="com.facebook.sdk.ApplicationId" android:value="12345"/>
        </application>
    </manifest>
    """
    smali1 = [
        "smali/com/google/firebase/FirebaseApp.smali",
        "smali/com/facebook/login/LoginManager.smali"
    ]
    apk1_dir = test_dir / "apk1"
    create_mock_apk(apk1_dir, manifest1, smali1)
    
    # Mock APK 2: ByteDance/Pangle and Mintegral (checking aliases and deduplication)
    manifest2 = """<?xml version="1.0" encoding="utf-8"?>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.app">
        <application>
            <activity android:name="com.bytedance.sdk.openadsdk.activity.TTFullScreenVideoActivity"/>
        </application>
    </manifest>
    """
    smali2 = [
        "smali/com/bytedance/sdk/openadsdk/AdSlot.smali",
        "smali/com/mbridge/msdk/MBridgeConstans.smali",
        "smali/com/mbridge/msdk/video/module/MBridgeVideoView.smali"
    ]
    apk2_dir = test_dir / "apk2"
    create_mock_apk(apk2_dir, manifest2, smali2)
    
    # Mock APK 3: ironSource and unknown SDK
    manifest3 = """<?xml version="1.0" encoding="utf-8"?>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.app">
        <application>
            <meta-data android:name="ironsource.sdk.key" android:value="abcde"/>
        </application>
    </manifest>
    """
    smali3 = [
        "smali/com/unity3d/ironsourceads/BannerAd.smali",
        "smali/com/unknown/sdk/UnknownSDK.smali"
    ]
    apk3_dir = test_dir / "apk3"
    create_mock_apk(apk3_dir, manifest3, smali3)
    
    test_apk("APK1", apk1_dir)
    test_apk("APK2", apk2_dir)
    test_apk("APK3", apk3_dir)
    
    print("\n--- Verifying Unknown Pass-Through ---")
    canon = Canonicalizer()
    print("resolve 'com.unknown.sdk' ->", canon.resolve("com.unknown.sdk"))
    print("resolve 'unknown_sdk_alias' ->", canon.resolve("unknown_sdk_alias"))
    
    print("\n--- Duplicate Consolidation ---")
    m = MetadataLoader()
    print(f"Total entries in Canonicalizer alias index: {len(canon._alias_index)}")
    print(f"Total entries in MetadataLoader db: {len(m._db)}")

if __name__ == "__main__":
    run_validation()
