import sys
from pathlib import Path
import json

ROOT = Path(__file__).parent.resolve()
sys.path.insert(0, str(ROOT / "third_party/libscan/tool/module"))

from apk import Apk
from lib import ThirdLib
from analyzer import detect
import os

APK_PATH = ROOT / "apks/com.maxbupa.healthapp/com.maxbupa.healthapp.apk"
DEX_DIR = ROOT / "third_party/libscan/data/ground_truth_libs_dex"
TOOL_DIR = ROOT / "third_party/libscan/tool"

def main():
    os.chdir(str(TOOL_DIR))
    print("Parsing APK...")
    apk_obj = Apk(str(APK_PATH))
    
    dex_files = list(DEX_DIR.glob("*.dex"))
    if not dex_files:
        print("No DEX files found.")
        return
        
    print(f"Testing against {dex_files[0].name}...")
    lib_obj = ThirdLib(str(dex_files[0]))
    result = detect(apk_obj, lib_obj)
    
    print("Result structure:")
    print(repr(result))
    
    # Try a few more until we get a hit (if first is empty)
    if not result:
        print("Empty result, searching for a hit...")
        for dex_file in dex_files[1:]:
            lib_obj = ThirdLib(str(dex_file))
            result = detect(apk_obj, lib_obj)
            if result:
                print(f"Hit on {dex_file.name}:")
                print(repr(result))
                break

if __name__ == "__main__":
    main()
