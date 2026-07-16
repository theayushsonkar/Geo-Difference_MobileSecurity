import os
from pathlib import Path
import zipfile

APK_DIR = Path("apks")

def extract_main_apk(xapk_path: Path):
    target_apk_name = f"{xapk_path.stem}.apk"
    target_apk_path = xapk_path.parent / target_apk_name
    
    if target_apk_path.exists():
        return True
        
    print(f"Extracting {xapk_path.name}...")
    try:
        with zipfile.ZipFile(xapk_path, 'r') as z:
            apk_files = [f for f in z.namelist() if f.endswith('.apk')]
            main_apk = None
            
            if "base.apk" in apk_files:
                main_apk = "base.apk"
            elif f"{xapk_path.stem}.apk" in apk_files:
                main_apk = f"{xapk_path.stem}.apk"
            elif len(apk_files) == 1:
                main_apk = apk_files[0]
            elif apk_files:
                main_apk = max(apk_files, key=lambda f: z.getinfo(f).file_size)
                
            if main_apk:
                source = z.open(main_apk)
                with open(target_apk_path, "wb") as f_out:
                    f_out.write(source.read())
                print(f"  -> Saved as {target_apk_name}")
                return True
            else:
                print("  -> No APK found inside XAPK!")
                return False
    except Exception as e:
        print(f"Failed to extract {xapk_path}: {e}")
        return False

def main():
    # First, count existing APKs
    existing_apks = list(APK_DIR.rglob("*.apk"))
    print(f"Found {len(existing_apks)} existing APK files.")
    
    # We want 20 total.
    target_total = 10
    needed = target_total - len(existing_apks)
    
    if needed <= 0:
        print("Already have 20 or more APKs extracted.")
        return
        
    print(f"Need to extract {needed} more APKs.")
    
    xapks = list(APK_DIR.rglob("*.xapk"))
    extracted_count = 0
    
    for xapk in xapks:
        target_apk_path = xapk.parent / f"{xapk.stem}.apk"
        if target_apk_path.exists():
            continue
            
        if extract_main_apk(xapk):
            extracted_count += 1
            
        if extracted_count >= needed:
            break
            
    print(f"\nDone extracting. Total new extractions: {extracted_count}")

if __name__ == "__main__":
    main()
