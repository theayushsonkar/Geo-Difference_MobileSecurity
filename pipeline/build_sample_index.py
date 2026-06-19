from pathlib import Path
import hashlib
import pandas as pd

# Get project root (parent of the pipeline folder)
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# ------------------------------------------------------------------
# CONSTANTS
# ------------------------------------------------------------------
COLLECTION_BATCH = "batch_001"
APP_STORE = "apkpure"
NOTES = "auto_generated"


# ------------------------------------------------------------------
# HELPERS
# ------------------------------------------------------------------
def compute_sha256(file_path: Path) -> str:
    """Computes the SHA256 hash of a file by reading it in chunks."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            sha256.update(chunk)
    return sha256.hexdigest()


def find_main_apk(app_dir: Path) -> Path:
    """Finds the main APK in the normalized directory (not starting with 'config.')."""
    apks = list(app_dir.glob("*.apk"))
    for apk in apks:
        if apk.name.startswith("config."):
            continue
        return apk
    return None


# ------------------------------------------------------------------
# MAIN PIPELINE STAGE
# ------------------------------------------------------------------
def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--app-store",
        default=APP_STORE,
        help="App store source name (e.g. apkpure, google_play)"
    )
    parser.add_argument(
        "--batch",
        default=COLLECTION_BATCH,
        help="Collection batch name"
    )
    args = parser.parse_args()

    normalized_dir = PROJECT_ROOT / "normalized"
    decoded_dir = PROJECT_ROOT / "decoded"
    output_file = PROJECT_ROOT / "sample_index.csv"

    if not normalized_dir.exists():
        print(f"[ERROR] Normalized directory does not exist: {normalized_dir}")
        return

    # Scan normalized directory to find all apps in the pipeline
    app_dirs = sorted([p for p in normalized_dir.iterdir() if p.is_dir()])

    total_processed = len(app_dirs)
    total_indexed = 0
    total_skipped = 0

    rows = []

    for app_dir in app_dirs:
        package_name = app_dir.name

        # Validation Rules:
        # 1. Decoded directory exists
        # 2. AndroidManifest.xml exists
        app_decoded_dir = decoded_dir / f"{package_name}_decoded"
        manifest_file = app_decoded_dir / "AndroidManifest.xml"

        if not app_decoded_dir.exists() or not manifest_file.exists():
            print(f"[SKIP] {package_name}")
            total_skipped += 1
            continue

        # Find main APK to get its hash
        main_apk = find_main_apk(app_dir)
        if main_apk is None:
            print(f"[SKIP] {package_name}")
            total_skipped += 1
            continue

        try:
            # Compute SHA256 of the main APK
            apk_hash = compute_sha256(main_apk)

            # Build the row dictionary according to the required schema
            row = {
                "sample_id": f"{package_name}_in",
                "package_name": package_name,
                "app_country_code": "IN",
                "source_path": str(app_decoded_dir.resolve()),
                "apk_sha256": apk_hash,
                "app_country_name": "India",
                "app_store": args.app_store,
                "collection_batch": args.batch,
                "notes": NOTES
            }

            rows.append(row)
            print(f"[OK] {package_name}")
            total_indexed += 1

        except Exception as e:
            print(f"[SKIP] {package_name} (Error: {e})")
            total_skipped += 1

    # Create the DataFrame and ensure the columns are in the exact order requested
    df = pd.DataFrame(rows, columns=[
        "sample_id",
        "package_name",
        "app_country_code",
        "source_path",
        "apk_sha256",
        "app_country_name",
        "app_store",
        "collection_batch",
        "notes"
    ])

    # Overwrite the existing sample_index.csv to guarantee consistency, with a fallback if Excel has locked it
    try:
        df.to_csv(output_file, index=False)
        print(f"[OK] Saved index to {output_file}")
    except PermissionError:
        fallback_file = PROJECT_ROOT / "sample_index_fallback.csv"
        df.to_csv(fallback_file, index=False)
        print(f"\n[WARNING] Permission denied when writing to {output_file}.")
        print("This usually means Microsoft Excel or another program is holding a lock on the file.")
        print(f"[OK] Saved index to fallback: {fallback_file}")

    print("\n========== SUMMARY ==========")
    print(f"Total apps processed : {total_processed}")
    print(f"Total apps indexed   : {total_indexed}")
    print(f"Total apps skipped   : {total_skipped}")


if __name__ == "__main__":
    main()
