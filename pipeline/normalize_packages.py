import zipfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

APKS_DIR = PROJECT_ROOT / "apks"
NORMALIZED_DIR = PROJECT_ROOT / "normalized"


def extract_xapk(xapk_path, output_dir):

    output_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    with zipfile.ZipFile(xapk_path, "r") as z:
        z.extractall(output_dir)


def process_package(package_dir):

    package_name = package_dir.name

    output_dir = NORMALIZED_DIR / package_name

    if output_dir.exists():
        print(f"[SKIP] {package_name}")
        return

    apk_files = list(package_dir.glob("*.apk"))

    if apk_files:

        output_dir.mkdir(
            parents=True,
            exist_ok=True
        )

        for apk in apk_files:
            target = output_dir / apk.name
            target.write_bytes(
                apk.read_bytes()
            )

        print(f"[APK ] {package_name}")
        return

    xapk_files = list(package_dir.glob("*.xapk"))

    if xapk_files:

        xapk = xapk_files[0]

        print(f"[XAPK] {package_name}")

        extract_xapk(
            xapk,
            output_dir
        )

        return

    print(f"[WARN] No APK/XAPK found: {package_name}")


def main():

    NORMALIZED_DIR.mkdir(
        exist_ok=True
    )

    package_dirs = [
        p for p in APKS_DIR.iterdir()
        if p.is_dir()
    ]

    print(
        f"[*] Packages: {len(package_dirs)}"
    )

    for package_dir in package_dirs:
        process_package(package_dir)


if __name__ == "__main__":
    main()
