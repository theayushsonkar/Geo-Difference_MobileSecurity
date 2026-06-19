import argparse
import os
import subprocess
from pathlib import Path

# Get project root (parent of the pipeline folder)
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# ------------------------------------------------------------------
# CONFIG
# ------------------------------------------------------------------

APKEEP_EXE = r"D:\Android\platform-tools-latest-windows\platform-tools\apkeep.exe"

APKS_DIR = PROJECT_ROOT / "apks"
LOGS_DIR = PROJECT_ROOT / "logs"

SUCCESS_FILE = LOGS_DIR / "download_success.txt"
FAILED_FILE = LOGS_DIR / "download_failed.txt"
LOG_FILE = LOGS_DIR / "download.log"


# ------------------------------------------------------------------
# HELPERS
# ------------------------------------------------------------------

def load_package_list(path: Path):
    packages = []

    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            packages.append(line)

    return packages


def append_line(path: Path, text: str):
    with open(path, "a", encoding="utf-8") as f:
        f.write(text + "\n")


def already_downloaded(package_name: str):
    pkg_dir = APKS_DIR / package_name

    if not pkg_dir.exists():
        return False

    apk_files = list(pkg_dir.glob("*.apk"))
    xapk_files = list(pkg_dir.glob("*.xapk"))

    return len(apk_files) > 0 or len(xapk_files) > 0


# ------------------------------------------------------------------
# DOWNLOAD
# ------------------------------------------------------------------

def download_package(
    package_name: str,
    source: str = "apk-pure",
    ini_path: str = None,
    email: str = None,
    token: str = None,
):

    pkg_dir = APKS_DIR / package_name
    pkg_dir.mkdir(parents=True, exist_ok=True)

    use_wsl = (source == "google-play" and os.name == "nt")

    if use_wsl:
        apkeep_path = "./.wsl_bin/apkeep"
        cmd = [
            "wsl",
            apkeep_path,
            "-a",
            package_name,
            "-d",
            source,
        ]
        
        # Convert output directory to WSL path
        p = pkg_dir.resolve()
        if p.drive:
            drive_letter = p.drive[0].lower()
            pkg_dir_str = f"/mnt/{drive_letter}/" + "/".join(p.parts[1:])
        else:
            pkg_dir_str = p.as_posix()
    else:
        cmd = [
            APKEEP_EXE,
            "-a",
            package_name,
            "-d",
            source,
        ]
        pkg_dir_str = str(pkg_dir)

    if source == "google-play":
        cmd.append("--accept-tos")
        # Run with split_apk=true and parallel=1 to ensure reliable downloads
        cmd.extend(["-o", "split_apk=true", "-r", "1"])
        if email:
            cmd.extend(["-e", email])
        if token:
            cmd.extend(["-t", token])

    if ini_path:
        if use_wsl:
            p = Path(ini_path).resolve()
            if p.drive:
                drive_letter = p.drive[0].lower()
                wsl_ini_path = f"/mnt/{drive_letter}/" + "/".join(p.parts[1:])
            else:
                wsl_ini_path = p.as_posix()
        else:
            wsl_ini_path = ini_path
        cmd.extend(["-i", wsl_ini_path])

    cmd.append(pkg_dir_str)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=str(PROJECT_ROOT)
        )

        return result

    except FileNotFoundError:
        executable = "wsl" if use_wsl else APKEEP_EXE
        print(f"[ERROR] Could not find executable: {executable}")
        return None


# ------------------------------------------------------------------
# MAIN
# ------------------------------------------------------------------

def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--packages",
        required=True,
        help="Path to package list",
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Download only first N apps",
    )

    parser.add_argument(
        "--source",
        choices=["apk-pure", "google-play"],
        default="apk-pure",
        help="Where to download the APKs from",
    )

    parser.add_argument(
        "--ini",
        type=str,
        default=None,
        help="Path to an ini file which contains Google Play configuration/credentials data",
    )

    parser.add_argument(
        "--email",
        type=str,
        default=None,
        help="Google account email address (for google-play)",
    )

    parser.add_argument(
        "--token",
        type=str,
        default=None,
        help="Google Play AAS token",
    )

    args = parser.parse_args()

    APKS_DIR.mkdir(exist_ok=True)
    LOGS_DIR.mkdir(exist_ok=True)

    # Resolve packages list path relative to PROJECT_ROOT if relative
    packages_path = Path(args.packages)
    if not packages_path.is_absolute():
        packages_path = PROJECT_ROOT / packages_path

    packages = load_package_list(packages_path)

    if args.limit:
        packages = packages[:args.limit]

    print(f"[*] Packages to process: {len(packages)}")

    success_count = 0
    fail_count = 0

    for i, package_name in enumerate(packages, start=1):

        print()
        print(f"[{i}/{len(packages)}] {package_name}")

        if already_downloaded(package_name):

            print("    already downloaded")

            append_line(
                SUCCESS_FILE,
                package_name
            )

            continue

        result = download_package(
            package_name,
            source=args.source,
            ini_path=args.ini,
            email=args.email,
            token=args.token,
        )

        if result is None:
            fail_count += 1
            continue

        append_line(
            LOG_FILE,
            f"{package_name} | rc={result.returncode}"
        )

        if result.returncode == 0:
            # Flatten nested subdirectory if created by apkeep
            pkg_dir = APKS_DIR / package_name
            nested_dir = pkg_dir / package_name
            if nested_dir.is_dir():
                for f in nested_dir.iterdir():
                    if f.is_file():
                        try:
                            target = pkg_dir / f.name
                            if target.exists():
                                target.unlink()
                            f.rename(target)
                        except Exception as e:
                            print(f"    [WARN] Failed to move {f.name} up: {e}")
                try:
                    nested_dir.rmdir()
                except Exception as e:
                    pass

            print("    success")

            append_line(
                SUCCESS_FILE,
                package_name
            )

            success_count += 1

        else:

            print("    failed")
            print(f"    returncode: {result.returncode}")

            if result.stdout:
                print("\n----- STDOUT -----")
                print(result.stdout[:3000])

            if result.stderr:
                print("\n----- STDERR -----")
                print(result.stderr[:3000])

            append_line(
                FAILED_FILE,
                package_name
            )

            fail_count += 1

    print()
    print("========== SUMMARY ==========")
    print(f"Success : {success_count}")
    print(f"Failed  : {fail_count}")


if __name__ == "__main__":
    main()
