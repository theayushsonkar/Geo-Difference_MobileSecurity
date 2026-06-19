from pathlib import Path
import subprocess
import time

PROJECT_ROOT = Path(__file__).resolve().parent.parent

APKTOOL_JAR = r"D:\Android\platform-tools-latest-windows\platform-tools\apktool.jar"

NORMALIZED_DIR = PROJECT_ROOT / "normalized"
DECODED_DIR = PROJECT_ROOT / "decoded"
LOGS_DIR = PROJECT_ROOT / "logs"

SUCCESS_LOG = LOGS_DIR / "decode_success.txt"
FAILED_LOG = LOGS_DIR / "decode_failed.txt"


def append_log(path, text):
    path.parent.mkdir(exist_ok=True)

    with open(path, "a", encoding="utf-8") as f:
        f.write(text + "\n")


def find_main_apk(app_dir):
    apks = list(app_dir.glob("*.apk"))

    for apk in apks:
        if apk.name.startswith("config."):
            continue

        return apk

    return None


def decode_app(app_dir):

    package_name = app_dir.name

    main_apk = find_main_apk(app_dir)

    if main_apk is None:
        print(f"[WARN] No main APK found: {package_name}")
        return False

    output_dir = DECODED_DIR / f"{package_name}_decoded"


    cmd = [
        "java",
        "-jar",
        "-Xmx1024M",
        "-Duser.language=en",
        "-Dfile.encoding=UTF8",
        "-Djdk.util.zip.disableZip64ExtraFieldValidation=true",
        "-Djdk.nio.zipfs.allowDotZipEntry=true",
        APKTOOL_JAR,
        "d",
        str(main_apk),
        "-o",
        str(output_dir),
        "-f",
    ]

    print(f"\n[DECODE] {package_name}")
    print(f"[APK] {main_apk}")

    start_time = time.time()

    try:

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="ignore",
            cwd=str(PROJECT_ROOT)
        )

        for line in process.stdout:
            print(line.rstrip())

        process.wait()

        elapsed = time.time() - start_time

        if process.returncode == 0:

            print(
                f"[OK] {package_name} "
                f"({elapsed:.1f}s)"
            )

            append_log(
                SUCCESS_LOG,
                package_name
            )

            return True

        else:

            print(
                f"[FAIL] {package_name} "
                f"(rc={process.returncode})"
            )

            append_log(
                FAILED_LOG,
                package_name
            )

            return False

    except Exception as e:

        print(f"[EXCEPTION] {package_name}")
        print(e)

        append_log(
            FAILED_LOG,
            f"{package_name} : {e}"
        )

        return False


def main():

    DECODED_DIR.mkdir(exist_ok=True)
    LOGS_DIR.mkdir(exist_ok=True)

    app_dirs = sorted(
        [
            p for p in NORMALIZED_DIR.iterdir()
            if p.is_dir()
        ]
    )

    print(f"[*] Apps found: {len(app_dirs)}")

    success_count = 0
    skipped_count = 0
    failed_count = 0

    for app_dir in app_dirs:
        package_name = app_dir.name
        output_dir = DECODED_DIR / f"{package_name}_decoded"

        if output_dir.exists():
            skipped_count += 1
            print(f"[SKIP] {package_name}")
            continue

        success = decode_app(app_dir)
        if success:
            success_count += 1
        else:
            failed_count += 1

    print("\n========== SUMMARY ==========")
    print(f"Newly Decoded             : {success_count}")
    print(f"Already Decoded (Skipped) : {skipped_count}")
    print(f"Failed                    : {failed_count}")
    print(f"Total Success             : {success_count + skipped_count} / {len(app_dirs)}")
    print("\n[+] Done")


if __name__ == "__main__":
    main()
