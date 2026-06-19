"""
collect_pcap.py
───────────────
Automated PCAP collection pipeline for Geo-Difference Mobile Security research.

This script automates the full collection cycle for each app:
  1. Read app list from sample_index.csv
  2. Install the APK (or split-APK bundle) via ADB
  3. Start PCAPdroid capture (filtered to the target package)
  4. Launch the app and run Android Monkey for simulated UI interaction
  5. Wait for the configured capture duration
  6. Force-stop the app
  7. Stop the PCAPdroid capture
  8. Pull the .pcap file from the device into data/pcap/
  9. Uninstall the app and clean up the device
 10. Write a collection log (collect_trace.json)

REQUIREMENTS
────────────
  - ADB installed and on PATH
  - Android device connected and authorized (adb devices shows it)
  - PCAPdroid installed on the device with a known API key
  - APKs placed under: apks/<package_name>/*.apk
  - sample_index.csv present in project root

USAGE
─────
  python collect_pcap.py [options]

  Options:
    --apk-dir         Path to APKs directory       (default: apks)
    --output-dir      Where to save .pcap files     (default: data/pcap)
    --sample-index    Path to sample_index.csv      (default: sample_index.csv)
    --capture-time    Seconds to record traffic     (default: 60)
    --monkey-events   Number of Monkey UI events    (default: 500)
    --api-key         PCAPdroid API key             (default: hardcoded in CONFIG)
    --country         Only process apps for this country code (optional filter)
    --skip-installed  Skip apps already captured    (default: False)
    --auto            Non-interactive mode, no y/n prompts (default: False)

PCAPDROID API KEY
─────────────────
  The script starts/stops PCAPdroid via ADB intents.
  You must set your PCAPdroid API key in the CONFIG section below,
  or pass it via --api-key. To get or set a key:
    1. Open PCAPdroid on device
    2. Go to Settings → API → Set API Key

SAMPLE_ID NAMING CONVENTION
────────────────────────────
  The output PCAP is named:
      {sample_id}.pcap
  where sample_id comes from sample_index.csv (e.g., com.bgfa_in).
  This ensures direct join-ability with all other pipeline outputs.
"""

import os
import sys
import csv
import json
import time
import uuid
import argparse
import datetime
import subprocess
import logging
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG — Edit these defaults before your first run
# ─────────────────────────────────────────────────────────────────────────────

CONFIG = {
    # PCAPdroid API key (must match what is set on the device)
    "pcapdroid_api_key": "4SLIqRtGC3xNFn6psIVe0wjT6bHTKp3p",

    # Path on the Android device where PCAPdroid saves the capture
    "device_pcap_path": "/storage/emulated/0/Download/PCAPdroid/capture.pcap",

    # PCAPdroid package and capture control activity
    "pcapdroid_package": "com.emanuelef.remote_capture",
    "pcapdroid_activity": "com.emanuelef.remote_capture/.activities.CaptureCtrl",

    # Seconds of traffic to capture per app
    "capture_time": 60,

    # Number of Android Monkey UI pseudo-random events per app
    # Monkey opens the app and fires random taps/swipes to trigger network activity
    "monkey_events": 500,

    # Monkey event throttle in ms (lower = faster taps)
    "monkey_throttle_ms": 200,
}

# ─────────────────────────────────────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout
)
logger = logging.getLogger("collect_pcap")


# ─────────────────────────────────────────────────────────────────────────────
# ADB HELPERS
# ─────────────────────────────────────────────────────────────────────────────

ADB_BIN = "adb"

def adb(*args, check=False, capture=True) -> subprocess.CompletedProcess:
    """Run an adb command and return the result."""
    cmd = [ADB_BIN] + list(args)
    logger.debug("ADB: %s", " ".join(cmd))
    result = subprocess.run(
        cmd,
        capture_output=capture,
        text=True,
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"ADB command failed: {' '.join(cmd)}\n"
            f"STDERR: {result.stderr.strip()}"
        )
    return result


def adb_shell(*args, check=False) -> str:
    """Run a shell command on the device and return stdout."""
    result = adb("shell", *args, check=check)
    return result.stdout.strip()


def check_device() -> str:
    """Confirm exactly one device is connected. Returns the device serial."""
    result = adb("devices")
    lines = [
        line.strip() for line in result.stdout.splitlines()
        if line.strip() and not line.startswith("List of")
    ]
    devices = [l.split("\t")[0] for l in lines if "\tdevice" in l]
    if not devices:
        raise RuntimeError(
            "No authorized ADB device found. "
            "Connect device, enable USB debugging, and authorize this computer."
        )
    if len(devices) > 1:
        logger.warning(
            "Multiple devices found (%s). Using first: %s",
            devices, devices[0]
        )
    logger.info("Device connected: %s", devices[0])
    return devices[0]


def get_device_abi() -> dict:
    """Returns the device ABI profile for 32/64-bit compatibility checks."""
    return {
        "primary": adb_shell("getprop", "ro.product.cpu.abi"),
        "abi32":   adb_shell("getprop", "ro.product.cpu.abilist32"),
        "abi64":   adb_shell("getprop", "ro.product.cpu.abilist64"),
    }


def is_package_installed(package_name: str) -> bool:
    """Returns True if the package is currently installed on the device."""
    out = adb_shell("pm", "list", "packages", package_name)
    return f"package:{package_name}" in out


# ─────────────────────────────────────────────────────────────────────────────
# INSTALL HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def install_apk(apk_dir: Path, package_name: str, abi_info: dict) -> bool:
    """
    Installs a split-APK directory or single APK.
    Returns True if installation succeeded.
    """
    apk_files = sorted(apk_dir.glob("*.apk"))
    if not apk_files:
        logger.error("No APK files found in: %s", apk_dir)
        return False

    # ABI compatibility guard — skip 32-bit-only apps on 64-bit-only devices
    has_arm32_config = any("armeabi_v7a" in f.name or "armeabi-v7a" in f.name for f in apk_files)
    has_arm64_config = any("arm64_v8a" in f.name or "arm64-v8a" in f.name for f in apk_files)
    if has_arm32_config and not has_arm64_config and not abi_info["abi32"]:
        logger.warning("32-bit-only app on 64-bit-only device — skipping: %s", package_name)
        return False

    if len(apk_files) == 1:
        logger.info("Installing single APK: %s", apk_files[0].name)
        result = adb("install", "-r", str(apk_files[0]))
    else:
        logger.info("Installing split APK bundle (%d files) for: %s", len(apk_files), package_name)
        result = adb("install-multiple", "-r", *[str(f) for f in apk_files])

    if result.returncode != 0:
        logger.error("Install failed:\n%s", result.stderr.strip())
        return False

    logger.info("Install succeeded: %s", package_name)
    return True


def uninstall_app(package_name: str):
    """Uninstall the app from the device."""
    result = adb("uninstall", package_name)
    if result.returncode == 0:
        logger.info("Uninstalled: %s", package_name)
    else:
        logger.warning("Uninstall failed (may already be gone): %s", package_name)


# ─────────────────────────────────────────────────────────────────────────────
# PCAPDROID HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def start_pcapdroid_capture(package_name: str, api_key: str):
    """
    Sends an ADB intent to PCAPdroid to begin capturing traffic
    filtered to the target app's package name only.
    
    PCAPdroid control intents:
        action=start  → begin capture
        action=stop   → stop capture and flush to file
        app_filter    → filter traffic to a single package
        pcap_dump_mode=pcap_file → output to file (not HTTP server)
        pcap_name     → filename to write on /sdcard/Download/PCAPdroid/
    """
    logger.info("Starting PCAPdroid capture for: %s", package_name)
    result = adb(
        "shell", "am", "start",
        "-n", CONFIG["pcapdroid_activity"],
        "-e", "action", "start",
        "-e", "api_key", api_key,
        "-e", "app_filter", package_name,
        "-e", "pcap_dump_mode", "pcap_file",
        "-e", "pcap_name", "capture.pcap"
    )
    if result.returncode != 0:
        raise RuntimeError(f"Failed to start PCAPdroid: {result.stderr}")
    # Give PCAPdroid 2 seconds to initialize and open the pcap file handle
    time.sleep(2)


def stop_pcapdroid_capture(package_name: str, api_key: str):
    """Sends an ADB intent to PCAPdroid to stop the capture and flush the file."""
    logger.info("Stopping PCAPdroid capture for: %s", package_name)
    adb(
        "shell", "am", "start",
        "-n", CONFIG["pcapdroid_activity"],
        "-e", "action", "stop",
        "-e", "api_key", api_key,
        "-e", "app_filter", package_name,
        "-e", "pcap_dump_mode", "pcap_file",
        "-e", "pcap_name", "capture.pcap"
    )
    # Give PCAPdroid 2 seconds to flush and close the file handle
    time.sleep(2)


# ─────────────────────────────────────────────────────────────────────────────
# APP LAUNCH / MONKEY HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def launch_app_with_monkey(package_name: str, events: int, throttle_ms: int):
    """
    Launches the app using Android Monkey (UI exerciser).
    
    Monkey fires random taps, swipes, and key events which trigger
    real network requests. This is what generates meaningful PCAP data.
    
    Options used:
      -p <package>             : restrict events to this app only
      -c android.intent.category.LAUNCHER : only launch via home launcher
      --ignore-crashes         : don't abort on app crash
      --ignore-timeouts        : don't abort on ANR timeouts
      --ignore-security-exceptions: skip permission dialogs
      --throttle <ms>          : pause between events (ms)
    """
    logger.info(
        "Running Monkey on %s (%d events, %dms throttle)",
        package_name, events, throttle_ms
    )
    result = adb(
        "shell", "monkey",
        "-p", package_name,
        "-c", "android.intent.category.LAUNCHER",
        "--ignore-crashes",
        "--ignore-timeouts",
        "--ignore-security-exceptions",
        "--throttle", str(throttle_ms),
        str(events),
        capture=True
    )
    if result.returncode != 0 and "No activities found" in (result.stderr or result.stdout):
        logger.warning(
            "No LAUNCHER activity found for %s — app may still generate traffic passively.",
            package_name
        )
    return result.returncode == 0


def force_stop_app(package_name: str):
    """Force-stops the app to end its network session cleanly."""
    logger.info("Force-stopping: %s", package_name)
    adb_shell("am", "force-stop", package_name)


# ─────────────────────────────────────────────────────────────────────────────
# PCAP FILE HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def pull_pcap(device_path: str, local_path: Path) -> bool:
    """
    Pull the PCAP file from the device to the local output directory.
    Returns True on success.
    
    The local filename uses sample_id (not package_name) so it joins
    directly with sample_index.csv in the analysis pipeline.
    """
    local_path.parent.mkdir(parents=True, exist_ok=True)
    logger.info("Pulling PCAP: %s -> %s", device_path, local_path)
    result = adb("pull", device_path, str(local_path))
    if result.returncode != 0:
        logger.error("Pull failed: %s", result.stderr.strip())
        return False
    size = local_path.stat().st_size if local_path.exists() else 0
    logger.info("PCAP saved: %s (%d bytes)", local_path.name, size)
    return True


def cleanup_device_pcap(device_path: str):
    """Removes the PCAP file from the device after pulling it."""
    adb_shell("rm", "-f", device_path)
    logger.info("Device PCAP deleted: %s", device_path)


# ─────────────────────────────────────────────────────────────────────────────
# SAMPLE INDEX LOADER
# ─────────────────────────────────────────────────────────────────────────────

def load_sample_index(index_path: Path) -> dict:
    """
    Loads sample_index.csv and returns a dict keyed by package_name.
    Each value contains sample_id, app_country_code, etc.
    """
    if not index_path.exists():
        logger.warning("sample_index.csv not found at: %s", index_path)
        return {}

    index = {}
    with open(index_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            pkg = row.get("package_name", "").strip()
            if pkg:
                index[pkg] = {k: v.strip() for k, v in row.items()}
    logger.info("Loaded sample index: %d entries", len(index))
    return index


# ─────────────────────────────────────────────────────────────────────────────
# INTERACTIVE PROMPT
# ─────────────────────────────────────────────────────────────────────────────

def ask_user(prompt: str) -> bool:
    """
    Asks the user y/n. Returns True if they say yes.
    Used to skip individual apps during interactive mode.
    """
    while True:
        try:
            resp = input(f"{prompt} [y/n]: ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.")
            sys.exit(0)
        if resp == "y":
            return True
        if resp == "n":
            return False
        print("  Please enter y or n.")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN COLLECTION LOOP
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Automated PCAP collection via ADB + PCAPdroid + Monkey"
    )
    parser.add_argument("--apk-dir",       default="apks",            help="Directory containing APK subdirectories")
    parser.add_argument("--output-dir",    default="data/pcap",       help="Directory to save pulled PCAP files")
    parser.add_argument("--sample-index",  default="sample_index.csv",help="Path to sample_index.csv")
    parser.add_argument("--capture-time",  type=int, default=CONFIG["capture_time"],      help="Seconds to capture traffic per app")
    parser.add_argument("--monkey-events", type=int, default=CONFIG["monkey_events"],     help="Number of Monkey UI events per app")
    parser.add_argument("--api-key",       default=CONFIG["pcapdroid_api_key"],           help="PCAPdroid API key")
    parser.add_argument("--country",       default=None,              help="Only process apps matching this country code")
    parser.add_argument("--skip-captured", action="store_true",       help="Skip apps whose PCAP already exists in output-dir")
    parser.add_argument("--adb-path",      default="adb",             help="Path to adb executable")
    parser.add_argument("--auto",          action="store_true",       help="Non-interactive mode (no y/n prompts per app)")
    args = parser.parse_args()

    # Configure ADB binary location
    global ADB_BIN
    ADB_BIN = args.adb_path
    if ADB_BIN == "adb":
        # Fallback check for user's specific path if default "adb" is not on PATH
        import shutil
        if not shutil.which("adb"):
            fallback = Path("D:/Android/platform-tools-latest-windows/platform-tools/adb.exe")
            if fallback.exists():
                ADB_BIN = str(fallback)
                logger.info("Auto-detected adb at: %s", ADB_BIN)

    apk_dir    = Path(args.apk_dir)
    output_dir = Path(args.output_dir)
    index_path = Path(args.sample_index)
    api_key    = args.api_key
    capture_time  = args.capture_time
    monkey_events = args.monkey_events

    output_dir.mkdir(parents=True, exist_ok=True)

    # ── Pre-flight: check ADB connection ──────────────────────────────────────
    print("=" * 60)
    print("  PCAP COLLECTION PIPELINE")
    print("=" * 60)

    try:
        device_serial = check_device()
        abi_info = get_device_abi()
    except RuntimeError as e:
        logger.error("%s", e)
        sys.exit(1)

    logger.info("Device ABI: primary=%s, abi32=%s, abi64=%s",
                abi_info["primary"], abi_info["abi32"], abi_info["abi64"])

    # ── Load sample index ─────────────────────────────────────────────────────
    sample_index = load_sample_index(index_path)

    # ── Discover APK directories ──────────────────────────────────────────────
    apk_dirs = sorted([d for d in apk_dir.iterdir() if d.is_dir()])
    total = len(apk_dirs)

    if total == 0:
        logger.error("No APK directories found in: %s", apk_dir)
        sys.exit(1)

    logger.info("Found %d APK packages to process", total)

    # ── Run trace ─────────────────────────────────────────────────────────────
    run_id        = str(uuid.uuid4())
    run_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    start_time    = time.time()
    trace_entries = []
    processed     = 0
    skipped       = 0
    failed        = 0

    for idx, pkg_dir in enumerate(apk_dirs, 1):
        package_name = pkg_dir.name
        meta = sample_index.get(package_name, {})
        sample_id        = meta.get("sample_id", f"{package_name}_unknown")
        app_country_code = meta.get("app_country_code", "")
        local_pcap       = output_dir / f"{sample_id}.pcap"

        # ── Country filter ────────────────────────────────────────────────────
        if args.country and app_country_code.upper() != args.country.upper():
            logger.info("[%d/%d] Skipping (country filter): %s", idx, total, package_name)
            skipped += 1
            continue

        # ── Skip if already captured ──────────────────────────────────────────
        if args.skip_captured and local_pcap.exists():
            logger.info("[%d/%d] Already captured, skipping: %s", idx, total, package_name)
            skipped += 1
            continue

        print(f"\n{'-'*60}")
        print(f"  [{idx}/{total}]  {package_name}")
        print(f"  sample_id        : {sample_id}")
        print(f"  app_country_code : {app_country_code}")
        print(f"  output           : {local_pcap.name}")
        print(f"{'-'*60}")

        # ── Interactive confirmation ───────────────────────────────────────────
        if not args.auto:
            if not ask_user(f"  Capture {package_name}?"):
                logger.info("Skipped by user: %s", package_name)
                skipped += 1
                continue

        entry = {
            "sample_id":    sample_id,
            "package_name": package_name,
            "status":       None,
            "error":        None,
            "pcap_path":    str(local_pcap),
            "pcap_bytes":   0,
            "timestamp":    datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }

        installed = False
        try:
            # ── 1. Install ────────────────────────────────────────────────────
            logger.info("[%d/%d] Installing: %s", idx, total, package_name)
            if not install_apk(pkg_dir, package_name, abi_info):
                entry["status"] = "install_failed"
                entry["error"] = "install_apk() returned False"
                failed += 1
                trace_entries.append(entry)
                continue

            if not is_package_installed(package_name):
                raise RuntimeError("Package not present on device after install")

            installed = True

            # ── 2. Start Capture ──────────────────────────────────────────────
            start_pcapdroid_capture(package_name, api_key)

            # ── 3. Launch app + Monkey ────────────────────────────────────────
            launch_app_with_monkey(package_name, monkey_events, CONFIG["monkey_throttle_ms"])

            # ── 4. Wait ───────────────────────────────────────────────────────
            logger.info("Capturing for %d seconds...", capture_time)
            time.sleep(capture_time)

            # ── 5. Stop app ───────────────────────────────────────────────────
            force_stop_app(package_name)

            # ── 6. Stop Capture ───────────────────────────────────────────────
            stop_pcapdroid_capture(package_name, api_key)

            # ── 7. Pull PCAP ──────────────────────────────────────────────────
            pull_ok = pull_pcap(CONFIG["device_pcap_path"], local_pcap)
            if not pull_ok:
                raise RuntimeError("PCAP pull failed — file may not exist on device")

            entry["status"]     = "success"
            entry["pcap_bytes"] = local_pcap.stat().st_size
            processed += 1
            logger.info("[SUCCESS] Done: %s -> %s", package_name, local_pcap.name)

        except Exception as e:
            logger.error("[ERROR] Error processing %s: %s", package_name, e)
            entry["status"] = "failed"
            entry["error"]  = str(e)
            failed += 1

        finally:
            # ── 8. Cleanup device ─────────────────────────────────────────────
            try:
                cleanup_device_pcap(CONFIG["device_pcap_path"])
            except Exception:
                pass
            if installed:
                uninstall_app(package_name)

        trace_entries.append(entry)

    # ── Write collection trace ─────────────────────────────────────────────────
    elapsed = time.time() - start_time
    trace = {
        "run_id":            run_id,
        "run_timestamp":     run_timestamp,
        "device_serial":     device_serial,
        "device_abi":        abi_info,
        "capture_time_sec":  capture_time,
        "monkey_events":     monkey_events,
        "total_apps":        total,
        "processed":         processed,
        "skipped":           skipped,
        "failed":            failed,
        "elapsed_sec":       round(elapsed, 2),
        "entries":           trace_entries,
    }

    trace_path = output_dir / "collect_trace.json"
    with open(trace_path, "w", encoding="utf-8") as f:
        json.dump(trace, f, indent=2)

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"  COLLECTION COMPLETE")
    print(f"  Processed : {processed}")
    print(f"  Skipped   : {skipped}")
    print(f"  Failed    : {failed}")
    print(f"  Time      : {elapsed:.1f}s")
    print(f"  Trace log : {trace_path}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
