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
    for attempt in range(3):
        out = adb_shell("pm", "list", "packages", package_name)
        if f"package:{package_name}" in out:
            return True
        time.sleep(1)
    return False


# ─────────────────────────────────────────────────────────────────────────────
# INSTALL HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def install_apk(apk_dir: Path, package_name: str, abi_info: dict) -> bool:
    """
    Installs a split-APK directory or single APK.
    Filters out incompatible and conflicting ABI splits.
    Returns True if installation succeeded.
    """
    raw_apk_files = sorted(apk_dir.glob("*.apk"))
    if not raw_apk_files:
        logger.error("No APK files found in: %s", apk_dir)
        return False

    # Build preference list of device-supported ABIs
    supported_abis = []
    if abi_info.get("primary"):
        supported_abis.append(abi_info["primary"])
    if abi_info.get("abi64"):
        supported_abis.extend([x.strip() for x in abi_info["abi64"].split(",") if x.strip()])
    if abi_info.get("abi32"):
        supported_abis.extend([x.strip() for x in abi_info["abi32"].split(",") if x.strip()])
    # De-duplicate while preserving order
    seen = set()
    supported_abis = [x for x in supported_abis if not (x in seen or seen.add(x))]

    # Patterns to match known architectures
    abi_patterns = {
        "arm64-v8a": ["arm64_v8a", "arm64-v8a", "arm64", "v8a"],
        "armeabi-v7a": ["armeabi_v7a", "armeabi-v7a", "armeabi", "v7a"],
        "x86_64": ["x86_64"],
        "x86": ["x86"]
    }

    base_and_other_apks = []
    abi_splits = []

    for f in raw_apk_files:
        matched_abi = None
        fname_lower = f.name.lower()
        for abi, patterns in abi_patterns.items():
            if any(p in fname_lower for p in patterns):
                matched_abi = abi
                break
        if matched_abi:
            abi_splits.append((f, matched_abi))
        else:
            base_and_other_apks.append(f)

    apk_files = []
    if abi_splits:
        # Group files by their matched ABI
        grouped = {}
        for f, abi in abi_splits:
            grouped.setdefault(abi, []).append(f)

        # Select the best ABI split that matches device capabilities
        best_abi = None
        for abi in supported_abis:
            if abi in grouped:
                best_abi = abi
                break

        if best_abi:
            logger.info("Device supports: %s. Selected ABI split: %s", supported_abis, best_abi)
            apk_files.extend(grouped[best_abi])
            # Log skipped ABI splits
            for abi, files in grouped.items():
                if abi != best_abi:
                    logger.info("Skipping redundant/incompatible ABI split (%s): %s", abi, [f.name for f in files])
        else:
            logger.warning("No supported ABI split found. Device: %s, Available in package: %s", supported_abis, list(grouped.keys()))
    
    apk_files.extend(base_and_other_apks)

    if not apk_files:
        logger.error("No compatible APK files to install for %s", package_name)
        return False

    if len(apk_files) == 1:
        logger.info("Installing single APK with Play Store installer spoofing: %s", apk_files[0].name)
        result = adb("install", "-i", "com.android.vending", "-r", str(apk_files[0]))
    else:
        logger.info("Installing split APK bundle (%d files) with Play Store installer spoofing for: %s", len(apk_files), package_name)
        result = adb("install-multiple", "-i", "com.android.vending", "-r", *[str(f) for f in apk_files])

    if result.returncode != 0:
        logger.error("Install with spoofing failed:\n%s", result.stderr.strip())
        logger.info("Retrying installation without spoofing...")
        if len(apk_files) == 1:
            result = adb("install", "-r", str(apk_files[0]))
        else:
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


def clear_device_pcap_folder():
    """Removes all .pcap files from the device's PCAPdroid folder before starting a new run."""
    adb_shell("rm", "-f", "/storage/emulated/0/Download/PCAPdroid/*.pcap")
    logger.info("Cleared any existing PCAPs from device PCAPdroid folder.")


def find_latest_device_pcap() -> str:
    """
    Finds the absolute path of the most recently modified .pcap file
    in /storage/emulated/0/Download/PCAPdroid/
    """
    out = adb_shell("ls", "-t", "/storage/emulated/0/Download/PCAPdroid/")
    if not out or "No such file" in out:
        return ""
    pcaps = [line.strip() for line in out.splitlines() if line.strip().endswith(".pcap")]
    if not pcaps:
        return ""
    return f"/storage/emulated/0/Download/PCAPdroid/{pcaps[0]}"


def init_pcapdroid(api_key: str):
    """Ensure PCAPdroid is clean and stopped before starting a capture."""
    logger.info("Initializing PCAPdroid state...")
    adb(
        "shell", "am", "start",
        "-n", CONFIG["pcapdroid_activity"],
        "-e", "action", "stop",
        "-e", "api_key", api_key
    )
    time.sleep(1)
    adb_shell("am", "force-stop", CONFIG["pcapdroid_package"])
    time.sleep(1)


def ensure_device_unlocked():
    """
    Checks if the device screen is asleep, wakes it up, and unlocks it using keyevent 82 (Menu)
    and/or swipe gestures if the keyguard is showing.
    """
    try:
        # 1. Check wakefulness / screen state
        result = adb("shell", "dumpsys", "power", capture=True)
        if result.returncode == 0:
            stdout = result.stdout or ""
            if "mWakefulness=Asleep" in stdout or "mWakefulness=Dozing" in stdout or "Display Power: state=OFF" in stdout:
                logger.info("Device screen is asleep. Waking up...")
                # Send KEYCODE_WAKE
                adb("shell", "input", "keyevent", "224")
                time.sleep(1.0)

        # 2. Check keyguard (lockscreen) state
        result_window = adb("shell", "dumpsys", "window", capture=True)
        if result_window.returncode == 0:
            stdout_window = result_window.stdout or ""
            if "mKeyguardShowing=true" in stdout_window or "isKeyguardLocked=true" in stdout_window or "mShowingLockscreen=true" in stdout_window:
                logger.info("Keyguard (lockscreen) is showing. Attempting unlock...")
                # Send keyevent 82 (KEYCODE_MENU) to dismiss lockscreen on some devices
                adb("shell", "input", "keyevent", "82")
                time.sleep(0.5)
                # Swipe up as standard fallback to dismiss lockscreen
                adb("shell", "input", "swipe", "500", "1500", "500", "500", "300")
                time.sleep(1.5)
    except Exception as e:
        logger.warning("Failed to check lock state or unlock device: %s", e)


def launch_app(package_name: str):
    """
    Launches the app via its LAUNCHER activity using a single Monkey event.
    Waits 3 seconds for the app to initialize before returning.
    """
    logger.info("Launching app: %s", package_name)
    result = adb(
        "shell", "monkey",
        "-p", package_name,
        "-c", "android.intent.category.LAUNCHER",
        "1",
        capture=True
    )
    if result.returncode != 0 and "No activities found" in (result.stderr or result.stdout or ""):
        logger.warning(
            "No LAUNCHER activity found for %s — app may still generate traffic passively.",
            package_name
        )
    time.sleep(3)  # Let the app initialize


def start_monkey_background(package_name: str, events: int, throttle_ms: int):
    """
    Starts Monkey UI exerciser as a NON-BLOCKING background subprocess.
    Returns the subprocess.Popen handle so the caller can kill it later.

    Key confinement flags:
      --pct-syskeys 0    : prevents HOME / BACK / VOLUME keys → Monkey stays
                           inside the app and can never navigate to PCAPdroid
      --pct-appswitch 0  : prevents Activity-switch intents
      (no --ignore-crashes): if the target app crashes, Monkey stops immediately
                           instead of continuing on whatever app is behind it
    """
    logger.info(
        "Starting background Monkey on %s (%d events, %dms throttle)",
        package_name, events, throttle_ms
    )
    proc = subprocess.Popen(
        [ADB_BIN, "shell", "monkey",
         "-p", package_name,
         "-c", "android.intent.category.LAUNCHER",
         "--pct-syskeys", "0",
         "--pct-appswitch", "0",
         "--ignore-timeouts",
         "--ignore-security-exceptions",
         "--throttle", str(throttle_ms),
         str(events)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    return proc


def stop_monkey(proc):
    """
    Stops a background Monkey subprocess (both the local adb process
    and the monkey process running on the device).
    """
    # 1. Terminate the local adb process that is driving monkey
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass

    # 2. Kill any lingering monkey process on the device itself
    try:
        adb("shell", "pkill -9 -f com.android.commands.monkey 2>/dev/null || true")
    except Exception:
        pass


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
    parser.add_argument("--apk-dir",       default="normalized",      help="Directory containing APK subdirectories")
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
        # Keep screen awake and unlock
        logger.info("Setting device to stay awake while connected to USB...")
        adb("shell", "svc", "power", "stayon", "true")
        ensure_device_unlocked()
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
        monkey_proc = None
        try:
            # ── 1. Install ────────────────────────────────────────────────────
            if is_package_installed(package_name):
                logger.info("[%d/%d] App %s is already installed on the device. Skipping installation to preserve Google Play Store license.", idx, total, package_name)
                installed = False
            else:
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

            # Ensure device is awake and unlocked
            ensure_device_unlocked()

            # Clean and stop any active PCAPdroid processes/captures
            init_pcapdroid(api_key)

            # Pre-clear the PCAP folder to ensure the current run creates the only file
            clear_device_pcap_folder()

            # ── 2. Start Capture ──────────────────────────────────────────────
            start_pcapdroid_capture(package_name, api_key)

            # ── 3. Launch app ─────────────────────────────────────────────────
            launch_app(package_name)

            # ── 4. Start Monkey in background (non-blocking) ─────────────────
            monkey_proc = start_monkey_background(
                package_name, monkey_events, CONFIG["monkey_throttle_ms"]
            )

            # ── 5. Wait for capture duration ─────────────────────────────────
            logger.info("Capturing for %d seconds...", capture_time)
            time.sleep(capture_time)

            # ── 6. Stop Monkey + Stop app ─────────────────────────────────────
            stop_monkey(monkey_proc)
            monkey_proc = None
            force_stop_app(package_name)

            # ── 7. Stop Capture ───────────────────────────────────────────────
            stop_pcapdroid_capture(package_name, api_key)

            # ── 8. Pull PCAP ──────────────────────────────────────────────────
            detected_pcap_path = find_latest_device_pcap()
            if not detected_pcap_path:
                logger.warning("No timestamped PCAP found. Falling back to default path.")
                detected_pcap_path = CONFIG["device_pcap_path"]

            pull_ok = pull_pcap(detected_pcap_path, local_pcap)
            if not pull_ok:
                raise RuntimeError(f"PCAP pull failed for path: {detected_pcap_path}")

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
            # ── 9. Kill Monkey if still running ──────────────────────────────
            if monkey_proc is not None:
                stop_monkey(monkey_proc)
            # ── 10. Cleanup device ────────────────────────────────────────────
            try:
                target_cleanup = find_latest_device_pcap()
                if target_cleanup:
                    cleanup_device_pcap(target_cleanup)
                else:
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
