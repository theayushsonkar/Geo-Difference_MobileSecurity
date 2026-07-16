"""
run_full_pipeline.py
════════════════════
Overnight, fully-automated orchestrator for the Geo-Difference Mobile Security
research pipeline.

Runs every stage sequentially:
  1. Scrape top apps metadata        (scrapper.py)
  2. Prepare India package list      (pipeline/prepare_india_package_list.py)
  3. Download APKs                   (pipeline/download_apks.py)
  4. Normalize packages              (pipeline/normalize_packages.py)
  5. Decode / decompile APKs         (pipeline/decode_apks.py)
  6. Build sample index              (pipeline/build_sample_index.py)
  7. Scan manifests                  (scan_manifest.py)
  8. Run CVE analysis                (cve/main.py)
  9. Capture live PCAP traffic       (collect_pcap.py)  [requires phone connected]
 10. Parse PCAP traffic              (run_pcap_analysis.py)
 11. Cleanup: delete decoded/, normalized/, apks/ to free D: drive space
 12. Cleanup: empty Windows Recycle Bin

USAGE
─────
  python run_full_pipeline.py [options]

  Options:
    --skip-scrape       Skip step 1 (scraping) if top_apps_full.csv already exists
    --skip-download     Skip step 3 (downloading) if APKs are already present
    --skip-pcap         Skip steps 9-10 (PCAP capture + analysis) if no phone connected
    --skip-cleanup      Skip steps 11-12 (do not delete intermediate files)
    --capture-time      Seconds to capture traffic per app (default: 60)
    --monkey-events     Number of Monkey UI events per app (default: 500)
    --download-source   APK download source: apk-pure or google-play (default: apk-pure)

NOTES
─────
  - Designed to run unattended overnight. All errors are caught and logged
    so the pipeline continues to the next stage even if one stage fails.
  - Phone must be connected, unlocked, and USB-debugging authorized BEFORE
    starting this script.
  - The cleanup stage permanently deletes decoded/, normalized/, and apks/
    directories and empties the Windows Recycle Bin to reclaim disk space.
    Output files (output/) are NEVER touched.
"""

import os
import sys

# Reconfigure stdout/stderr to avoid UnicodeEncodeError on Windows console
if sys.version_info >= (3, 7):
    try:
        sys.stdout.reconfigure(errors="replace")
        sys.stderr.reconfigure(errors="replace")
    except Exception:
        pass

import time
import shutil
import logging
import argparse
import datetime
import subprocess
import ctypes
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# SETUP
# ─────────────────────────────────────────────────────────────────────────────

PROJECT_ROOT = Path(__file__).resolve().parent
PYTHON = sys.executable  # Use the same Python interpreter running this script

LOG_DIR = PROJECT_ROOT / "logs"
LOG_DIR.mkdir(exist_ok=True)

# Timestamp for this run
RUN_TIMESTAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = LOG_DIR / f"full_pipeline_{RUN_TIMESTAMP}.log"

# Setup dual logging: console + file
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
    ]
)
logger = logging.getLogger("full_pipeline")


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def run_step(step_num: int, description: str, cmd: list[str], critical: bool = True) -> bool:
    """
    Runs a pipeline step as a subprocess.
    Returns True on success, False on failure.
    If critical=True and the step fails, logs an error but continues.
    """
    separator = "=" * 70
    logger.info("")
    logger.info(separator)
    logger.info("  STEP %d: %s", step_num, description)
    logger.info(separator)
    logger.info("  Command: %s", " ".join(cmd))
    logger.info("")

    start = time.time()

    try:
        process = subprocess.Popen(
            cmd,
            cwd=str(PROJECT_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace"
        )
        
        # Stream output line-by-line in real-time to both console and file
        for line in process.stdout:
            logger.info("  %s", line.rstrip())
            
        process.wait()
        elapsed = time.time() - start

        if process.returncode == 0:
            logger.info("")
            logger.info("  [OK] STEP %d PASSED (%s) — %.1fs", step_num, description, elapsed)
            return True
        else:
            logger.error("")
            logger.error("  [FAIL] STEP %d FAILED (rc=%d) (%s) — %.1fs",
                         step_num, process.returncode, description, elapsed)
            return False

    except Exception as e:
        elapsed = time.time() - start
        logger.error("  ✗ STEP %d EXCEPTION: %s — %.1fs", step_num, e, elapsed)
        return False


def delete_directory(dir_path: Path, description: str):
    """Permanently deletes a directory and all its contents."""
    if not dir_path.exists():
        logger.info("  [SKIP] %s does not exist: %s", description, dir_path)
        return

    try:
        total_size = sum(f.stat().st_size for f in dir_path.rglob("*") if f.is_file())
        size_mb = total_size / (1024 * 1024)
        logger.info("  [DELETE] %s: %s (%.1f MB)", description, dir_path, size_mb)
        shutil.rmtree(dir_path)
        logger.info("  [OK] Deleted: %s", dir_path)
    except Exception as e:
        logger.error("  [ERROR] Failed to delete %s: %s", dir_path, e)


def empty_recycle_bin():
    """Empties ONLY the D: drive Recycle Bin using the Shell API."""
    logger.info("  [RECYCLE BIN] Emptying Recycle Bin for D: drive only...")
    try:
        # SHEmptyRecycleBin flags:
        #   0x01 = SHERB_NOCONFIRMATION  (no confirmation dialog)
        #   0x02 = SHERB_NOPROGRESSUI    (no progress dialog)
        #   0x04 = SHERB_NOSOUND         (no sound)
        flags = 0x01 | 0x02 | 0x04
        # Pass "D:\\" as pszRootPath to restrict to D: drive only
        ctypes.windll.shell32.SHEmptyRecycleBinW(None, "D:\\", flags)
        logger.info("  [OK] D: drive Recycle Bin emptied.")
    except Exception as e:
        logger.warning("  [WARN] Could not empty D: drive Recycle Bin: %s", e)


def format_duration(seconds: float) -> str:
    """Formats seconds into a human-readable string."""
    hours = int(seconds // 3600)
    minutes = int((seconds % 3600) // 60)
    secs = int(seconds % 60)
    if hours > 0:
        return f"{hours}h {minutes}m {secs}s"
    elif minutes > 0:
        return f"{minutes}m {secs}s"
    else:
        return f"{secs}s"


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Overnight full pipeline orchestrator for Geo-Difference Mobile Security"
    )
    parser.add_argument("--skip-scrape",     action="store_true", help="Skip scraping if top_apps_full.csv exists")
    parser.add_argument("--skip-download",   action="store_true", help="Skip APK downloading if apks/ is populated")
    parser.add_argument("--skip-static",     action="store_true", help="Skip static manifest and CVE analysis")
    parser.add_argument("--skip-pcap",       action="store_true", help="Skip PCAP capture + analysis stages")
    parser.add_argument("--skip-cleanup",    action="store_true", help="Do not delete intermediate files")
    parser.add_argument("--capture-time",    type=int, default=60,  help="Seconds of traffic to capture per app")
    parser.add_argument("--monkey-events",   type=int, default=500, help="Monkey UI events per app")
    parser.add_argument("--download-source", default="apk-pure", choices=["apk-pure", "google-play"],
                        help="APK download source")
    args = parser.parse_args()

    pipeline_start = time.time()
    results = {}  # step_num -> (description, passed)

    logger.info("")
    logger.info("+------------------------------------------------------------------+")
    logger.info("|     GEO-DIFFERENCE MOBILE SECURITY - FULL PIPELINE RUN           |")
    logger.info("|     Started: %s                              |", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    logger.info("|     Log: %s  |", LOG_FILE.name.ljust(40))
    logger.info("+------------------------------------------------------------------+")
    logger.info("")

    # -- STEP 1: Scrape top apps ----------------------------------------------
    if args.skip_scrape and (PROJECT_ROOT / "output" / "top_apps_full.csv").exists():
        logger.info("  [SKIP] Step 1: Scraping - top_apps_full.csv already exists")
        results[1] = ("Scrape top apps", True)
    else:
        ok = run_step(1, "Scrape top apps metadata", [PYTHON, "-u", "scrapper.py"])
        results[1] = ("Scrape top apps", ok)
        if not ok:
            logger.error("Scraping failed — cannot continue without app list.")
            _print_summary(results, pipeline_start)
            return

    # ── STEP 2: Prepare India package list ────────────────────────────────────
    ok = run_step(2, "Prepare India package list",
                  [PYTHON, "-u", "pipeline/prepare_india_package_list.py"])
    results[2] = ("Prepare package list", ok)
    if not ok:
        logger.error("Package list preparation failed — cannot continue.")
        _print_summary(results, pipeline_start)
        return

    # ── STEP 3: Download APKs ────────────────────────────────────────────────
    pkg_list = str(PROJECT_ROOT / "data" / "package_lists" / "india_packages.txt")
    if args.skip_download:
        logger.info("  [SKIP] Step 3: Download — --skip-download flag set")
        results[3] = ("Download APKs", True)
    else:
        ok = run_step(3, "Download APK binaries",
                      [PYTHON, "-u", "pipeline/download_apks.py",
                       "--packages", pkg_list,
                       "--source", args.download_source])
        results[3] = ("Download APKs", ok)
        if not ok:
            logger.warning("Some APK downloads may have failed — continuing with available APKs.")

    # ── STEP 4: Normalize packages ───────────────────────────────────────────
    ok = run_step(4, "Normalize package layouts",
                  [PYTHON, "-u", "pipeline/normalize_packages.py"])
    results[4] = ("Normalize packages", ok)

    # ── STEP 5: Decode APKs ──────────────────────────────────────────────────
    ok = run_step(5, "Decode / decompile APKs (apktool)",
                  [PYTHON, "-u", "pipeline/decode_apks.py"])
    results[5] = ("Decode APKs", ok)
    if not ok:
        logger.warning("Some APK decodes may have failed — continuing with available decoded apps.")

    # ── STEP 6: Build sample index ───────────────────────────────────────────
    ok = run_step(6, "Build sample index (sample_index.csv)",
                  [PYTHON, "-u", "pipeline/build_sample_index.py",
                   "--app-store", args.download_source])
    results[6] = ("Build sample index", ok)
    if not ok:
        logger.error("Sample index build failed — static analysis cannot proceed without it.")
        _print_summary(results, pipeline_start)
        return

    # -- STEP 7: Scan manifests -----------------------------------------------
    if args.skip_static:
        logger.info("  [SKIP] Step 7: Static manifest analysis — --skip-static flag set")
        results[7] = ("Scan manifests", True)
    else:
        ok = run_step(7, "Static manifest analysis",
                      [PYTHON, "-u", "scan_manifest.py",
                       "-i", "sample_index.csv",
                       "-o", "output",
                       "-v"])
        results[7] = ("Scan manifests", ok)

    # -- STEP 8: CVE vulnerability analysis -----------------------------------
    if args.skip_static:
        logger.info("  [SKIP] Step 8: CVE vulnerability analysis — --skip-static flag set")
        results[8] = ("CVE analysis", True)
    else:
        ok = run_step(8, "CVE vulnerability analysis",
                      [PYTHON, "-u", "-m", "cve.main"])
        results[8] = ("CVE analysis", ok)

    # ── STEP 9: PCAP capture (requires phone) ────────────────────────────────
    if args.skip_pcap:
        logger.info("  [SKIP] Step 9: PCAP capture — --skip-pcap flag set")
        logger.info("  [SKIP] Step 10: PCAP analysis — --skip-pcap flag set")
        results[9] = ("PCAP capture", None)
        results[10] = ("PCAP analysis", None)
    else:
        ok = run_step(9, "Capture live PCAP traffic (phone must be connected)",
                      [PYTHON, "-u", "collect_pcap.py",
                       "--auto",
                       "--skip-captured",
                       "--apk-dir", "normalized",
                       "--capture-time", str(args.capture_time),
                       "--monkey-events", str(args.monkey_events)])
        results[9] = ("PCAP capture", ok)

        # ── STEP 10: Parse PCAP traffic ──────────────────────────────────────
        ok = run_step(10, "Parse and geolocate PCAP traffic",
                      [PYTHON, "-u", "run_pcap_analysis.py",
                       "--input-dir", "data/pcap",
                       "--output-dir", "output/pcap",
                       "--sample-index", "sample_index.csv"])
        results[10] = ("PCAP analysis", ok)

    # ── STEP 11: Cleanup intermediate files ──────────────────────────────────
    if args.skip_cleanup:
        logger.info("  [SKIP] Step 11: Cleanup — --skip-cleanup flag set")
        results[11] = ("Cleanup files", None)
        results[12] = ("Empty Recycle Bin", None)
    else:
        logger.info("")
        logger.info("=" * 70)
        logger.info("  STEP 11: Cleanup intermediate files to free D: drive space")
        logger.info("=" * 70)

        # Delete decoded/ — largest intermediate directory (decompiled smali, resources)
        # delete_directory(PROJECT_ROOT / "decoded", "Decoded APKs")

        # Delete normalized/ — copied/extracted APK files
        # delete_directory(PROJECT_ROOT / "normalized", "Normalized packages")

        # Delete apks/ — raw downloaded APK binaries
        # delete_directory(PROJECT_ROOT / "apks", "Downloaded APKs")

        results[11] = ("Cleanup files", None)
        logger.info("  [SKIP] STEP 11 SKIPPED — intermediate files preserved")

        # ── STEP 12: Empty Recycle Bin ───────────────────────────────────────
        logger.info("")
        logger.info("=" * 70)
        logger.info("  STEP 12: Empty Windows Recycle Bin")
        logger.info("=" * 70)

        # empty_recycle_bin()
        results[12] = ("Empty Recycle Bin", None)
        logger.info("  [SKIP] STEP 12 SKIPPED — Recycle Bin preserved")

    _print_summary(results, pipeline_start)


def _print_summary(results: dict, pipeline_start: float):
    """Prints the final pipeline summary report."""
    elapsed = time.time() - pipeline_start

    logger.info("")
    logger.info("+------------------------------------------------------------------+")
    logger.info("|                    PIPELINE RUN COMPLETE                         |")
    logger.info("+------------------------------------------------------------------+")

    for step_num in sorted(results.keys()):
        desc, passed = results[step_num]
        if passed is True:
            status = "PASSED"
        elif passed is False:
            status = "FAILED"
        else:
            status = "SKIPPED"
        logger.info("|  Step %2d: %-30s  %-12s |", step_num, desc, status)

    logger.info("+------------------------------------------------------------------+")
    logger.info("|  Total time: %-50s |", format_duration(elapsed))
    logger.info("|  Log file  : %-50s |", LOG_FILE.name)
    logger.info("|  Finished  : %-50s |", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    logger.info("+------------------------------------------------------------------+")

    # Count outcomes
    passed_count = sum(1 for _, p in results.values() if p is True)
    failed_count = sum(1 for _, p in results.values() if p is False)
    skipped_count = sum(1 for _, p in results.values() if p is None)

    logger.info("")
    logger.info("  Results: %d passed, %d failed, %d skipped", passed_count, failed_count, skipped_count)

    if failed_count > 0:
        logger.warning("  [WARNING] Some steps failed. Check the log file for details: %s", LOG_FILE)
    else:
        logger.info("  [SUCCESS] All steps completed successfully!")

    logger.info("")
    logger.info("  Output files are in: %s", PROJECT_ROOT / "output")
    logger.info("")


if __name__ == "__main__":
    main()
