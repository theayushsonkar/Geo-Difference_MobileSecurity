"""
bench_apk_parse.py — Phase 3.8 LibScan profiling script.

Measures:
  A) Pure APK parsing cost (1-DEX tiny chunk = near-zero matching)
  B) Real chunk execution for both APKs with timing per phase
  C) Memory usage via psutil (if available)
"""
import os
import struct
import subprocess
import sys
import time
from pathlib import Path

# ─── setup ───────────────────────────────────────────────────────────────────

ROOT = Path(__file__).parent
TOOL_DIR = ROOT / "third_party/libscan/tool"
LIBS_DIR  = ROOT / "third_party/libscan/data/ground_truth_libs"
CHUNK_DB  = ROOT / "third_party/libscan/data/chunk_db"

APK_MAXBUPA = ROOT / "apks/com.maxbupa.healthapp/com.maxbupa.healthapp.apk"
APK_UTKARSH = ROOT / "apks/com.utkarshnew.android/com.utkarshnew.android.apk"

def make_env():
    env = os.environ.copy()
    env["PATH"] = str(TOOL_DIR / "module" / "dex2jar") + os.pathsep + env.get("PATH", "")
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    return env

def run_chunk(apk_dir: Path, chunk_dir: Path, out_dir: Path, log_path: Path,
              timeout: int = 600) -> tuple:
    """Returns (runtime_s, returncode, timed_out)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable, "LibScan.py", "detect_all",
        "-o", str(out_dir.resolve()),
        "-af", str(apk_dir.resolve()),
        "-lf", str(LIBS_DIR.resolve()),
        "-ld", str(chunk_dir.resolve()),
        "-p", "1",
    ]
    t0 = time.time()
    try:
        with open(log_path, "w", encoding="utf-8") as f_err:
            res = subprocess.run(
                cmd, cwd=str(TOOL_DIR),
                stdout=subprocess.PIPE,
                stderr=f_err,
                timeout=timeout,
                env=make_env(),
                text=True,
            )
        return time.time() - t0, res.returncode, False
    except subprocess.TimeoutExpired:
        return time.time() - t0, -1, True


def make_minimal_dex(path: Path):
    """Create a syntactically minimal DEX with 0 classes."""
    # Fixed at exactly 112 bytes (standard DEX header size)
    data = bytearray(112)
    data[0:8]   = b'dex\n035\x00'          # magic
    data[32:36] = struct.pack('<I', 112)    # file_size
    data[36:40] = struct.pack('<I', 112)    # header_size
    data[40:44] = struct.pack('<I', 0x12345678)  # endian_tag
    # checksum + sha1 left as 0 — androguard ignores them on read
    path.write_bytes(bytes(data))

# ─── Part A: APK parse cost ──────────────────────────────────────────────────

print("\n" + "="*60)
print("  PART A — APK Parsing Cost (minimal reference DB)")
print("="*60)

tiny_chunk = ROOT / "bench_tiny_chunk"
tiny_chunk.mkdir(exist_ok=True)
make_minimal_dex(tiny_chunk / "tiny.dex")

apks_dir_m = ROOT / "bench_apk_m"
apks_dir_m.mkdir(exist_ok=True)
apk_link = apks_dir_m / APK_MAXBUPA.name
if not apk_link.exists():
    try:
        apk_link.symlink_to(APK_MAXBUPA.resolve())
    except OSError:
        import shutil; shutil.copy2(APK_MAXBUPA, apk_link)

apks_dir_u = ROOT / "bench_apk_u"
apks_dir_u.mkdir(exist_ok=True)
apk_link_u = apks_dir_u / APK_UTKARSH.name
if not apk_link_u.exists():
    try:
        apk_link_u.symlink_to(APK_UTKARSH.resolve())
    except OSError:
        import shutil; shutil.copy2(APK_UTKARSH, apk_link_u)

for label, apks_dir in [("maxbupa", apks_dir_m), ("utkarsh", apks_dir_u)]:
    out = ROOT / f"bench_tiny_out_{label}"
    log = ROOT / f"bench_tiny_{label}.log"
    print(f"\n  Running APK parse-only test for {label}...")
    t, rc, timed_out = run_chunk(apks_dir, tiny_chunk, out, log, timeout=300)
    result = "TIMEOUT" if timed_out else f"exit={rc}"
    print(f"  {label:12s}  parse-only runtime: {t:.1f}s  ({result})")

# ─── Part B: Real chunk timing breakdown (maxbupa, chunk 0 only) ─────────────

print("\n" + "="*60)
print("  PART B — Chunk Timing: maxbupa, all 6 chunks (80 DEX each)")
print("="*60)
print(f"  {'Chunk':>7}  {'Files':>6}  {'Runtime (s)':>12}  {'Timeout?':>10}  {'Exit':>5}")
print("  " + "-"*50)

chunk_dirs = sorted(CHUNK_DB.glob("chunk_???"))
total_runtime = 0.0

for cdir in chunk_dirs:
    nfiles = sum(1 for _ in cdir.iterdir())
    out = ROOT / f"bench_real_out_{cdir.name}"
    log = ROOT / f"bench_real_{cdir.name}.log"
    t, rc, timed_out = run_chunk(apks_dir_m, cdir, out, log, timeout=360)
    total_runtime += t
    print(f"  {cdir.name:>9}  {nfiles:>6}  {t:>10.1f}s  {'YES' if timed_out else 'no':>10}  {rc:>5}")

print(f"\n  Total across 6 chunks: {total_runtime:.1f}s")
print(f"  Average per chunk:     {total_runtime/len(chunk_dirs):.1f}s")

# ─── Part C: Memory snapshot ─────────────────────────────────────────────────

print("\n" + "="*60)
print("  PART C — Python / System Info")
print("="*60)
print(f"  Python version: {sys.version}")
try:
    import psutil
    mem = psutil.virtual_memory()
    print(f"  Total RAM      : {mem.total / 2**30:.1f} GB")
    print(f"  Available RAM  : {mem.available / 2**30:.1f} GB")
    print(f"  RAM used       : {mem.percent:.1f}%")
except ImportError:
    print("  psutil not available — install with: pip install psutil")

print("\n  Done.")
