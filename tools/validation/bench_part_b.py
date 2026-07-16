"""
bench_part_b.py — Collect remaining chunk timings (chunks 001-005) for maxbupa.
chunk_000 already measured at 157.2s.
"""
import os, subprocess, sys, time
from pathlib import Path

ROOT     = Path(__file__).parent
TOOL_DIR = ROOT / "third_party/libscan/tool"
LIBS_DIR = ROOT / "third_party/libscan/data/ground_truth_libs"
CHUNK_DB = ROOT / "third_party/libscan/data/chunk_db"
APK_DIR  = ROOT / "bench_apk_m"   # already populated by bench_apk_parse.py

def make_env():
    env = os.environ.copy()
    env["PATH"] = str(TOOL_DIR / "module" / "dex2jar") + os.pathsep + env.get("PATH", "")
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    return env

# chunk_000 already done
KNOWN = {"chunk_000": 157.2}

chunk_dirs = sorted(CHUNK_DB.glob("chunk_???"))
print(f"\nPART B — Chunk timing for com.maxbupa.healthapp ({len(chunk_dirs)} chunks total)")
print(f"  {'Chunk':>9}  {'Files':>6}  {'Runtime (s)':>12}  {'Timeout?':>10}  {'Exit':>5}")
print("  " + "-"*55)

# Print already-known results
for k, v in KNOWN.items():
    nfiles = sum(1 for _ in (CHUNK_DB / k).iterdir())
    print(f"  {k:>9}  {nfiles:>6}  {v:>10.1f}s  {'no':>10}  {'0':>5}  (prior run)")

total = sum(KNOWN.values())
results = dict(KNOWN)

for cdir in chunk_dirs:
    if cdir.name in KNOWN:
        continue
    nfiles = sum(1 for _ in cdir.iterdir())
    out_dir = ROOT / f"bench_real_out_{cdir.name}"
    out_dir.mkdir(parents=True, exist_ok=True)
    log     = ROOT / f"bench_real_{cdir.name}.log"

    cmd = [
        sys.executable, "LibScan.py", "detect_all",
        "-o", str(out_dir.resolve()),
        "-af", str(APK_DIR.resolve()),
        "-lf", str(LIBS_DIR.resolve()),
        "-ld", str(cdir.resolve()),
        "-p", "1",
    ]

    t0 = time.time()
    timed_out = False
    rc = -1
    try:
        with open(log, "w", encoding="utf-8") as f_err:
            res = subprocess.run(
                cmd, cwd=str(TOOL_DIR),
                stdout=subprocess.PIPE,
                stderr=f_err,
                timeout=600,
                env=make_env(),
                text=True,
            )
        rc = res.returncode
    except subprocess.TimeoutExpired:
        timed_out = True
    elapsed = time.time() - t0

    total += elapsed
    results[cdir.name] = elapsed
    print(f"  {cdir.name:>9}  {nfiles:>6}  {elapsed:>10.1f}s  {'YES' if timed_out else 'no':>10}  {rc:>5}")

print(f"\n  Total (all 6 chunks): {total:.1f}s")
print(f"  Average per chunk:    {total/len(chunk_dirs):.1f}s")

# ── derive breakdown ──────────────────────────────────────────────────────────
apk_parse_cost = 203.7   # measured in Part A
matching_total = total - apk_parse_cost * len(chunk_dirs)
print(f"\n  === Cost Breakdown (com.maxbupa.healthapp) ===")
print(f"  APK parse per invocation : {apk_parse_cost:.0f}s")
print(f"  APK parse x{len(chunk_dirs)} chunks       : {apk_parse_cost*len(chunk_dirs):.0f}s")
print(f"  Library matching total   : {max(0, matching_total):.0f}s  (total - parse overhead)")
print(f"  Parse fraction of total  : {apk_parse_cost*len(chunk_dirs)/total*100:.1f}%")

# ── system info ───────────────────────────────────────────────────────────────
print(f"\n  Python {sys.version}")
try:
    import psutil
    m = psutil.virtual_memory()
    print(f"  RAM: {m.total/2**30:.1f} GB total, {m.available/2**30:.1f} GB free, {m.percent:.0f}% used")
except ImportError:
    pass

print("\nDone.")
