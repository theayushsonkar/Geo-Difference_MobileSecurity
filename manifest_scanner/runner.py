"""
Orchestration logic (run and main) for the manifest scanner.
"""

import argparse
import json
import time
import uuid
from typing import Optional

from .constants import PARSER_VERSION, SCHEMA_VERSION
from .extractor import ManifestFeatureExtractor
from .output import write_outputs
from .sample_index import load_sample_index


def run(sample_index_path: str, output_dir: str, run_id: Optional[str] = None, verbose: bool = False):
    run_id = run_id or str(uuid.uuid4())
    samples, index_sha256 = load_sample_index(sample_index_path)
    results = []
    trace = {
        "run_id": run_id,
        "schema_version": SCHEMA_VERSION,
        "parser_version": PARSER_VERSION,
        "sample_index_path": sample_index_path,
        "sample_index_sha256": index_sha256,
        "samples": [],
    }

    extractors = []
    total_start = time.time()
    for i, sample in enumerate(samples, start=1):
        sample_start = time.time()
        if verbose:
            print(f"[{i}/{len(samples)}] {sample.sample_id} {sample.source_path}")
        extractor = ManifestFeatureExtractor(sample, run_id)
        result = extractor.extract()
        results.append(result)
        extractors.append(extractor)
        trace["samples"].append(result["trace"])
        sample_duration = time.time() - sample_start
        if verbose:
            print(f"  -> Extracted {sample.sample_id} in {sample_duration:.2f}s")

    total_duration = time.time() - total_start
    print(f"[STATUS] Extraction of {len(samples)} samples completed in {total_duration:.2f}s")

    statistics = {
        "samples_processed": sum(1 for r in results if r.get("app", {}).get("extraction_status") == "ok"),
        "samples_skipped": sum(1 for r in results if r.get("app", {}).get("extraction_status") != "ok"),
        "smali_files_scanned": sum((r.get("trace", {}).get("statistics", {}) or {}).get("smali_files_scanned", 0) for r in results),
        "resource_files_scanned": sum((r.get("trace", {}).get("statistics", {}) or {}).get("resource_files_scanned", 0) for r in results),
        "sdks_detected": sum(len(r.get("sdks", [])) for r in results),
        "sdk_versions_found": sum((r.get("trace", {}).get("statistics", {}) or {}).get("sdk_versions_found", 0) for r in results),
        "duplicates_suppressed": sum((r.get("trace", {}).get("statistics", {}) or {}).get("duplicates_suppressed", 0) for r in results),
    }
    findings_by_type = {}
    for result in results:
        sample_findings = (result.get("trace", {}).get("statistics", {}) or {}).get("findings_by_type", {}) or {}
        for finding_type, count in sample_findings.items():
            findings_by_type[finding_type] = findings_by_type.get(finding_type, 0) + int(count)
    statistics["findings_by_type"] = findings_by_type

    trace["row_counts"] = {
        "manifest_apps": len(results),
        "manifest_sdks": sum(len(r["sdks"]) for r in results),
        "manifest_components": sum(len(r["components"]) for r in results),
        "manifest_permissions": sum(len(r["permissions"]) for r in results),
        "manifest_network_domains": sum(len(r["network_domains"]) for r in results),
        "static_code_findings": sum(len(r.get("findings", [])) for r in results),
    }
    trace["statistics"] = statistics
    
    t_out_start = time.time()
    write_outputs(output_dir, results, trace)
    output_time_per_sample = (time.time() - t_out_start) / max(1, len(samples))

    for ext in extractors:
        print(f"[PROFILE] {ext.sample.sample_id}")
        print(f"filesystem: {ext.perf_timers['filesystem']:.2f}s")
        print(f"sdk_detection: {ext.perf_timers['sdk_detection']:.2f}s")
        print(f"version_extraction: {ext.perf_timers['version_extraction']:.2f}s")
        print(f"findings: {ext.perf_timers['findings']:.2f}s")
        print(f"  - endpoint_detection: {ext.perf_timers['endpoint']:.2f}s")
        print(f"  - secret_detection: {ext.perf_timers['secret']:.2f}s")
        print(f"  - pii_detection: {ext.perf_timers['pii']:.2f}s")
        print(f"  - geo_logic_detection: {ext.perf_timers['geo']:.2f}s")
        print(f"aggregation: {ext.perf_timers['aggregation']:.2f}s")
        print(f"output: {output_time_per_sample:.2f}s")
        print(f"file_open: {ext.perf_timers['file_open']:.2f}s")
        print(f"file_read: {ext.perf_timers['file_read']:.2f}s")
        print(f"file_decode: {ext.perf_timers['file_decode']:.2f}s")
        print(f"total_files_scanned: {ext.total_files_scanned}")
        print(f"smali_files_scanned: {ext.stats.get('smali_files_scanned', 0)}")
        print(f"regex_evaluations: {ext.regex_evals}")
        print()

    if len(results) != len(samples):
        raise ValueError("manifest_apps.csv row count does not match loaded sample count")
    return trace["row_counts"]


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Schema-driven, facts-only Android manifest feature extractor."
    )
    parser.add_argument("-i", "--index", required=True, help="Path to sample_index.csv")
    parser.add_argument("-o", "--output", default="./output", help="Output directory")
    parser.add_argument("--run-id", default=None, help="Optional deterministic run id")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print per-sample progress")
    args = parser.parse_args(argv)
    counts = run(args.index, args.output, args.run_id, args.verbose)
    print(json.dumps(counts, sort_keys=True))


if __name__ == "__main__":
    main()
