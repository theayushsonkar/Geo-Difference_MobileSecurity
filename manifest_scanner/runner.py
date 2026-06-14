"""
Orchestration logic (run and main) for the manifest scanner.
"""

import argparse
import json
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

    for i, sample in enumerate(samples, start=1):
        if verbose:
            print(f"[{i}/{len(samples)}] {sample.sample_id} {sample.source_path}")
        extractor = ManifestFeatureExtractor(sample, run_id)
        result = extractor.extract()
        results.append(result)
        trace["samples"].append(result["trace"])

    trace["row_counts"] = {
        "manifest_apps": len(results),
        "manifest_sdks": sum(len(r["sdks"]) for r in results),
        "manifest_components": sum(len(r["components"]) for r in results),
        "manifest_permissions": sum(len(r["permissions"]) for r in results),
        "manifest_network_domains": sum(len(r["network_domains"]) for r in results),
    }
    write_outputs(output_dir, results, trace)
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
