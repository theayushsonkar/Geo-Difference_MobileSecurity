import os
import sys
import json
import shutil
import subprocess
from pathlib import Path
import pandas as pd

workspace_dir = Path(r"d:\New folder\Geo-Difference_MobileSecurity")
sys.path.append(str(workspace_dir))

def main():
    print("=== STARTING RUNNER AUDIT ===")
    
    # 1. Run pipeline on the test PCAP
    input_dir = workspace_dir / "data" / "pcap"
    output_dir = workspace_dir / "output" / "audit_run"
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        sys.executable,
        str(workspace_dir / "run_pcap_analysis.py"),
        "--input-dir", str(input_dir),
        "--output-dir", str(output_dir)
    ]
    subprocess.run(cmd, capture_output=True, text=True)

    # List files generated
    print("Files in output directory:")
    files = list(output_dir.iterdir())
    for f in files:
        print(f"  - {f.name}")

    # Check Part 1 & 2: Row/Col counts & schemas
    csv_mapping = {
        "connections.csv": "ConnectionRecord",
        "dns_records.csv": "DNSRecord",
        "domain_geo_records.csv": "DomainGeoRecord",
        "app_summaries.csv": "AppSummary"
    }

    # Load schemas.py fields
    from pcap.schemas import ConnectionRecord, DNSRecord, AppSummary
    # DomainGeoRecord is defined in connection_builder.py
    from pcap.connection_builder import DomainGeoRecord

    schema_fields = {
        "ConnectionRecord": list(ConnectionRecord.__dataclass_fields__.keys()),
        "DNSRecord": list(DNSRecord.__dataclass_fields__.keys()),
        "DomainGeoRecord": list(DomainGeoRecord.__dataclass_fields__.keys()),
        "AppSummary": list(AppSummary.__dataclass_fields__.keys())
    }

    for fname, dataclass_name in csv_mapping.items():
        fpath = output_dir / fname
        if fpath.exists():
            df = pd.read_csv(fpath)
            print(f"\nCSV: {fname}")
            print(f"  Rows: {len(df)}")
            print(f"  Cols: {len(df.columns)}")
            
            # Compare columns
            csv_cols = list(df.columns)
            target_cols = schema_fields[dataclass_name]
            
            missing = [c for c in target_cols if c not in csv_cols]
            extra = [c for c in csv_cols if c not in target_cols]
            
            print(f"  Missing fields: {missing}")
            print(f"  Extra fields: {extra}")
            
            # Check order
            common = [c for c in target_cols if c in csv_cols]
            order_diff = False
            for idx, c in enumerate(common):
                csv_idx = csv_cols.index(c)
                if csv_idx != idx:
                    order_diff = True
            print(f"  Column order matches exactly: {not order_diff}")

    # Trace count validation
    trace_file = output_dir / "pcap_trace.json"
    with open(trace_file, "r") as f:
        trace = json.load(f)

    print("\nTrace Count Validation:")
    print(f"  connections: trace={trace['connections_generated']} vs csv={len(pd.read_csv(output_dir / 'connections.csv'))} -> {'PASS' if trace['connections_generated'] == len(pd.read_csv(output_dir / 'connections.csv')) else 'FAIL'}")
    print(f"  dns_records: trace={trace['dns_records_generated']} vs csv={len(pd.read_csv(output_dir / 'dns_records.csv'))} -> {'PASS' if trace['dns_records_generated'] == len(pd.read_csv(output_dir / 'dns_records.csv')) else 'FAIL'}")
    print(f"  domain_geo: trace={trace['domain_geo_records_generated']} vs csv={len(pd.read_csv(output_dir / 'domain_geo_records.csv'))} -> {'PASS' if trace['domain_geo_records_generated'] == len(pd.read_csv(output_dir / 'domain_geo_records.csv')) else 'FAIL'}")
    print(f"  app_summaries: trace={trace['app_summaries_generated']} vs csv={len(pd.read_csv(output_dir / 'app_summaries.csv'))} -> {'PASS' if trace['app_summaries_generated'] == len(pd.read_csv(output_dir / 'app_summaries.csv')) else 'FAIL'}")

    # Failure Handling
    print("\n--- Testing Failure Handling ---")
    fake_input_dir = output_dir / "fake_input"
    fake_input_dir.mkdir(exist_ok=True)
    # Copy valid PCAP
    shutil.copy(input_dir / "arrow_escape.pcap", fake_input_dir / "arrow_escape.pcap")
    # Write broken PCAP
    with open(fake_input_dir / "broken.pcap", "wb") as f:
        f.write(b"BROKEN_INVALID_PCAP_BYTES_12345")

    fake_output_dir = output_dir / "fake_output"
    cmd = [
        sys.executable,
        str(workspace_dir / "run_pcap_analysis.py"),
        "--input-dir", str(fake_input_dir),
        "--output-dir", str(fake_output_dir)
    ]
    subprocess.run(cmd, capture_output=True, text=True)

    with open(fake_output_dir / "pcap_trace.json", "r") as f:
        fake_trace = json.load(f)
    print(f"Samples processed: {fake_trace['samples_processed']}")
    print(f"Samples failed: {fake_trace['samples_failed']}")
    print(f"Errors recorded: {json.dumps(fake_trace['errors'])}")
    print(f"Fail Handling: {'PASS' if fake_trace['samples_processed'] == 1 and fake_trace['samples_failed'] == 1 and len(fake_trace['errors']) == 1 else 'FAIL'}")

    # Multi-PCAP Audit
    print("\n--- Testing Multi-PCAP ---")
    multi_input_dir = output_dir / "multi_input"
    multi_input_dir.mkdir(exist_ok=True)
    shutil.copy(input_dir / "arrow_escape.pcap", multi_input_dir / "pcap1.pcap")
    shutil.copy(input_dir / "arrow_escape.pcap", multi_input_dir / "pcap2.pcap")

    multi_output_dir = output_dir / "multi_output"
    cmd = [
        sys.executable,
        str(workspace_dir / "run_pcap_analysis.py"),
        "--input-dir", str(multi_input_dir),
        "--output-dir", str(multi_output_dir)
    ]
    subprocess.run(cmd, capture_output=True, text=True)

    with open(multi_output_dir / "pcap_trace.json", "r") as f:
        multi_trace = json.load(f)
    print(f"Multi-PCAP Summaries: {multi_trace['app_summaries_generated']}")
    print(f"Multi-PCAP: {'PASS' if multi_trace['app_summaries_generated'] == 2 and len(pd.read_csv(multi_output_dir / 'app_summaries.csv')) == 2 else 'FAIL'}")

    # Re-run Audit
    print("\n--- Testing Re-run ---")
    # Check if files are overwritten or appended. 
    # Current implementation overwrites: it loads pd.DataFrame(all_conns).to_csv(..., index=False)
    # Let's verify by checking row counts before and after.
    conns_len_1 = len(pd.read_csv(multi_output_dir / "connections.csv"))
    subprocess.run(cmd, capture_output=True, text=True)
    conns_len_2 = len(pd.read_csv(multi_output_dir / "connections.csv"))
    print(f"First run len: {conns_len_1}, Second run len: {conns_len_2}")
    print(f"Re-run behavior: {'OVERWRITE' if conns_len_1 == conns_len_2 else 'APPEND'}")

    # Cleanup
    shutil.rmtree(output_dir)

if __name__ == "__main__":
    main()
