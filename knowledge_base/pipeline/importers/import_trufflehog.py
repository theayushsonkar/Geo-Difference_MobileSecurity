import os
import re
import csv
import json
import subprocess
from datetime import datetime, timezone

def camel_case_split(identifier):
    matches = re.finditer('.+?(?:(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])|$)', identifier)
    return [m.group(0) for m in matches]

def main():
    repo_dir = os.path.join("knowledge_base", "raw", "trufflehog")
    detectors_dir = os.path.join(repo_dir, "pkg", "detectors")
    output_dir = os.path.join("knowledge_base", "metadata")
    processed_dir = os.path.join("knowledge_base", "processed")
    
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(processed_dir, exist_ok=True)
    
    # Get git info
    try:
        commit_hash = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo_dir).decode("utf-8").strip()
    except Exception:
        commit_hash = "unknown"
        
    records = []
    
    # Track statistics
    stats = {}
    total_detectors = 0
    total_regex = 0
    discarded_helpers = 0
    discarded_verifications = 0
    type_counters = {}
    
    for root, _, files in os.walk(detectors_dir):
        for f in files:
            if f.endswith('.go') and not f.endswith('_test.go'):
                path = os.path.join(root, f)
                with open(path, 'r', encoding='utf-8') as file:
                    content = file.read()
                    
                    folder_name = os.path.basename(root)
                    
                    # Remove comments from content to avoid extracting commented-out malformed regexes
                    # Only remove lines that start with // to avoid breaking https:// in strings
                    lines = content.split('\n')
                    clean_lines = []
                    for line in lines:
                        if line.strip().startswith('//'):
                            continue
                        clean_lines.append(line)
                    content = '\n'.join(clean_lines)
                    content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
                    
                    # Extract Detector Type Name (e.g. DetectorType_AlgoliaAdminKey -> AlgoliaAdminKey)
                    type_match = re.search(r'DetectorType_([A-Za-z0-9_]+)', content)
                    detector_type_name = type_match.group(1) if type_match else folder_name.title()
                    
                    # Try to separate provider and secret type
                    parts = camel_case_split(detector_type_name)
                    provider = parts[0] if parts else folder_name
                    
                    secret_type = "API Key"
                    if len(parts) > 1:
                        secret_type = " ".join(parts[1:])
                        if "Key" not in secret_type and "Token" not in secret_type and "Secret" not in secret_type and "Password" not in secret_type:
                            secret_type += " API Key"
                            
                    # Extract Verification
                    verification_supported = "true" if "func verifyMatch" in content or "verify {" in content or "verify   bool" in content or "func (s Scanner) FromData(ctx context.Context, verify bool," in content else "false"
                    if "verify bool" in content and "if verify {" in content:
                        verification_supported = "true"
                        
                    # Extract patterns
                    patterns = []
                    
                    blacklist_substrings = ['domain', 'email', 'url', 'endpoint', 'uri', 'server', 'falsepositive', 'tenant', 'portal', 'cloudname', 'vaulturl', 'baseurl', 'host', 'subdomain', 'connstrpart', 'hostname', 'geterror', 'keyword', 'placeholder', 'username', 'uname']
                    verification_substrings = ['verify', 'validation']
                    
                    for m in re.finditer(r'(?:([A-Za-z0-9_]+)\s*(?:=|:=)\s*)?regexp\.MustCompile', content):
                        var_name = m.group(1)
                        if var_name:
                            var_lower = var_name.lower()
                            if any(b in var_lower for b in blacklist_substrings):
                                discarded_helpers += 1
                                continue
                            if any(v in var_lower for v in verification_substrings):
                                discarded_verifications += 1
                                continue
                                
                        start = m.end()
                        chunk = content[start:start+5000]
                        bt_pos = chunk.find('`')
                        dq_pos = chunk.find('"')
                        
                        bt_pos = bt_pos if bt_pos != -1 else 9999
                        dq_pos = dq_pos if dq_pos != -1 else 9999
                        
                        if bt_pos < dq_pos and bt_pos < 9999:
                            str_match = re.search(r'`([^`]+)`', chunk[bt_pos:])
                            if str_match and str_match.group(1).strip():
                                patterns.append(str_match.group(1))
                        elif dq_pos < 9999:
                            dq_match = re.search(r'"((?:\\.|[^"\\])*)"', chunk[dq_pos:])
                            if dq_match and dq_match.group(1).strip():
                                patterns.append(dq_match.group(1).replace('\\"', '"'))
                                
                    if patterns:
                        total_detectors += 1
                        
                        if provider not in stats:
                            stats[provider] = {"detectors": 0, "regexes": 0, "verified": 0}
                            
                        stats[provider]["detectors"] += 1
                        stats[provider]["regexes"] += len(patterns)
                        if verification_supported == "true":
                            stats[provider]["verified"] += 1
                            
                    type_key = detector_type_name.lower()
                    if type_key not in type_counters:
                        type_counters[type_key] = 1
                    
                    for idx, pat in enumerate(patterns):
                        total_regex += 1
                        pat_id = f"{type_key}_{type_counters[type_key]}"
                        type_counters[type_key] += 1
                        
                        records.append({
                            "pattern_id": pat_id,
                            "provider": provider,
                            "secret_type": secret_type,
                            "regex": pat,
                            "severity": "HIGH",
                            "verification_supported": verification_supported,
                            "source": "TruffleHog",
                            "notes": ""
                        })
                        
    # Normalization (Deduplication)
    unique_records = {}
    for r in records:
        key = r["regex"]
        if key not in unique_records:
            unique_records[key] = r
            
    final_records = list(unique_records.values())
    final_records.sort(key=lambda x: x["pattern_id"])
    
    # Write CSV
    csv_path = os.path.join(output_dir, "secret_patterns.csv")
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=["pattern_id", "provider", "secret_type", "regex", "severity", "verification_supported", "source", "notes"])
        writer.writeheader()
        writer.writerows(final_records)
        
    # Write Stats CSV
    stats_csv_path = os.path.join(processed_dir, "trufflehog_statistics.csv")
    with open(stats_csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["provider", "detector_count", "regex_count", "verification_supported_count"])
        for prov in sorted(stats.keys()):
            writer.writerow([prov, stats[prov]["detectors"], stats[prov]["regexes"], stats[prov]["verified"]])
            
    # STEP 1: Provider Summary CSV
    prov_summary_path = os.path.join(processed_dir, "trufflehog_provider_summary.csv")
    provider_stats = {}
    for r in final_records:
        p = r["provider"]
        if p not in provider_stats:
            provider_stats[p] = {"detectors": set(), "regex_count": 0, "verified_count": 0}
        provider_stats[p]["detectors"].add(r["pattern_id"].rsplit('_', 1)[0])
        provider_stats[p]["regex_count"] += 1
        if r["verification_supported"] == "true":
            provider_stats[p]["verified_count"] += 1
            
    with open(prov_summary_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["provider", "detector_count", "regex_count", "verification_supported_count"])
        sorted_prov = sorted(provider_stats.items(), key=lambda x: x[1]["regex_count"], reverse=True)
        for p, d in sorted_prov:
            writer.writerow([p, len(d["detectors"]), d["regex_count"], d["verified_count"]])
            
    # STEP 2: Detector Summary CSV
    det_summary_path = os.path.join(processed_dir, "trufflehog_detector_summary.csv")
    detector_stats = {}
    for r in final_records:
        det_name = r["pattern_id"].rsplit('_', 1)[0]
        p = r["provider"]
        key = (p, det_name)
        if key not in detector_stats:
            detector_stats[key] = {"regex_count": 0, "verification": r["verification_supported"]}
        detector_stats[key]["regex_count"] += 1
        
    with open(det_summary_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["provider", "detector_name", "regex_count", "verification_supported"])
        sorted_det = sorted(detector_stats.items(), key=lambda x: x[1]["regex_count"], reverse=True)
        for (p, dname), d in sorted_det:
            writer.writerow([p, dname, d["regex_count"], d["verification"]])
            
    # Write Report
    from collections import Counter
    provider_dist = Counter([r["provider"] for r in final_records])
    secret_type_dist = Counter([r["secret_type"] for r in final_records])
    verification_dist = Counter([r["verification_supported"] for r in final_records])
    
    report_path = os.path.join(processed_dir, "trufflehog_import_report.md")
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write("# TruffleHog Secret Knowledge Acquisition Report\n\n")
        f.write(f"- **Repository**: https://github.com/trufflesecurity/trufflehog.git\n")
        f.write(f"- **Commit Hash**: `{commit_hash}`\n")
        f.write(f"- **Import Timestamp**: {datetime.now(timezone.utc).isoformat()}\n\n")
        f.write(f"## Statistics\n")
        f.write(f"- **Detectors Imported**: {total_detectors}\n")
        f.write(f"- **Regex Extracted**: {total_regex}\n")
        f.write(f"- **Discarded Helper Regexes**: {discarded_helpers}\n")
        f.write(f"- **Discarded Verification Regexes**: {discarded_verifications}\n")
        f.write(f"- **Duplicate Regex Removed**: {total_regex - len(final_records)}\n")
        f.write(f"- **Final Unique Patterns**: {len(final_records)}\n\n")
        
        f.write("## Verification-Supported Statistics\n")
        f.write(f"- **Verified**: {verification_dist.get('true', 0)}\n")
        f.write(f"- **Unverified**: {verification_dist.get('false', 0)}\n\n")
        
        f.write("## Top 10 Provider Distribution\n")
        for prov, count in provider_dist.most_common(10):
            f.write(f"- **{prov}**: {count}\n")
        f.write("\n")
        
        f.write("## Top 10 Secret Type Distribution\n")
        for stype, count in secret_type_dist.most_common(10):
            f.write(f"- **{stype}**: {count}\n")
        f.write("\n")
        
        f.write("## Known Limitations\n")
        f.write("- **Regex Extraction**: Some highly dynamic regexes generated via complex Go AST or `Sprintf` logic cannot be extracted statically and might be missed or malformed.\n")
        f.write("- **Comments**: String literals containing `//` require strict multi-line AST parsing, our regex-based comment-stripper gracefully skips lines beginning with comments to prevent corruption.\n\n")
        f.write("The importer preserves TruffleHog RE2 expressions verbatim rather than translating them into Python regex.\n")
        
    print("Done")

if __name__ == "__main__":
    main()
