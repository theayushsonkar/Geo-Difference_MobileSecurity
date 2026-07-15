import csv
import re
import os
from collections import Counter
from typing import List, Dict, Any
from knowledge_base.schemas.secret_pattern_schema import SecretPattern
from knowledge_base.pipeline.base_matcher import BaseMatcher
from knowledge_base.schemas.finding_schema import SecretFinding

class SecretMatcher(BaseMatcher):
    def __init__(self, csv_path="knowledge_base/metadata/secret_patterns.csv", generate_reports=True):
        self.csv_path = csv_path
        self.generate_reports = generate_reports
        self.patterns = []
        self.unsupported_patterns = []
        
    def initialize(self) -> None:
        if self.patterns:
            return
        self._load_patterns(self.csv_path)
        if self.generate_reports:
            self._generate_reports()

    def _load_patterns(self, csv_path):
        if not os.path.exists(csv_path):
            return
            
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                raw_regex = row.get("regex", "")
                compiled = None
                supported = True
                compile_error = ""
                
                try:
                    compiled = re.compile(raw_regex)
                except re.error as e:
                    supported = False
                    compile_error = str(e)
                except Exception as e:
                    supported = False
                    compile_error = str(e)
                    
                pattern = SecretPattern(
                    pattern_id=row.get("pattern_id", ""),
                    provider=row.get("provider", ""),
                    secret_type=row.get("secret_type", ""),
                    raw_regex=raw_regex,
                    compiled_regex=compiled,
                    severity=row.get("severity", ""),
                    verification_supported=row.get("verification_supported", ""),
                    source=row.get("source", ""),
                    notes=row.get("notes", ""),
                    supported=supported
                )
                
                self.patterns.append(pattern)
                if not supported:
                    self.unsupported_patterns.append((pattern, compile_error))

    def _generate_reports(self):
        processed_dir = "knowledge_base/processed"
        os.makedirs(processed_dir, exist_ok=True)
        
        # 1. Unsupported Report
        unsupported_path = os.path.join(processed_dir, "unsupported_secret_patterns.csv")
        with open(unsupported_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["pattern_id", "provider", "secret_type", "regex", "compile_error"])
            for pat, err in self.unsupported_patterns:
                writer.writerow([pat.pattern_id, pat.provider, pat.secret_type, pat.raw_regex, err])
                
        # 2. Loader Statistics
        total = len(self.patterns)
        failed = len(self.unsupported_patterns)
        success = total - failed
        success_rate = (success / total * 100) if total > 0 else 0
        
        provider_dist = Counter(p.provider for p in self.patterns)
        severity_dist = Counter(p.severity for p in self.patterns)
        
        stats_path = os.path.join(processed_dir, "secret_loader_statistics.csv")
        with open(stats_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Metric", "Value"])
            writer.writerow(["Total patterns", total])
            writer.writerow(["Successfully compiled", success])
            writer.writerow(["Failed compilation", failed])
            writer.writerow(["Compilation success rate", f"{success_rate:.2f}%"])
            writer.writerow([])
            writer.writerow(["Provider distribution", ""])
            for prov, count in provider_dist.most_common():
                writer.writerow([prov, count])
            writer.writerow([])
            writer.writerow(["Severity distribution", ""])
            for sev, count in severity_dist.most_common():
                writer.writerow([sev, count])
                
        # 3. Markdown Report
        report_path = os.path.join(processed_dir, "secret_matcher_report.md")
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("# Secret Matcher Robustness & Compatibility Report\n\n")
            f.write(f"- **Total patterns**: {total}\n")
            f.write(f"- **Successfully compiled**: {success}\n")
            f.write(f"- **Unsupported patterns**: {failed}\n")
            f.write(f"- **Compilation success percentage**: {success_rate:.2f}%\n\n")
            
            f.write("## Reasons unsupported regexes exist\n")
            f.write("TruffleHog uses Google's RE2 engine while the scanner currently relies on Python's `re` regex engine. ")
            f.write("Google's RE2 engine supports certain syntax elements that Python's native regex engine does not, ")
            f.write("such as the `\\z` anchor (absolute end of string without newline) or inline modifiers `(?i)` placed in the middle of a regex. ")
            f.write("Attempting to blindly compile these with `re.compile()` raises an `re.error`.\n\n")
            
            f.write("Unsupported detectors are preserved in the canonical database but excluded from runtime matching. ")
            f.write("This fault-tolerant design ensures the scanner gracefully falls back and never crashes due to a single incompatible RE2 signature.\n")

    def search(self, text: str) -> List[SecretFinding]:
        results = []
        if not text:
            return results
            
        for pat in self.patterns:
            if not pat.supported or pat.compiled_regex is None:
                continue
            
            try:
                for match in pat.compiled_regex.finditer(text):
                    results.append(SecretFinding(
                        matcher="secret",
                        category="Secret",
                        subcategory=pat.secret_type,
                        confidence=pat.severity.lower(),
                        matched_text=match.group(0),
                        offset_start=match.start(),
                        offset_end=match.end(),
                        source="secret_matcher",
                        rule_id=pat.pattern_id
                    ))
            except Exception:
                pass
        return results

    def statistics(self) -> Dict[str, Any]:
        return {
            "total_patterns": len(self.patterns),
            "unsupported_patterns": len(self.unsupported_patterns)
        }
        
    def close(self) -> None:
        pass
