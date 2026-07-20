import re
from typing import List, Dict, Tuple
from pcap.schemas import PIIFact
from pcap.matchers.pii_validators import VALIDATOR_REGISTRY

class PIIMatcher:
    """Matches text against a compiled master regex of known PII patterns."""
    
    def __init__(self, patterns: List[dict]):
        self.patterns = patterns
        self._group_map = {}
        
        # Build master regex
        regex_parts = []
        for i, pat in enumerate(self.patterns):
            group_name = f"pii_{i}"
            self._group_map[group_name] = {
                "pattern_name": pat["pattern_name"],
                "category": pat["category"],
                "source_dataset": pat.get("source_dataset", ""),
                "source_reference": pat.get("source_reference", ""),
                "confidence": pat.get("confidence", "MEDIUM")
            }
            # Wrap the pattern's regex in a named capture group
            regex_parts.append(f"(?P<{group_name}>{pat['regex']})")
            
        if regex_parts:
            # Combine with OR
            master_regex_str = "|".join(regex_parts)
            self.master_regex = re.compile(master_regex_str, re.IGNORECASE)
        else:
            self.master_regex = None

    def match(self, text: str, source_location: str) -> List[PIIFact]:
        facts = []
        if not text or not self.master_regex:
            return facts
            
        for match in self.master_regex.finditer(text):
            # find which group matched
            for group_name, value in match.groupdict().items():
                if value is not None:
                    # Some patterns like Session ID have an inner capture group for the actual ID
                    # We should extract the exact matched string. If the user provided capture groups 
                    # inside their regex, we still get the full match of the named group here.
                    
                    meta = self._group_map[group_name]
                    
                    # Run validator if one exists
                    validator = VALIDATOR_REGISTRY.get(meta["pattern_name"])
                    if validator and not validator(value):
                        break # Reject
                        
                    facts.append(PIIFact(
                        pattern_name=meta["pattern_name"],
                        category=meta["category"],
                        matched_value=value,
                        source_location=source_location,
                        start_offset=match.start(group_name),
                        end_offset=match.end(group_name),
                        confidence=meta["confidence"],
                        source_dataset=meta["source_dataset"],
                        source_reference=meta["source_reference"]
                    ))
                    break # Only one top-level group matches per finditer yield
                    
        return facts
