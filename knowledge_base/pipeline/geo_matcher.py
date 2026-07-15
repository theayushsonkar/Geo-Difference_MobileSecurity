from dataclasses import dataclass
from typing import List, Tuple, Dict, Any
from knowledge_base.schemas.geo_rule_schema import GeoRule
from knowledge_base.pipeline.geo_rule_loader import GeoRuleLoader
from knowledge_base.pipeline.base_matcher import BaseMatcher
from knowledge_base.schemas.finding_schema import GeoFinding

class GeoMatcher(BaseMatcher):
    def __init__(self, rules: List[GeoRule] = None):
        self._initial_rules = rules
        self.rules = []

    def initialize(self) -> None:
        if self.rules:
            return
        if self._initial_rules is None:
            self.rules = GeoRuleLoader.load_rules()
        else:
            self.rules = self._initial_rules

    def search(self, text: str) -> List[GeoFinding]:
        findings = []
        for rule in self.rules:
            if not rule.supported or rule.compiled_pattern is None:
                continue
            
            for match in rule.compiled_pattern.finditer(text):
                findings.append(GeoFinding(
                    matcher="geo",
                    category=rule.category,
                    subcategory=rule.subcategory,
                    confidence=rule.confidence,
                    matched_text=match.group(0),
                    offset_start=match.start(),
                    offset_end=match.end(),
                    source="geo_matcher",
                    rule_id=rule.rule_id
                ))
        return findings

    def statistics(self) -> Dict[str, Any]:
        return {
            "total_rules": len(self.rules)
        }

    def close(self) -> None:
        pass
