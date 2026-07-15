"""Aho-Corasick Multi-Pattern Matcher for Privacy APIs."""
import ahocorasick
from abc import ABC, abstractmethod
from typing import List, Dict, Set, Any
from collections import defaultdict

from knowledge_base.schemas.privacy_api_schema import PrivacyAPIRecord
from knowledge_base.logger import get_logger
from knowledge_base.pipeline.base_matcher import BaseMatcher
from knowledge_base.schemas.finding_schema import PrivacyFinding

logger = get_logger(__name__)



class PrivacyMatcher(BaseMatcher):
    """High-Performance Aho-Corasick Backend for Privacy APIs."""
    
    def __init__(self):
        self.automaton = ahocorasick.Automaton()
        self.is_built = False
        
    def initialize(self) -> None:
        """Initialize the matcher by building the automaton."""
        if self.is_built:
            return
        from knowledge_base.pipeline.knowledge_enrichment import KnowledgeEnrichmentEngine
        records = KnowledgeEnrichmentEngine().enrich()
        self.build(records)
        
    def _generate_tokens(self, api: PrivacyAPIRecord) -> Set[str]:
        tokens = set()
        if api.class_name and api.method_name:
            if api.method_name == "<init>":
                tokens.add(api.class_name)
            else:
                tokens.add(f"{api.class_name}.{api.method_name}")
        elif api.class_name:
            tokens.add(api.class_name)
        elif api.package_name:
            tokens.add(api.package_name.split('.')[-1])
        return {t.strip() for t in tokens if t.strip()}
        
    def build(self, records: List[PrivacyAPIRecord]) -> None:
        """Builds the Aho-Corasick automaton from enriched API records."""
        logger.info("Building Aho-Corasick automaton...")
        mapping = defaultdict(list)
        
        for rec in records:
            if not rec.category or rec.category.lower() == "unknown":
                continue
                
            cat = rec.category.lower().replace(" ", "_")
            subcat = rec.subcategory.lower().replace(" ", "_")
            conf = rec.confidence.upper()
            
            best_conf = "low"
            if conf in ["VERY_HIGH", "HIGH"]:
                best_conf = "high"
            elif conf == "MEDIUM":
                best_conf = "medium"
                
            tokens = self._generate_tokens(rec)
            for token in tokens:
                mapping[token.lower()].append({
                    "token": token,
                    "category": cat,
                    "subcategory": subcat,
                    "confidence": best_conf
                })
                
        # Insert into automaton
        for key, values in mapping.items():
            unique_vals = []
            seen = set()
            for v in values:
                tup = (v["category"], v["subcategory"])
                if tup not in seen:
                    seen.add(tup)
                    unique_vals.append(v)
            self.automaton.add_word(key, unique_vals)
            
        self.automaton.make_automaton()
        self.is_built = True
        logger.info(f"Automaton built with {len(self.automaton)} unique lowercased tokens.")
        
    def search(self, text: str) -> List[PrivacyFinding]:
        """Searches text for matches in O(text length) time."""
        if not self.is_built or not text:
            return []
            
        text_lower = text.lower()
        findings = []
        seen_combinations = set()
        
        for end_idx, values in self.automaton.iter(text_lower):
            for v in values:
                tup = (v["category"], v["subcategory"], v["token"])
                if tup not in seen_combinations:
                    seen_combinations.add(tup)
                    start_idx = end_idx - len(v["token"]) + 1
                    findings.append(PrivacyFinding(
                        matcher="privacy",
                        category=v["category"],
                        subcategory=v["subcategory"],
                        confidence=v["confidence"],
                        matched_text=v["token"],
                        offset_start=start_idx,
                        offset_end=end_idx,
                        source="privacy_api",
                        api_signature=v["token"]
                    ))
                    
        # Deterministic sort
        findings.sort(key=lambda x: (x.category, x.subcategory, x.matched_text))
        return findings

    def statistics(self) -> Dict[str, Any]:
        return {
            "automaton_size": len(self.automaton) if self.is_built else 0,
            "is_built": self.is_built
        }

    def close(self) -> None:
        pass
