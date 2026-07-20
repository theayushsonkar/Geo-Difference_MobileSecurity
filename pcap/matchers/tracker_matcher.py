"""
TrackerMatcher for the PCAP Analysis Engine.
Integrates with SuffixMatcher and TrackerFact.
"""
import functools
from typing import Optional, List

from pcap.schemas import TrackerFact
from pcap.matchers.suffix_matcher import SuffixMatcher


class TrackerMatcher(SuffixMatcher[TrackerFact]):
    """
    Matches domains against the Tracker Knowledge Base using a longest-suffix Trie.
    """
    def __init__(self, tracker_facts: List[TrackerFact]):
        super().__init__()
        for fact in tracker_facts:
            self.insert(fact.domain_suffix, fact)

    @functools.lru_cache(maxsize=8192)
    def match(self, domain: str) -> Optional[TrackerFact]:
        """
        Cached wrapper around the suffix trie match method.
        """
        return super().match(domain)
