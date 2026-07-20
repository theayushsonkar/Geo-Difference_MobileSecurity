"""
Generic SuffixMatcher for the PCAP Analysis Engine.
Implements longest-suffix matching for domain names.
"""
from typing import Generic, TypeVar, Dict, Optional, Any

T = TypeVar('T')

class SuffixMatcher(Generic[T]):
    """
    A generic matcher that finds the longest suffix of a domain.
    Internally uses a dictionary-based suffix tree (Trie) where nodes are domain labels reversed.
    """
    def __init__(self):
        # Trie structure: dict mapping label -> dict
        # A special key '' indicates a value at this node.
        self._trie: Dict[str, Any] = {}

    def insert(self, domain_suffix: str, value: T) -> None:
        """Inserts a domain suffix and its associated value into the Trie."""
        # Remove leading/trailing dots so .facebook.com becomes facebook.com
        clean_suffix = domain_suffix.lower().strip().strip('.')
        labels = clean_suffix.split('.') if clean_suffix else []
        # Reverse labels to match from the top-level domain (TLD) down to subdomains
        labels.reverse()
        
        node = self._trie
        for label in labels:
            if label not in node:
                node[label] = {}
            node = node[label]
        node[''] = value

    def match(self, domain: str) -> Optional[T]:
        """
        Finds the value associated with the longest matching suffix of the domain.
        Returns None if no suffix matches.
        """
        if not domain:
            return None
            
        clean_domain = domain.lower().strip().strip('.')
        labels = clean_domain.split('.') if clean_domain else []
        labels.reverse()
        
        node = self._trie
        best_match = None
        
        for label in labels:
            if label in node:
                node = node[label]
                if '' in node:
                    best_match = node['']
            else:
                break
                
        return best_match
