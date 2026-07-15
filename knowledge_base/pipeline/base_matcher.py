from abc import ABC, abstractmethod
from typing import List, Dict, Any
from knowledge_base.schemas.finding_schema import BaseFinding

class BaseMatcher(ABC):
    @abstractmethod
    def initialize(self) -> None:
        """Initialize the matcher, loading knowledge bases and compiling automata/regexes."""
        pass
        
    @abstractmethod
    def search(self, text: str) -> List[BaseFinding]:
        """Search the text for findings and return them."""
        pass
        
    @abstractmethod
    def statistics(self) -> Dict[str, Any]:
        """Return statistics about the matcher's state and performance."""
        pass
        
    @abstractmethod
    def close(self) -> None:
        """Release resources used by the matcher."""
        pass
