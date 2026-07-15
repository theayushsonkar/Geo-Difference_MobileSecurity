from dataclasses import dataclass
from typing import Optional
import re

@dataclass(frozen=True)
class GeoRule:
    rule_id: str
    package_name: str
    class_name: str
    method_name: str
    category: str
    subcategory: str
    confidence: str
    source: str
    notes: str
    compiled_pattern: Optional[re.Pattern]
    supported: bool
