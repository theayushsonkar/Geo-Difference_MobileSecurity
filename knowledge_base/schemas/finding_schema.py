from dataclasses import dataclass
from typing import Optional

@dataclass
class BaseFinding:
    matcher: str
    category: str
    subcategory: str
    confidence: str
    matched_text: str
    offset_start: int
    offset_end: int
    source: str

@dataclass
class PrivacyFinding(BaseFinding):
    permission: str = ""
    api_signature: str = ""

@dataclass
class SecretFinding(BaseFinding):
    rule_id: str = ""

@dataclass
class GeoFinding(BaseFinding):
    rule_id: str = ""
