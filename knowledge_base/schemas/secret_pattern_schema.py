from dataclasses import dataclass
from typing import Optional
import re

@dataclass(frozen=True)
class SecretPattern:
    pattern_id: str
    provider: str
    secret_type: str
    raw_regex: str
    compiled_regex: Optional[re.Pattern]
    severity: str
    verification_supported: str
    source: str
    notes: str
    supported: bool
