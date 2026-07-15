"""Privacy API Schema."""
from dataclasses import dataclass, field
from typing import Optional, List

@dataclass
class PrivacyAPIRecord:
    """Canonical data model for representing a privacy-sensitive API."""
    record_id: str = ""
    category: str = ""
    subcategory: str = ""
    framework: str = ""
    package_name: str = ""
    class_name: str = ""
    method_name: str = ""
    api_name: str = ""
    api_type: str = ""
    permission: str = ""
    sources: List[str] = field(default_factory=list)
    source_versions: List[str] = field(default_factory=list)
    supported_android_versions: List[int] = field(default_factory=list)
    import_timestamp: str = ""
    min_android_api: Optional[int] = None
    max_android_api: Optional[int] = None
    confidence: str = ""
    documentation_url: str = ""
    deprecated: bool = False
    notes: str = ""
