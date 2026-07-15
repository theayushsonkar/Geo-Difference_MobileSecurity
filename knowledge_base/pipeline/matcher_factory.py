from typing import Optional
from knowledge_base.pipeline.cache_manager import CacheManager
from knowledge_base.pipeline.base_matcher import BaseMatcher

class MatcherFactory:
    _instance: Optional['MatcherFactory'] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(MatcherFactory, cls).__new__(cls)
        return cls._instance

    @classmethod
    def initialize(cls) -> None:
        """Initialize all matchers centrally and exactly once."""
        if CacheManager.has("matchers_initialized"):
            return
            
        privacy = cls().privacy()
        privacy.initialize()
        
        secret = cls().secret()
        secret.initialize()
        
        geo = cls().geo()
        geo.initialize()
        
        CacheManager.set("matchers_initialized", True)

    def privacy(self) -> BaseMatcher:
        from knowledge_base.pipeline.aho_matcher import PrivacyMatcher
        if not CacheManager.has("privacy_matcher"):
            CacheManager.set("privacy_matcher", PrivacyMatcher())
        return CacheManager.get("privacy_matcher")
        
    def secret(self) -> BaseMatcher:
        from knowledge_base.pipeline.secret_matcher import SecretMatcher
        if not CacheManager.has("secret_matcher"):
            CacheManager.set("secret_matcher", SecretMatcher())
        return CacheManager.get("secret_matcher")
        
    def geo(self) -> BaseMatcher:
        from knowledge_base.pipeline.geo_matcher import GeoMatcher
        if not CacheManager.has("geo_matcher"):
            CacheManager.set("geo_matcher", GeoMatcher())
        return CacheManager.get("geo_matcher")
