import sys
from knowledge_base.pipeline.matcher_factory import MatcherFactory

def validate_matchers():
    print("Validating Matcher Framework...")
    
    # 1. Initialize Factory
    try:
        MatcherFactory.initialize()
    except Exception as e:
        print(f"Failed to initialize MatcherFactory: {e}")
        sys.exit(1)
        
    factory = MatcherFactory()
    
    # 2. Check Matchers Load Successfully
    privacy = factory.privacy()
    secret = factory.secret()
    geo = factory.geo()
    
    stats = {
        "privacy": privacy.statistics(),
        "secret": secret.statistics(),
        "geo": geo.statistics()
    }
    
    if stats["privacy"].get("automaton_size", 0) == 0:
        print("Validation Failed: PrivacyMatcher loaded empty automaton.")
        sys.exit(1)
        
    if stats["secret"].get("total_patterns", 0) == 0:
        print("Validation Failed: SecretMatcher loaded 0 patterns.")
        sys.exit(1)
        
    if stats["geo"].get("total_rules", 0) == 0:
        print("Validation Failed: GeoMatcher loaded 0 rules.")
        sys.exit(1)
        
    # 3. Validation Passed
    print("Unified Validation Passed Successfully.")
    print("Matcher Statistics:")
    print(f" - Privacy Automaton Nodes: {stats['privacy'].get('automaton_size')}")
    print(f" - Secret Regex Patterns: {stats['secret'].get('total_patterns')}")
    print(f" - Geo Logic Rules: {stats['geo'].get('total_rules')}")

if __name__ == "__main__":
    validate_matchers()
