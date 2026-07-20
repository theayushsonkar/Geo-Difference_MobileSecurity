import re
from pathlib import Path
from typing import List, Generator

from knowledge_base.network.schemas.kb_schemas import NormalizedTracker

class EasyPrivacyImporter:
    """Importer for EasyPrivacy dataset format."""
    
    def __init__(self, raw_path: Path):
        self.raw_path = raw_path

    def process(self) -> Generator[NormalizedTracker, None, None]:
        """Parses the raw EasyPrivacy text into NormalizedTracker models."""
        if not self.raw_path.exists():
            return
            
        version = ""
        # Regex for pure domain blocking rules: ||example.com^
        # We ignore rules with paths (e.g. ||example.com/path)
        # The user requested to ignore browser-specific rules, so we'll 
        # ignore rules with modifiers like $third-party if we want to be strict,
        # but capturing the domain before the ^ is the main goal.
        # We'll allow modifiers but just extract the domain.
        domain_regex = re.compile(r'^\|\|([a-zA-Z0-9.-]+)\^(\$.*)?$')
        
        with open(self.raw_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                # Extract version
                if line.startswith("! Version:"):
                    version = line.split(":", 1)[1].strip()
                    continue
                
                # Ignore comments and cosmetic rules
                if line.startswith("!") or line.startswith("["):
                    continue
                if "##" in line or "#?#" in line or "#@#" in line:
                    continue
                    
                match = domain_regex.match(line)
                if match:
                    domain = match.group(1).lower()
                    # Skip IP addresses if any, though regex matches them,
                    # we can just yield them and let the builder or matcher handle it.
                    yield NormalizedTracker(
                        domain_suffix=domain,
                        vendor="",
                        canonical_vendor="",
                        category="",
                        source_dataset="EasyPrivacy",
                        source_version=version
                    )
