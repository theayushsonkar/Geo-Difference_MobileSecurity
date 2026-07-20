import base64
from pathlib import Path
from typing import Generator
import logging

from knowledge_base.network.schemas.kb_schemas import NormalizedDNSResolver

logger = logging.getLogger(__name__)

class DNSCryptResolverImporter:
    """Importer for the official dnscrypt-resolvers dataset."""
    
    def __init__(self, raw_path: Path):
        self.raw_path = raw_path

    def _parse_sdns(self, stamp: str):
        try:
            # Add padding just in case
            b = base64.urlsafe_b64decode(stamp + "===")
            proto = b[0]
            addr_len = b[9]
            addr = b[10:10+addr_len].decode('utf-8')
            
            ip = addr
            # Remove port if present
            if ip.startswith('['):
                ip = ip[1:ip.find(']')]
            else:
                if ':' in ip and not ip.count(':') > 1:
                    ip = ip.split(':')[0]
                
            return proto, ip
        except Exception as e:
            return None, None

    def process(self) -> Generator[NormalizedDNSResolver, None, None]:
        if not self.raw_path.exists():
            logger.warning(f"Dataset not found: {self.raw_path}")
            return
            
        with open(self.raw_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        blocks = content.split('\n## ')
        
        for block in blocks[1:]: # Skip header
            lines = block.split('\n')
            name = lines[0].strip()
            provider = ""
            ips = set()
            supports_doh = False
            supports_dnscrypt = False
            
            for line in lines[1:]:
                if line.startswith('Operated by'):
                    provider = line.split('Operated by')[1].split('.')[0].strip()
                
                if line.startswith('sdns://'):
                    stamp = line[7:]
                    proto, ip = self._parse_sdns(stamp)
                    if not ip:
                        continue
                        
                    if proto == 1:
                        supports_dnscrypt = True
                    elif proto == 2:
                        supports_doh = True
                        
                    ips.add(ip)
                    
            if ips:
                for ip in ips:
                    yield NormalizedDNSResolver(
                        ip_address=ip,
                        provider=provider or name,
                        canonical_provider="",
                        resolver_name=name,
                        provider_country="", # Not easily available in md
                        supports_doh=supports_doh,
                        supports_dot=False, # Not tracked in dnscrypt list
                        supports_dnscrypt=supports_dnscrypt,
                        source_dataset="dnscrypt-resolvers",
                        source_version="v3",
                        confidence="MEDIUM"
                    )
