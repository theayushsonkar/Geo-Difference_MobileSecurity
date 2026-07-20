import ipaddress
from typing import Dict, Optional
from pcap.schemas import DNSResolverFact

class DNSResolverMatcher:
    """Matches IP addresses against the DNS Resolver Knowledge Base."""
    
    def __init__(self, resolvers: Dict[str, dict]):
        self.resolvers = resolvers
        # Precompute IP networks for CIDR matching
        self.networks = {}
        for ip_str, record in self.resolvers.items():
            if "/" in ip_str:
                try:
                    net = ipaddress.ip_network(ip_str, strict=False)
                    self.networks[net] = record
                except ValueError:
                    pass
        
    def match(self, ip_address: str) -> Optional[DNSResolverFact]:
        if not ip_address:
            return None
            
        # 1. Exact match
        record = self.resolvers.get(ip_address)
        
        # 2. CIDR match
        if not record and self.networks:
            try:
                ip_obj = ipaddress.ip_address(ip_address)
                for net, net_record in self.networks.items():
                    if ip_obj in net:
                        record = net_record
                        break
            except ValueError:
                pass
                
        if record:
            return DNSResolverFact(
                ip_address=ip_address,
                provider=record.get("provider", ""),
                canonical_provider=record.get("canonical_provider", ""),
                resolver_name=record.get("resolver_name", ""),
                provider_country=record.get("provider_country", ""),
                supports_doh=str(record.get("supports_doh", "false")).lower() == "true",
                supports_dot=str(record.get("supports_dot", "false")).lower() == "true",
                supports_dnscrypt=str(record.get("supports_dnscrypt", "false")).lower() == "true",
                source_dataset=record.get("source_dataset", ""),
                source_version=record.get("source_version", ""),
                confidence=record.get("confidence", "MEDIUM")
            )
            
        return None
