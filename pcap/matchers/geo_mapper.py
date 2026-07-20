from typing import Optional, Tuple
from pathlib import Path
import geoip2.database
import ipaddress

from pcap.schemas import GeoFact, ASNFact

def _is_private(ip: str) -> bool:
    if not ip:
        return True
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_multicast or addr.is_unspecified or addr.is_link_local
    except ValueError:
        return True

class GeoMapper:
    """Performs runtime lookups against GeoLite2 databases."""
    
    def __init__(self, country_reader: geoip2.database.Reader, asn_reader: geoip2.database.Reader):
        self.country_reader = country_reader
        self.asn_reader = asn_reader
        self._cache_geo = {}
        self._cache_asn = {}

    def lookup_geo(self, ip: str) -> Optional[GeoFact]:
        if ip in self._cache_geo:
            return self._cache_geo[ip]
            
        if _is_private(ip):
            fact = GeoFact(ip=ip, country_code="PRIVATE", country_name="Private Network", continent="")
            self._cache_geo[ip] = fact
            return fact
            
        try:
            resp = self.country_reader.country(ip)
            fact = GeoFact(
                ip=ip,
                country_code=resp.country.iso_code or "",
                country_name=resp.country.name or "",
                continent=resp.continent.code or "",
                latitude=None,
                longitude=None
            )
            self._cache_geo[ip] = fact
            return fact
        except Exception:
            self._cache_geo[ip] = None
            return None

    def lookup_asn(self, ip: str) -> Optional[ASNFact]:
        if ip in self._cache_asn:
            return self._cache_asn[ip]
            
        if _is_private(ip):
            fact = ASNFact(ip=ip, asn="PRIVATE", organization="Private Network", organization_type="")
            self._cache_asn[ip] = fact
            return fact
            
        try:
            resp = self.asn_reader.asn(ip)
            fact = ASNFact(
                ip=ip,
                asn=str(resp.autonomous_system_number) if resp.autonomous_system_number else "",
                organization=resp.autonomous_system_organization or "",
                organization_type=""  # Not available in free GeoLite2 ASN
            )
            self._cache_asn[ip] = fact
            return fact
        except Exception:
            self._cache_asn[ip] = None
            return None
