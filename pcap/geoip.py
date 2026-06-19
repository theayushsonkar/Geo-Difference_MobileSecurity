"""
geoip.py
--------
IP-to-country and IP-to-ASN lookup.

Backend priority:
  1. MaxMind GeoLite2  (local, fast, requires free registration)
     Download from: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
     Files needed: GeoLite2-Country.mmdb, GeoLite2-ASN.mmdb
     Place in:     data/geoip/

  2. ip-api.com        (free API, no key, 45 req/min)
     Used automatically when MaxMind DB is absent.

Both backends are cached in memory during a run.
"""

import json
import time
import urllib.request
import urllib.parse
import urllib.error
from pathlib import Path
from typing import Optional

# MaxMind optional import
try:
    import geoip2.database
    import geoip2.errors
    _GEOIP2_AVAILABLE = True
except ImportError:
    _GEOIP2_AVAILABLE = False


# ─────────────────────────────────────────────────────────────────────────────
# PRIVATE IP RANGES  (skip these — no geo lookup needed)
# ─────────────────────────────────────────────────────────────────────────────

def _is_private(ip: str) -> bool:
    if not ip or ":" in ip:  # skip IPv6 for now
        return True
    try:
        parts = [int(x) for x in ip.split(".")]
        if len(parts) != 4:
            return True
        a, b = parts[0], parts[1]
        return (
            a == 10 or
            a == 127 or
            (a == 172 and 16 <= b <= 31) or
            (a == 192 and b == 168) or
            (a == 169 and b == 254)
        )
    except (ValueError, IndexError):
        return True


# ─────────────────────────────────────────────────────────────────────────────
# RESULT TYPE
# ─────────────────────────────────────────────────────────────────────────────

class GeoResult:
    __slots__ = ("country_code", "country_name", "asn", "asn_org", "source")

    def __init__(
        self,
        country_code: str = "",
        country_name: str = "",
        asn: str = "",
        asn_org: str = "",
        source: str = "",
    ):
        self.country_code = country_code
        self.country_name = country_name
        self.asn          = asn
        self.asn_org      = asn_org
        self.source       = source

    def is_empty(self) -> bool:
        return not self.country_code

    def __repr__(self):
        return (f"GeoResult(cc={self.country_code!r}, "
                f"asn_org={self.asn_org!r}, src={self.source!r})")


EMPTY_GEO = GeoResult(country_code="XX", country_name="Unknown",
                      asn="", asn_org="", source="unknown")


# ─────────────────────────────────────────────────────────────────────────────
# MAXMIND BACKEND
# ─────────────────────────────────────────────────────────────────────────────

class MaxMindBackend:
    def __init__(self, country_db: Path, asn_db: Optional[Path] = None):
        if not _GEOIP2_AVAILABLE:
            raise RuntimeError("geoip2 not installed: pip install geoip2")
        self._country_reader = geoip2.database.Reader(str(country_db))
        self._asn_reader = (
            geoip2.database.Reader(str(asn_db)) if asn_db and asn_db.exists() else None
        )
        self.version = country_db.stem   # e.g. "GeoLite2-Country"

    def lookup(self, ip: str) -> GeoResult:
        try:
            resp = self._country_reader.country(ip)
            country_code = resp.country.iso_code or ""
            country_name = resp.country.name or ""
        except Exception:
            country_code, country_name = "", ""

        asn, asn_org = "", ""
        if self._asn_reader:
            try:
                asn_resp = self._asn_reader.asn(ip)
                asn     = str(asn_resp.autonomous_system_number or "")
                asn_org = asn_resp.autonomous_system_organization or ""
            except Exception:
                pass

        return GeoResult(
            country_code=country_code,
            country_name=country_name,
            asn=asn,
            asn_org=asn_org,
            source="maxmind",
        )

    def close(self):
        self._country_reader.close()
        if self._asn_reader:
            self._asn_reader.close()


# ─────────────────────────────────────────────────────────────────────────────
# IP-API.COM BACKEND
# ─────────────────────────────────────────────────────────────────────────────

class IPAPIBackend:
    """
    Free tier: 45 req/min for single lookups, 100 IPs per batch.
    No API key required.
    """
    BATCH_URL = "http://ip-api.com/batch"
    FIELDS    = "status,country,countryCode,org,as,query"
    DELAY_SEC = 1.5   # conservative: 40 req/min

    def __init__(self):
        self.version = "ip-api.com"

    def lookup_batch(self, ips: list[str]) -> dict[str, GeoResult]:
        results: dict[str, GeoResult] = {}
        public = [ip for ip in ips if not _is_private(ip)]

        for i in range(0, len(public), 100):
            batch = public[i:i + 100]
            payload = json.dumps(
                [{"query": ip, "fields": self.FIELDS} for ip in batch]
            ).encode()
            try:
                req = urllib.request.Request(
                    self.BATCH_URL,
                    data=payload,
                    headers={"Content-Type": "application/json"},
                )
                with urllib.request.urlopen(req, timeout=15) as resp:
                    data = json.loads(resp.read())
                for entry in data:
                    ip = entry.get("query", "")
                    if entry.get("status") == "success":
                        results[ip] = GeoResult(
                            country_code=entry.get("countryCode", ""),
                            country_name=entry.get("country", ""),
                            asn=entry.get("as", ""),
                            asn_org=entry.get("org", ""),
                            source="ip-api",
                        )
                    else:
                        results[ip] = EMPTY_GEO
                time.sleep(self.DELAY_SEC)
            except Exception as e:
                print(f"  [GEOIP] ip-api batch failed: {e}")
                for ip in batch:
                    results[ip] = EMPTY_GEO

        # private IPs
        for ip in ips:
            if _is_private(ip):
                results[ip] = GeoResult(
                    country_code="PRIVATE", country_name="Private/Local",
                    source="private"
                )
        return results


# ─────────────────────────────────────────────────────────────────────────────
# UNIFIED GEO MAPPER  (used by the rest of the pipeline)
# ─────────────────────────────────────────────────────────────────────────────

class GeoMapper:
    """
    Auto-selects MaxMind (if DBs present) or ip-api.com.
    Maintains an in-memory cache so each IP is only looked up once per run.
    """

    GEOIP_DB_DIR_DEFAULT = Path("data") / "geoip"

    def __init__(self, db_dir: Optional[Path] = None):
        self._cache: dict[str, GeoResult] = {}
        self._backend = None
        self.db_version = "ip-api.com"

        db_dir = db_dir or self.GEOIP_DB_DIR_DEFAULT
        country_db = db_dir / "GeoLite2-Country.mmdb"
        asn_db     = db_dir / "GeoLite2-ASN.mmdb"

        if _GEOIP2_AVAILABLE and country_db.exists():
            try:
                self._backend = MaxMindBackend(
                    country_db,
                    asn_db if asn_db.exists() else None,
                )
                self.db_version = f"MaxMind/{country_db.stat().st_mtime:.0f}"
                print(f"  [GEOIP] Using MaxMind GeoLite2 from {db_dir}")
            except Exception as e:
                print(f"  [GEOIP] MaxMind init failed ({e}) — falling back to ip-api.com")
                self._backend = None

        if self._backend is None:
            print(f"  [GEOIP] Using ip-api.com (free tier, rate-limited)")
            self.db_version = "ip-api.com"

    def lookup(self, ip: str) -> GeoResult:
        if ip in self._cache:
            return self._cache[ip]
        if _is_private(ip):
            result = GeoResult(country_code="PRIVATE",
                               country_name="Private/Local", source="private")
            self._cache[ip] = result
            return result
        if self._backend:
            result = self._backend.lookup(ip)
        else:
            # Single lookup via ip-api
            result = self._lookup_single_ipapi(ip)
        self._cache[ip] = result
        return result

    def lookup_batch(self, ips: list[str]) -> dict[str, GeoResult]:
        """Look up multiple IPs, using cache where possible."""
        uncached = [ip for ip in ips if ip not in self._cache and not _is_private(ip)]

        if uncached:
            if self._backend:
                for ip in uncached:
                    self._cache[ip] = self._backend.lookup(ip)
            else:
                batch_results = IPAPIBackend().lookup_batch(uncached)
                self._cache.update(batch_results)

        # Fill privates
        for ip in ips:
            if _is_private(ip) and ip not in self._cache:
                self._cache[ip] = GeoResult(
                    country_code="PRIVATE",
                    country_name="Private/Local",
                    source="private",
                )

        return {ip: self._cache.get(ip, EMPTY_GEO) for ip in ips}

    def _lookup_single_ipapi(self, ip: str) -> GeoResult:
        url = f"http://ip-api.com/json/{ip}?fields={IPAPIBackend.FIELDS}"
        try:
            with urllib.request.urlopen(url, timeout=10) as resp:
                data = json.loads(resp.read())
            if data.get("status") == "success":
                return GeoResult(
                    country_code=data.get("countryCode", ""),
                    country_name=data.get("country", ""),
                    asn=data.get("as", ""),
                    asn_org=data.get("org", ""),
                    source="ip-api",
                )
        except Exception:
            pass
        return EMPTY_GEO

    def close(self):
        if self._backend and hasattr(self._backend, "close"):
            self._backend.close()
