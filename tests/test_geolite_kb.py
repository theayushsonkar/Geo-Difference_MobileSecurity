import pytest
from unittest.mock import MagicMock, patch
from pathlib import Path

from pcap.schemas import GeoFact, ASNFact
from pcap.matchers.geo_mapper import GeoMapper
from pcap.network_context import NetworkContext
from pcap.connection_builder import ConnectionBuilder, ConnectionRecord
from pcap.pcap_parser import RawEvent
from pcap.app_summary import AppSummaryBuilder
from knowledge_base.dataset_manager import DatasetManager

class MockCountryResponse:
    class _Country:
        def __init__(self):
            self.iso_code = "US"
            self.name = "United States"
    class _Continent:
        def __init__(self):
            self.code = "NA"
    class _Location:
        def __init__(self):
            self.latitude = 37.0
            self.longitude = -122.0
            
    def __init__(self):
        self.country = self._Country()
        self.continent = self._Continent()
        self.location = self._Location()

class MockASNResponse:
    def __init__(self):
        self.autonomous_system_number = 15169
        self.autonomous_system_organization = "Google LLC"

def test_geo_mapper_lookup():
    country_reader = MagicMock()
    country_reader.country.return_value = MockCountryResponse()
    
    asn_reader = MagicMock()
    asn_reader.asn.return_value = MockASNResponse()
    
    mapper = GeoMapper(country_reader, asn_reader)
    
    geo_fact = mapper.lookup_geo("8.8.8.8")
    assert geo_fact is not None
    assert geo_fact.country_code == "US"
    assert geo_fact.country_name == "United States"
    assert geo_fact.continent == "NA"
    assert geo_fact.latitude is None
    
    asn_fact = mapper.lookup_asn("8.8.8.8")
    assert asn_fact is not None
    assert asn_fact.asn == "15169"
    assert asn_fact.organization == "Google LLC"
    
    # Test private IP
    priv_geo = mapper.lookup_geo("192.168.1.1")
    assert priv_geo.country_code == "PRIVATE"
    
    priv_asn = mapper.lookup_asn("10.0.0.1")
    assert priv_asn.asn == "PRIVATE"

def test_dataset_manager_load_geolite():
    manager = DatasetManager()
    
    with patch("pathlib.Path.exists", return_value=True), \
         patch("geoip2.database.Reader") as mock_reader:
         
        mapper = manager.load_geolite()
        assert mapper is not None
        assert mapper.country_reader is not None
        assert mapper.asn_reader is not None

def test_connection_builder_enrichment():
    country_reader = MagicMock()
    country_reader.country.return_value = MockCountryResponse()
    asn_reader = MagicMock()
    asn_reader.asn.return_value = MockASNResponse()
    
    mapper = GeoMapper(country_reader, asn_reader)
    context = NetworkContext(geo_mapper=mapper)
    
    builder = ConnectionBuilder(network_context=context)
    
    events = [
        RawEvent(
            timestamp=1.0,
            domain="google.com",
            dst_ip="8.8.8.8",
            dst_port=443,
            protocol="TCP",
            is_tls=True
        )
    ]
    
    result = builder.build(events, "sample1", "sess1")
    conn = result.connections[0]
    
    assert conn.geo_fact is not None
    assert conn.geo_fact.country_code == "US"
    assert conn.geo_fact.continent == "NA"
    
    assert conn.asn_fact is not None
    assert conn.asn_fact.asn == "15169"
    assert conn.asn_fact.organization == "Google LLC"

def test_app_summary_aggregation():
    conn1 = ConnectionRecord(
        sample_id="s1", session_id="s1", domain="google.com",
        registered_domain="google.com", tld="com", subdomain="",
        dst_ip="8.8.8.8", dst_port=443, protocol="TCP", connection_count=5,
        payload_bytes_total=500, first_seen=1.0, last_seen=2.0,
        tracker_matched=False, sdk_name="", sdk_vendor_country="",
        sdk_category="", canonical_vendor="",
        is_quic=False, is_tls=True, is_dns=False, is_http=False,
        is_nonstandard_port=False, is_hardcoded_dns=False, is_anti_analysis_probe=False,
        geo_fact=GeoFact(ip="8.8.8.8", country_code="US", country_name="United States", continent="NA"),
        asn_fact=ASNFact(ip="8.8.8.8", asn="15169", organization="Google LLC", organization_type="")
    )
    
    builder = AppSummaryBuilder()
    summary = builder.build([conn1], [], [])
    
    assert summary.unique_destination_countries == 1
    assert summary.destination_country_distribution == {"US": 1}
    assert summary.destination_continent_distribution == {"NA": 1}
    assert summary.unique_destination_asns == 1
    assert summary.destination_asn_distribution == {"15169": 1}
    assert summary.top_organizations == ["Google LLC"]
