import json
import tempfile
from pathlib import Path
import pytest

from knowledge_base.network.schemas.kb_schemas import NormalizedTracker
from knowledge_base.network.importers.tracker_importer import ExodusTrackerImporter
from knowledge_base.network.builders.tracker_builder import TrackerBuilder
from knowledge_base.dataset_manager import DatasetManager
from pcap.schemas import TrackerFact
from pcap.matchers.suffix_matcher import SuffixMatcher
from pcap.matchers.tracker_matcher import TrackerMatcher
from pcap.network_context import NetworkContext
from pcap.connection_builder import ConnectionBuilder, ConnectionRecord
from pcap.pcap_parser import RawEvent
from pcap.app_summary import AppSummaryBuilder
from knowledge_base.network.importers.easyprivacy_importer import EasyPrivacyImporter

def test_suffix_matcher():
    matcher = SuffixMatcher()
    matcher.insert("vungle.com", "vungle.com")
    matcher.insert("branch.io", "branch.io")
    matcher.insert("doubleclick.net", "doubleclick.net")
    
    assert matcher.match("ads.vungle.com") == "vungle.com"
    assert matcher.match("sdk.api.branch.io") == "branch.io"
    assert matcher.match("sub.doubleclick.net") == "doubleclick.net"
    assert matcher.match("google.com") is None

def test_tracker_builder():
    with tempfile.TemporaryDirectory() as tmpdir:
        base_dir = Path(tmpdir)
        raw_dir = base_dir / "raw"
        processed_dir = base_dir / "processed"
        metadata_dir = base_dir / "metadata"
        
        exodus_dir = raw_dir / "exodus"
        exodus_dir.mkdir(parents=True)
        ep_dir = raw_dir / "easyprivacy"
        ep_dir.mkdir(parents=True)
        
        # Mock raw data
        mock_exodus = {
            "trackers": {
                "1": {
                    "name": "Google Ads",
                    "network_signature": "doubleclick.net|conflict.com",
                    "categories": ["Advertising"]
                }
            }
        }
        with open(exodus_dir / "trackers.json", "w") as f:
            json.dump(mock_exodus, f)
            
        mock_ep = "! Version: 202607171607\n||conflict.com^\n||eponly.com^$third-party"
        with open(ep_dir / "easyprivacy.txt", "w") as f:
            f.write(mock_ep)
            
        builder = TrackerBuilder(raw_dir, processed_dir, metadata_dir)
        builder.build()
        
        assert (processed_dir / "trackers.csv").exists()
        assert (processed_dir / ".stats_tracker.json").exists()
        assert (metadata_dir / "metadata.json").exists()
        
        # Check conflict resolution (conflict.com should take Exodus metadata)
        # Check eponly.com (should be from EasyPrivacy)
        import csv
        with open(processed_dir / "trackers.csv", "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = {row['domain_suffix']: row for row in reader}
            
        assert rows["conflict.com"]["vendor"] == "Google Ads"
        assert rows["conflict.com"]["category"] == "Advertising"
        assert "EasyPrivacy" in rows["conflict.com"]["source_dataset"] or "Exodus" in rows["conflict.com"]["source_dataset"]
        
        assert rows["eponly.com"]["source_dataset"] == "EasyPrivacy"
        assert rows["eponly.com"]["source_version"] == "202607171607"
            
        # Check stats
        with open(processed_dir / ".stats_tracker.json", "r") as f:
            stats = json.load(f)
            assert stats["raw_rows_per_dataset"]["Exodus"] == 2
            assert stats["raw_rows_per_dataset"]["EasyPrivacy"] == 2
            assert stats["conflicts_resolved"] == 1
            assert stats["unique_domains"] == 3
        
        # Check provenance
        with open(metadata_dir / "metadata.json", "r") as f:
            meta = json.load(f)
            assert "trackers" in meta
            assert "datasets" in meta["trackers"]
            assert meta["trackers"]["datasets"]["EasyPrivacy"]["version"] == "202607171607"
            assert meta["trackers"]["sha256"] is not None

def test_easyprivacy_importer():
    with tempfile.TemporaryDirectory() as tmpdir:
        raw_path = Path(tmpdir) / "easyprivacy.txt"
        with open(raw_path, "w") as f:
            f.write("! Version: 12345\n||test.com^\n##cosmetic\n||path.com/foo^")
            
        importer = EasyPrivacyImporter(raw_path)
        models = list(importer.process())
        assert len(models) == 1
        assert models[0].domain_suffix == "test.com"
        assert models[0].source_version == "12345"


def test_tracker_matcher():
    facts = [
        TrackerFact(
            domain_suffix="doubleclick.net",
            vendor="Google Ads",
            canonical_vendor="Google",
            category="Advertising",
            source_dataset="Exodus",
            source_version=""
        )
    ]
    matcher = TrackerMatcher(facts)
    match = matcher.match("ad.doubleclick.net")
    assert match is not None
    assert match.canonical_vendor == "Google"

def test_connection_builder_enrichment():
    facts = [
        TrackerFact(
            domain_suffix="doubleclick.net",
            vendor="Google Ads",
            canonical_vendor="Google",
            category="Advertising",
            source_dataset="Exodus",
            source_version=""
        )
    ]
    matcher = TrackerMatcher(facts)
    context = NetworkContext(tracker_matcher=matcher)
    
    # Mock geo mapper
    class MockGeoMapper:
        def __init__(self):
            self.db_version = "mock"
            self._cache = {}
        def lookup_geo(self, ip):
            from pcap.schemas import GeoFact
            return GeoFact(ip=ip, country_code='US', country_name='United States', continent='NA')
        def lookup_asn(self, ip):
            from pcap.schemas import ASNFact
            return ASNFact(ip=ip, asn='15169', organization='Google LLC', organization_type='')

    builder = ConnectionBuilder(geo_mapper=MockGeoMapper(), network_context=context)
    
    events = [
        RawEvent(
            timestamp=1.0,
            domain="ad.doubleclick.net",
            dst_ip="8.8.8.8",
            dst_port=443,
            protocol="TCP",
            is_tls=True
        )
    ]
    
    result = builder.build(events, "sample1", "sess1")
    conn = result.connections[0]
    
    assert conn.tracker_matched is True
    assert conn.sdk_name == "Google Ads"
    assert conn.canonical_vendor == "Google"
    assert conn.tracker_fact is not None
    assert conn.tracker_fact.category == "Advertising"

def test_app_summary_aggregation():
    conn1 = ConnectionRecord(
        sample_id="s1", session_id="s1", domain="ad.doubleclick.net",
        registered_domain="doubleclick.net", tld="net", subdomain="ad",
        dst_ip="8.8.8.8", dst_port=443, protocol="TCP", connection_count=5,
        payload_bytes_total=500, first_seen=1.0, last_seen=2.0,
        tracker_matched=True, sdk_name="Google Ads", sdk_vendor_country="",
        sdk_category="Advertising", canonical_vendor="Google",
        is_quic=False, is_tls=True, is_dns=False, is_http=False,
        is_nonstandard_port=False, is_hardcoded_dns=False, is_anti_analysis_probe=False,
        tracker_fact=TrackerFact(
            domain_suffix="doubleclick.net", vendor="Google", canonical_vendor="Google",
            category="Advertising", source_dataset="Exodus", source_version="1.0"
        ),
        geo_fact=None, asn_fact=None
    )
    
    builder = AppSummaryBuilder()
    summary = builder.build([conn1], [], [])
    
    assert summary.tracker_domain_count == 1
    assert summary.top_tracker_vendor == "Google"
    assert summary.tracker_vendor_distribution == {"Google": 1}
    assert summary.tracker_category_distribution == {"Advertising": 5}
    assert summary.tracker_diversity == 1
    assert "Google" in summary.top_tracker_vendors
