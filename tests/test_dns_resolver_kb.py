import pytest
from pathlib import Path

from pcap.schemas import DNSResolverFact
from pcap.matchers.dns_resolver_matcher import DNSResolverMatcher
from pcap.network_context import NetworkContext
from pcap.connection_builder import ConnectionBuilder
from pcap.pcap_parser import RawEvent
from knowledge_base.dataset_manager import DatasetManager

def test_dns_resolver_matcher():
    resolvers = {
        "8.8.8.8": {
            "ip_address": "8.8.8.8",
            "provider": "Google",
            "resolver_name": "Google Public DNS",
            "provider_country": "US",
            "supports_doh": "true",
            "supports_dot": "true",
            "source_dataset": "PublicDNS",
            "source_version": "1.0"
        },
        "192.168.2.0/24": {
            "ip_address": "192.168.2.0/24",
            "provider": "MockProvider",
            "canonical_provider": "Community",
            "resolver_name": "Mock",
            "provider_country": "US",
            "supports_doh": "false",
            "supports_dot": "false",
            "supports_dnscrypt": "false",
            "source_dataset": "Mock",
            "source_version": "1.0",
            "confidence": "HIGH"
        },
        "8.8.8.8": {
            "ip_address": "8.8.8.8",
            "provider": "Google Public DNS",
            "canonical_provider": "Google",
            "resolver_name": "Google DNS",
            "provider_country": "US",
            "supports_doh": "true",
            "supports_dot": "true",
            "supports_dnscrypt": "false",
            "source_dataset": "Mock",
            "source_version": "1.0",
            "confidence": "HIGH"
        },
        "9.9.9.9": {
            "ip_address": "9.9.9.9",
            "provider": "Quad9",
            "canonical_provider": "Quad9",
            "resolver_name": "Quad9",
            "provider_country": "CH",
            "supports_doh": "true",
            "supports_dot": "true",
            "supports_dnscrypt": "true",
            "source_dataset": "dnscrypt",
            "source_version": "1.0",
            "confidence": "MEDIUM"
        }
    }
    
    matcher = DNSResolverMatcher(resolvers)
    fact = matcher.match("8.8.8.8")
    assert fact is not None
    assert fact.provider == "Google Public DNS"
    assert fact.canonical_provider == "Google"
    assert fact.confidence == "HIGH"
    
    q9 = matcher.match("9.9.9.9")
    assert q9 is not None
    assert q9.canonical_provider == "Quad9"
    assert q9.confidence == "MEDIUM"
    
    miss = matcher.match("192.168.1.1")
    assert miss is None
    
    # Test CIDR match
    cidr_match = matcher.match("192.168.2.10")
    assert cidr_match is not None
    assert cidr_match.provider == "MockProvider"

def test_dataset_manager_load_dns_resolvers():
    manager = DatasetManager()
    facts = manager.load_dns_resolvers()
    assert len(facts) > 0
    
    google_dns = next((f for f in facts if f.ip_address == "8.8.8.8"), None)
    assert google_dns is not None
    assert google_dns.provider == "Google"
    
def test_dnscrypt_importer():
    from knowledge_base.network.importers.dnscrypt_importer import DNSCryptResolverImporter
    p = Path("knowledge_base/raw/dns_resolvers/dnscrypt_resolvers.md")
    if p.exists():
        importer = DNSCryptResolverImporter(p)
        models = list(importer.process())
        assert len(models) > 0
        assert hasattr(models[0], "supports_dnscrypt")

def test_connection_builder_enrichment():
    resolvers = {
        "1.1.1.1": {
            "ip_address": "1.1.1.1",
            "provider": "Cloudflare",
            "resolver_name": "Cloudflare DNS",
            "provider_country": "US",
            "supports_doh": "true",
            "supports_dot": "true"
        }
    }
    
    matcher = DNSResolverMatcher(resolvers)
    context = NetworkContext(dns_resolver_matcher=matcher)
    builder = ConnectionBuilder(network_context=context)
    
    # 1. Test DNSRecord enrichment
    dns_event = RawEvent(
        timestamp=1.0,
        dns_query="example.com",
        dst_ip="1.1.1.1",
        dst_port=53,
        protocol="UDP",
        is_dns=True
    )
    result = builder.build([dns_event], "s1", "s1")
    dns_rec = result.dns_records[0]
    assert dns_rec.dns_resolver_fact is not None
    assert dns_rec.dns_resolver_fact.provider == "Cloudflare"

    # 2. Test ConnectionRecord DoH enrichment
    doh_event = RawEvent(
        timestamp=2.0,
        domain="cloudflare-dns.com",
        dst_ip="1.1.1.1",
        dst_port=443,
        protocol="TCP",
        is_tls=True
    )
    result = builder.build([doh_event], "s1", "s1")
    conn = result.connections[0]
    assert conn.dns_resolver_fact is not None
    assert conn.dns_resolver_fact.provider == "Cloudflare"
