import os
import sys
import time
import tracemalloc
import datetime
from pathlib import Path
from pprint import pprint

workspace_dir = Path(r"d:\New folder\Geo-Difference_MobileSecurity")
sys.path.append(str(workspace_dir))

from knowledge_base.dataset_manager import DatasetManager
from pcap.pcap_parser import RawEvent
from pcap.connection_builder import ConnectionBuilder
from pcap.network_context import NetworkContext
from pcap.app_summary import AppSummaryBuilder

print("="*60)
print("1. Dataset Verification")
print("="*60)

import geoip2.database

geolite_dir = workspace_dir / "knowledge_base" / "raw" / "geolite2"
country_db = geolite_dir / "GeoLite2-Country.mmdb"
asn_db = geolite_dir / "GeoLite2-ASN.mmdb"

for db_path in [country_db, asn_db]:
    if db_path.exists():
        stat = db_path.stat()
        print(f"File: {db_path.name}")
        print(f"Absolute Path: {db_path.resolve()}")
        print(f"File Size: {stat.st_size / (1024*1024):.2f} MB")
        print(f"Last Modified: {datetime.datetime.fromtimestamp(stat.st_mtime)}")
        try:
            with geoip2.database.Reader(str(db_path)) as reader:
                meta = reader.metadata()
                build_epoch = meta.build_epoch
                print(f"Database Build Date: {datetime.datetime.fromtimestamp(build_epoch)}")
                print(f"Database Type: {meta.database_type}")
                print(f"Description: {meta.description.get('en', '')}")
                print(f"IP Version: {meta.ip_version}")
        except Exception as e:
            print(f"Error reading metadata: {e}")
    else:
        print(f"File not found: {db_path}")
    print("-" * 30)

print("\n" + "="*60)
print("3. Runtime Lookup Verification")
print("="*60)

manager = DatasetManager()
geo_mapper = manager.load_geolite()

ips_to_test = [
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "9.9.9.9",
    "208.67.222.222",
    "114.114.114.114",
    "223.5.5.5"
]

for ip in ips_to_test:
    print(f"\nIP: {ip}")
    geo = geo_mapper.lookup_geo(ip)
    asn = geo_mapper.lookup_asn(ip)
    if geo:
        print(f"  Country Code: {geo.country_code}")
        print(f"  Country Name: {geo.country_name}")
        print(f"  Continent: {geo.continent}")
    if asn:
        print(f"  ASN Number: {asn.asn}")
        print(f"  Organization: {asn.organization}")

print("\n" + "="*60)
print("6. Failure Handling")
print("="*60)

failure_ips = [
    ("Unknown IP", "192.0.2.1"), # TEST-NET-1
    ("Private IP", "192.168.1.1"),
    ("Loopback IP", "127.0.0.1"),
    ("Multicast IP", "224.0.0.1"),
    ("IPv6 Address", "2001:4860:4860::8888"),
]

for label, ip in failure_ips:
    print(f"\n{label}: {ip}")
    try:
        geo = geo_mapper.lookup_geo(ip)
        print(f"  GeoFact: {geo}")
    except Exception as e:
        print(f"  Geo Error: {e}")
        
    try:
        asn = geo_mapper.lookup_asn(ip)
        print(f"  ASNFact: {asn}")
    except Exception as e:
        print(f"  ASN Error: {e}")

print("\n" + "="*60)
print("7. Performance Verification")
print("="*60)

# Initialization Time
t0 = time.perf_counter()
test_mapper = manager.load_geolite()
t1 = time.perf_counter()
print(f"Dataset initialization time: {(t1-t0)*1000:.2f} ms")

# Lookup Latency & Peak Memory
tracemalloc.start()
t0 = time.perf_counter()
iterations = 10000
for _ in range(iterations):
    test_mapper.lookup_geo("8.8.8.8")
    test_mapper.lookup_asn("8.8.8.8")
t1 = time.perf_counter()
current, peak = tracemalloc.get_traced_memory()
tracemalloc.stop()

print(f"Average Geo+ASN lookup latency: {((t1-t0)/iterations)*1000:.3f} ms / ip ({(t1-t0):.2f}s for {iterations} lookups)")
print(f"Peak memory usage during 10k lookups: {peak / (1024*1024):.2f} MB")
