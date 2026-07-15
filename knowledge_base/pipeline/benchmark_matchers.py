import time
import tracemalloc
from knowledge_base.pipeline.matcher_factory import MatcherFactory

def benchmark_matchers():
    print("Benchmarking Unified Matcher Framework...")
    
    # 1. Initialization Performance
    tracemalloc.start()
    t0 = time.time()
    MatcherFactory.initialize()
    init_time = time.time() - t0
    _, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    
    peak_mem_mb = peak_mem / 1024 / 1024
    print(f"Factory Initialization Time: {init_time:.4f}s")
    print(f"Factory Peak Memory Usage: {peak_mem_mb:.2f} MiB")
    
    # 2. Search Performance
    factory = MatcherFactory()
    privacy = factory.privacy()
    secret = factory.secret()
    geo = factory.geo()
    
    sample_text = """
    Ljava/util/Locale;->getCountry()Ljava/lang/String;
    Landroid/location/Location;->getLatitude()D
    AIzaSyB-abcdefghijklmnopqrstuvwx_yZ1234
    https://my-app.firebaseio.com/
    Landroid/telephony/TelephonyManager;->getDeviceId()Ljava/lang/String;
    Landroid/net/wifi/WifiInfo;->getMacAddress()Ljava/lang/String;
    """
    
    # Pre-warm
    privacy.search(sample_text)
    secret.search(sample_text)
    geo.search(sample_text)
    
    iterations = 1000
    
    t0 = time.time()
    priv_count = sum(len(privacy.search(sample_text)) for _ in range(iterations))
    t_priv = time.time() - t0
    
    t0 = time.time()
    sec_count = sum(len(secret.search(sample_text)) for _ in range(iterations))
    t_sec = time.time() - t0
    
    t0 = time.time()
    geo_count = sum(len(geo.search(sample_text)) for _ in range(iterations))
    t_geo = time.time() - t0
    
    print("\nSearch Performance (1000 iterations):")
    print(f" - Privacy Matcher: {t_priv:.4f}s | Findings: {priv_count}")
    print(f" - Secret Matcher: {t_sec:.4f}s | Findings: {sec_count}")
    print(f" - Geo Matcher: {t_geo:.4f}s | Findings: {geo_count}")

if __name__ == "__main__":
    benchmark_matchers()
