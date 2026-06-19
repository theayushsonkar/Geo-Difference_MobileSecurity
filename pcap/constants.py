TRACKER_DOMAINS: dict[str, tuple[str, str, str]] = {
    # ── Chinese SDKs ────────────────────────────────────────────────────────
    "pangle.io":                ("ByteDance/Pangle",     "CN", "ad_network"),
    "tiktokpangle.us":          ("ByteDance/Pangle",     "CN", "ad_network"),
    "pglstatp.com":             ("ByteDance CDN",        "CN", "cdn"),
    "tiktokpangle-cdn-us.com":  ("ByteDance CDN",        "CN", "cdn"),
    "i18n-pglstatp.com":        ("ByteDance CDN",        "CN", "cdn"),
    "byteoversea.com":          ("ByteDance",            "CN", "ad_network"),
    "bytedance.com":            ("ByteDance",            "CN", "ad_network"),
    "mtgglobals.com":           ("Mintegral",            "CN", "ad_network"),
    "mbridge.com":              ("Mintegral",            "CN", "ad_network"),
    "rayjump.com":              ("Mintegral",            "CN", "ad_network"),
    "mintegral.com":            ("Mintegral",            "CN", "ad_network"),

    # ── US Ad Networks ───────────────────────────────────────────────────────
    "applovin.com":             ("AppLovin",             "US", "ad_mediation"),
    "applvn.com":               ("AppLovin CDN",         "US", "cdn"),
    "ms4.applvn.com":           ("AppLovin CDN",         "US", "cdn"),
    "vungle.com":               ("Vungle/Liftoff",       "US", "ad_network"),
    "ads.vungle.com":           ("Vungle Ads",           "US", "ad_network"),
    "logs.ads.vungle.com":      ("Vungle Metrics",       "US", "analytics"),
    "liftoff.io":               ("Liftoff",              "US", "ad_network"),
    "adsmoloco.com":            ("Moloco",               "US", "ad_exchange"),
    "dsp-api.moloco.com":       ("Moloco DSP",           "US", "ad_exchange"),
    "bidmachine.io":            ("BidMachine",           "US", "ad_exchange"),
    "doubleclick.net":          ("Google DV360",         "US", "ad_exchange"),
    "googlesyndication.com":    ("Google Ads",           "US", "ad_network"),
    "googleadservices.com":     ("Google Ads",           "US", "ad_network"),
    "googleads.g.doubleclick.net": ("Google Ads",        "US", "ad_network"),
    "pagead2.googlesyndication.com": ("Google Ads",      "US", "ad_network"),
    "amazon-adsystem.com":      ("Amazon APS",           "US", "ad_exchange"),
    "aax-eu.amazon-adsystem.com": ("Amazon APS EU",      "US", "ad_exchange"),
    "a9.com":                   ("Amazon A9",            "US", "ad_exchange"),
    "adsqtungsten.a9.amazon.dev": ("Amazon Tungsten",    "US", "ad_exchange"),
    "bidswitch.net":            ("BidSwitch RTB",        "US", "ad_exchange"),
    "doubleverify.com":         ("DoubleVerify",         "US", "ad_measurement"),
    "moatads.com":              ("Oracle Moat",          "US", "ad_measurement"),
    "chartboost.com":           ("Chartboost",           "US", "ad_network"),
    "mobilefuse.com":           ("MobileFuse",           "US", "ad_network"),
    "ogury.com":                ("Ogury",                "FR", "ad_network"),
    "presage.io":               ("Presage",              "US", "analytics"),

    # ── Indian Ad Networks ──────────────────────────────────────────────────
    "inmobi.com":               ("InMobi",               "IN", "ad_network"),
    "inmobicdn.net":            ("InMobi CDN",           "IN", "cdn"),
    "supply.inmobicdn.net":     ("InMobi Supply",        "IN", "ad_exchange"),
    "telemetry.sdk.inmobi.com": ("InMobi Telemetry",     "IN", "analytics"),

    # ── European Ad Networks ────────────────────────────────────────────────
    "ironsource.com":           ("IronSource",           "IL", "ad_mediation"),
    "pubnative.net":            ("PubNative/HyBid",      "DE", "ad_exchange"),
    "fyber.com":                ("Fyber",                "DE", "ad_network"),
    "inner-active.mobi":        ("InnerActive",          "DE", "ad_network"),
    "wv.inner-active.mobi":     ("InnerActive WV",       "DE", "ad_network"),
    "smaato.com":               ("Smaato",               "DE", "ad_exchange"),
    "smaato.net":               ("Smaato",               "DE", "ad_exchange"),
    "sdk-files.smaato.net":     ("Smaato SDK Files",     "DE", "cdn"),

    # ── Attribution / Analytics ─────────────────────────────────────────────
    "adjust.com":               ("Adjust",               "DE", "attribution"),
    "adjust.io":                ("Adjust",               "DE", "attribution"),
    "app.adjust.com":           ("Adjust",               "DE", "attribution"),
    "appsflyer.com":            ("AppsFlyer",            "IL", "attribution"),
    "singular.net":             ("Singular",             "US", "attribution"),
    "epsilon.com":              ("Epsilon (data broker)", "US", "data_broker"),
    "branch.io":                ("Branch",               "US", "attribution"),
    "kochava.com":              ("Kochava",              "US", "attribution"),

    # ── Google / Firebase ───────────────────────────────────────────────────
    "firebase.io":              ("Firebase",             "US", "analytics"),
    "firebaseio.com":           ("Firebase RTDB",        "US", "analytics"),
    "firebaseapp.com":          ("Firebase Hosting",     "US", "analytics"),
    "crashlytics.com":          ("Crashlytics",          "US", "crash_reporting"),
    "firebase.google.com":      ("Firebase",             "US", "analytics"),
    "fcm.googleapis.com":       ("Firebase FCM",         "US", "push_notifications"),

    # ── Facebook / Meta ─────────────────────────────────────────────────────
    "facebook.com":             ("Facebook",             "US", "social_analytics"),
    "facebook.net":             ("Facebook CDN",         "US", "cdn"),
    "graph.facebook.com":       ("Facebook Graph API",   "US", "social_analytics"),
    "adnw_sync2":               ("Facebook Ad Sync",     "US", "ad_network"),

    # ── Data Brokers ────────────────────────────────────────────────────────
    "acxiom.com":               ("Acxiom",               "US", "data_broker"),
    "experian.com":             ("Experian",             "US", "data_broker"),
}

# ─────────────────────────────────────────────────────────────────────────────
# HARDCODED DNS RESOLVERS  (bypasses system DNS)
# ─────────────────────────────────────────────────────────────────────────────
HARDCODED_DNS_RESOLVERS: set[str] = {
    "8.8.8.8",          # Google Public DNS
    "8.8.4.4",          # Google Public DNS secondary
    "1.1.1.1",          # Cloudflare
    "1.0.0.1",          # Cloudflare secondary
    "9.9.9.9",          # Quad9
    "208.67.222.222",   # OpenDNS
    "208.67.220.220",   # OpenDNS secondary
    "4.2.2.1",          # Level3
    "4.2.2.2",          # Level3 secondary
}

# ─────────────────────────────────────────────────────────────────────────────
# ANTI-ANALYSIS PROBE DOMAINS
# These are queried to detect MITM/proxy environments.
# ─────────────────────────────────────────────────────────────────────────────
ANTI_ANALYSIS_DOMAINS: set[str] = {
    "example.com",
    "example.org",
    "example.net",
    "detectportal.firefox.com",
    "connectivity-check.ubuntu.com",
    "connectivitycheck.gstatic.com",
    "clients3.google.com",
    "www.google.com/generate_204",
    "captive.apple.com",
}

# ─────────────────────────────────────────────────────────────────────────────
# PII PATTERNS
# Applied to request bodies (from Burpsuite XML decoded content).
# Format: pii_type → list of regex patterns
# ─────────────────────────────────────────────────────────────────────────────
PII_PATTERNS: dict[str, list[str]] = {
    "GAID": [
        r'"gaid"\s*:\s*"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"',
        r'gps_adid=([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})',
        r'advertising_id=([0-9a-f-]{36})',
        r'"adid"\s*:\s*"([0-9a-f-]{36})"',
        r'"gaid2?"\s*:\s*"([0-9a-f-]{36})"',
    ],
    "Android_ID": [
        r'"android_id"\s*:\s*"([a-f0-9]{16})"',
        r'android_id=([a-f0-9]{16})',
        r'"androidId"\s*:\s*"([a-f0-9]{16})"',
    ],
    "Device_Model": [
        r'"model"\s*:\s*"(SM-[A-Z0-9]+[A-Z]?)"',
        r'"device"\s*:\s*"(SM-[A-Z0-9]+)"',
        r'SM-[A-Z][0-9]{3,4}[A-Z]?',
        r'"make"\s*:\s*"(samsung|xiaomi|oppo|vivo|realme|oneplus|motorola)"',
        r'"manufacturer"\s*:\s*"(samsung|xiaomi|oppo|vivo|realme)"',
    ],
    "OS_Version": [
        r'"os_version"\s*:\s*"?(\d{1,2})"?',
        r'"api_level"\s*:\s*(\d{2})',
        r'Android/(\d{1,2})',
        r'"osv"\s*:\s*"?(\d{1,2})"?',
    ],
    "App_Version": [
        r'"app_version"\s*:\s*"([\d.]+)"',
        r'app_version=([\d.]+)',
        r'"appVersion"\s*:\s*"([\d.]+)"',
        r'"version_name"\s*:\s*"([\d.]+)"',
    ],
    "Device_UUID": [
        r'"did"\s*:\s*"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"',
        r'"device_id"\s*:\s*"([0-9a-f-]{36})"',
        r'"uuid"\s*:\s*"([0-9a-f-]{36})"',
        r'"deviceId"\s*:\s*"([0-9a-f-]{36})"',
        r'"idfv"\s*:\s*"([0-9a-f-]{36})"',
    ],
    "Build_Fingerprint": [
        r'TP1A\.\d{6}\.\d{3}',
        r'SP1A\.\d{6}\.\d{3}',
        r'"build_id"\s*:\s*"([A-Z0-9.]+)"',
        r'"fingerprint"\s*:\s*"([^"]{20,})"',
    ],
    "Timezone": [
        r'timezone=([A-Z]{2,3}%2B\d+%3A\d+)',
        r'timezone=(GMT[%+][^&"]{3,6})',
        r'"timezone"\s*:\s*"([^"]{3,15})"',
        r'"tz"\s*:\s*"([^"]{3,15})"',
    ],
    "Network_Type": [
        r'"network_type"\s*:\s*"(WIFI|LTE|5G|4G|3G|2G)"',
        r'"connection_type"\s*:\s*"(wifi|cellular|unknown)"',
        r'"carrier"\s*:\s*"([^"]{3,30})"',
        r'"operator"\s*:\s*"([^"]{3,20})"',
    ],
    "IP_Address": [
        r'"ip"\s*:\s*"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"',
        r'"client_ip"\s*:\s*"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"',
        r'"userip"\s*:\s*"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"',
    ],
    "Location": [
        r'"lat(?:itude)?"\s*:\s*([-+]?\d{1,2}\.\d+)',
        r'"lon(?:gitude|g)?"\s*:\s*([-+]?\d{1,3}\.\d+)',
        r'"location"\s*:\s*\{[^}]{10,}',
        r'lat=(-?\d+\.\d+)',
        r'lon=(-?\d+\.\d+)',
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
# HIGH RISK COUNTRIES (data sovereignty perspective for India)
# ─────────────────────────────────────────────────────────────────────────────
HIGH_RISK_COUNTRIES: set[str] = {"CN", "RU", "IR", "KP"}

# ─────────────────────────────────────────────────────────────────────────────
# CHINESE CLOUD PROVIDERS (ASN org names to match)
# ─────────────────────────────────────────────────────────────────────────────
CHINESE_CLOUD_ORGS: set[str] = {
    "alibaba", "aliyun", "tencent", "huawei", "china telecom",
    "china unicom", "china mobile", "ucloud", "qcloud", "qiniu",
    "baidu", "jdcloud", "kingsoft", "ctyun",
}

# ─────────────────────────────────────────────────────────────────────────────
# KNOWN DoH (DNS-over-HTTPS) RESOLVERS
# ─────────────────────────────────────────────────────────────────────────────
DOH_DOMAINS: set[str] = {
    "dns.google", "dns.cloudflare.com", "cloudflare-dns.com",
    "doh.opendns.com", "doh.xfinity.com", "mozilla.cloudflare-dns.com",
}

# ─────────────────────────────────────────────────────────────────────────────
# STANDARD PORTS  (anything else = non-standard)
# ─────────────────────────────────────────────────────────────────────────────
STANDARD_PORTS: set[str] = {
    "80", "443", "53", "8080", "8443", "8008",
}

# ─────────────────────────────────────────────────────────────────────────────
# LARGE DOWNLOAD THRESHOLD (bytes)
# ─────────────────────────────────────────────────────────────────────────────
LARGE_DOWNLOAD_THRESHOLD_BYTES: int = 1_000_000   # 1 MB

# ─────────────────────────────────────────────────────────────────────────────
# RTB AUCTION WINDOW (milliseconds)
# Connections within this window are considered part of the same auction.
# ─────────────────────────────────────────────────────────────────────────────
RTB_WINDOW_MS: int = 500