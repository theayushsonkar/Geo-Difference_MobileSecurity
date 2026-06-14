"""

All constants, region maps, permission families, SDK database,
secret patterns, and related lookup tables.

"""

from typing import Dict, Set, Tuple

# ═══════════════════════════════════════════════════════════════════════════════
# VERSIONING
# ═══════════════════════════════════════════════════════════════════════════════
SCHEMA_VERSION = "1.0.0"
PARSER_VERSION = "1.0.0"

# ═══════════════════════════════════════════════════════════════════════════════
# ANDROID XML HELPERS
# ═══════════════════════════════════════════════════════════════════════════════
ANDROID_NS = "http://schemas.android.com/apk/res/android"

def A(attr: str) -> str:
    return f"{{{ANDROID_NS}}}{attr}"

# ═══════════════════════════════════════════════════════════════════════════════
# EU-27 MEMBER STATES
# Excludes: IL, GB, CH, NO
# ═══════════════════════════════════════════════════════════════════════════════
EU_MEMBER_STATES = frozenset({
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR",
    "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL",
    "PL", "PT", "RO", "SK", "SI", "ES", "SE",
})

# ═══════════════════════════════════════════════════════════════════════════════
# COUNTRY → REGION GROUPING
# ═══════════════════════════════════════════════════════════════════════════════
_REGION_MAP: Dict[str, str] = {}
for _cc in ["US", "CA"]:
    _REGION_MAP[_cc] = "north_america"
for _cc in ["BR", "MX", "AR", "CL", "CO", "PE", "VE", "EC", "UY", "PY", "BO", "CR", "PA", "DO", "GT", "HN", "SV", "NI", "CU", "PR"]:
    _REGION_MAP[_cc] = "latin_america"
for _cc in EU_MEMBER_STATES:
    _REGION_MAP[_cc] = "eu_member"
for _cc in ["GB", "CH", "NO", "UA", "IS", "RS", "BA", "ME", "MK", "AL", "MD", "BY", "XK"]:
    _REGION_MAP[_cc] = "europe_non_eu"
for _cc in ["CN", "JP", "KR", "TW", "HK", "MO", "MN"]:
    _REGION_MAP[_cc] = "east_asia"
for _cc in ["IN", "PK", "BD", "LK", "NP", "BT", "MV"]:
    _REGION_MAP[_cc] = "south_asia"
for _cc in ["SG", "ID", "TH", "VN", "PH", "MY", "MM", "KH", "LA", "BN"]:
    _REGION_MAP[_cc] = "southeast_asia"
for _cc in ["IL", "AE", "SA", "TR", "QA", "KW", "BH", "OM", "JO", "LB", "IQ", "IR", "YE", "PS"]:
    _REGION_MAP[_cc] = "middle_east"
for _cc in ["ZA", "NG", "KE", "EG", "GH", "TZ", "ET", "UG", "MA", "DZ", "TN", "SN", "CM", "CI"]:
    _REGION_MAP[_cc] = "africa"
for _cc in ["AU", "NZ", "FJ", "PG"]:
    _REGION_MAP[_cc] = "oceania"

def get_region(country_code: str) -> str:
    if not country_code:
        return ""
    return _REGION_MAP.get(country_code.upper(), "other")

# ═══════════════════════════════════════════════════════════════════════════════
# PERMISSION FAMILIES — unique permission counts per family
# ═══════════════════════════════════════════════════════════════════════════════
PERMISSION_FAMILIES: Dict[str, str] = {
    # perm_location
    "android.permission.ACCESS_FINE_LOCATION": "perm_location",
    "android.permission.ACCESS_COARSE_LOCATION": "perm_location",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "perm_location",
    "android.permission.ACCESS_MEDIA_LOCATION": "perm_location",
    # perm_contacts
    "android.permission.READ_CONTACTS": "perm_contacts",
    "android.permission.WRITE_CONTACTS": "perm_contacts",
    "android.permission.GET_ACCOUNTS": "perm_contacts",
    # perm_phone
    "android.permission.READ_PHONE_STATE": "perm_phone",
    "android.permission.READ_PHONE_NUMBERS": "perm_phone",
    "android.permission.CALL_PHONE": "perm_phone",
    "android.permission.PROCESS_OUTGOING_CALLS": "perm_phone",
    "android.permission.ANSWER_PHONE_CALLS": "perm_phone",
    "android.permission.ADD_VOICEMAIL": "perm_phone",
    "android.permission.USE_SIP": "perm_phone",
    # perm_sms_calllog
    "android.permission.SEND_SMS": "perm_sms_calllog",
    "android.permission.RECEIVE_SMS": "perm_sms_calllog",
    "android.permission.READ_SMS": "perm_sms_calllog",
    "android.permission.RECEIVE_MMS": "perm_sms_calllog",
    "android.permission.RECEIVE_WAP_PUSH": "perm_sms_calllog",
    "android.permission.READ_CALL_LOG": "perm_sms_calllog",
    "android.permission.WRITE_CALL_LOG": "perm_sms_calllog",
    # perm_camera_mic
    "android.permission.CAMERA": "perm_camera_mic",
    "android.permission.RECORD_AUDIO": "perm_camera_mic",
    # perm_storage
    "android.permission.READ_EXTERNAL_STORAGE": "perm_storage",
    "android.permission.WRITE_EXTERNAL_STORAGE": "perm_storage",
    "android.permission.MANAGE_EXTERNAL_STORAGE": "perm_storage",
    # perm_media
    "android.permission.READ_MEDIA_IMAGES": "perm_media",
    "android.permission.READ_MEDIA_VIDEO": "perm_media",
    "android.permission.READ_MEDIA_AUDIO": "perm_media",
    # perm_bluetooth
    "android.permission.BLUETOOTH": "perm_bluetooth",
    "android.permission.BLUETOOTH_ADMIN": "perm_bluetooth",
    "android.permission.BLUETOOTH_SCAN": "perm_bluetooth",
    "android.permission.BLUETOOTH_CONNECT": "perm_bluetooth",
    "android.permission.BLUETOOTH_ADVERTISE": "perm_bluetooth",
    # perm_network
    "android.permission.INTERNET": "perm_network",
    "android.permission.ACCESS_NETWORK_STATE": "perm_network",
    "android.permission.CHANGE_NETWORK_STATE": "perm_network",
    "android.permission.ACCESS_WIFI_STATE": "perm_network",
    "android.permission.CHANGE_WIFI_STATE": "perm_network",
    # perm_system_overlay
    "android.permission.SYSTEM_ALERT_WINDOW": "perm_system_overlay",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "perm_system_overlay",
    # perm_biometric
    "android.permission.USE_BIOMETRIC": "perm_biometric",
    "android.permission.USE_FINGERPRINT": "perm_biometric",
}
ALL_FAMILIES = [
    "perm_location", "perm_contacts", "perm_phone", "perm_sms_calllog",
    "perm_camera_mic", "perm_storage", "perm_media", "perm_bluetooth",
    "perm_network", "perm_system_overlay", "perm_biometric", "perm_other",
]

DANGEROUS_PERMISSIONS: Set[str] = {
    "android.permission.READ_CALENDAR", "android.permission.WRITE_CALENDAR",
    "android.permission.CAMERA", "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS", "android.permission.GET_ACCOUNTS",
    "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION", "android.permission.RECORD_AUDIO",
    "android.permission.READ_PHONE_STATE", "android.permission.READ_PHONE_NUMBERS",
    "android.permission.CALL_PHONE", "android.permission.ANSWER_PHONE_CALLS",
    "android.permission.ADD_VOICEMAIL", "android.permission.USE_SIP",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.BODY_SENSORS", "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.SEND_SMS", "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS", "android.permission.RECEIVE_MMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.READ_CALL_LOG", "android.permission.WRITE_CALL_LOG",
    "android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_IMAGES", "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.NEARBY_WIFI_DEVICES",
    "android.permission.BLUETOOTH_SCAN", "android.permission.BLUETOOTH_CONNECT",
    "android.permission.BLUETOOTH_ADVERTISE",
    "android.permission.ACCESS_MEDIA_LOCATION",
    "android.permission.USE_BIOMETRIC", "android.permission.USE_FINGERPRINT",
}

PRIVACY_SANDBOX_PERMISSIONS = {
    "android.permission.ACCESS_ADSERVICES_TOPICS": "ps_topics",
    "android.permission.ACCESS_ADSERVICES_ATTRIBUTION": "ps_attribution",
    "android.permission.ACCESS_ADSERVICES_CUSTOM_AUDIENCE": "ps_custom_audience",
    "android.permission.ACCESS_ADSERVICES_AD_ID": "ps_ad_id",
}

# ═══════════════════════════════════════════════════════════════════════════════
# SDK DATABASE — manifest-only detection
# Format: prefix → (sdk_name, vendor_country_code, sdk_category)
# ═══════════════════════════════════════════════════════════════════════════════
KNOWN_SDK_DATABASE: Dict[str, Tuple[str, str, str]] = {
    # Platform (USA)
    "com.google.android.gms":       ("Google Play Services",  "US", "platform"),
    "com.google.firebase":          ("Firebase",              "US", "platform"),
    "com.google.android.play":      ("Google Play Core",      "US", "platform"),
    "com.google.mlkit":             ("ML Kit",                "US", "platform"),
    "androidx":                     ("AndroidX",              "US", "platform"),
    # Ad Networks
    "com.google.android.gms.ads":   ("Google AdMob",          "US", "ad_network"),
    "com.google.ads":               ("Google Ads",            "US", "ad_network"),
    "com.bytedance":                ("ByteDance/Pangle",      "CN", "ad_network"),
    "com.ss.android":               ("ByteDance (SS)",        "CN", "ad_network"),
    "com.pangle":                   ("Pangle",                "CN", "ad_network"),
    "com.mbridge":                  ("Mintegral",             "CN", "ad_network"),
    "com.inmobi":                   ("InMobi",                "IN", "ad_network"),
    "com.chartboost":               ("Chartboost",            "US", "ad_network"),
    "com.vungle":                   ("Vungle/Liftoff",        "US", "ad_network"),
    "io.liftoff":                   ("Liftoff",               "US", "ad_network"),
    "com.liftoff":                  ("Liftoff",               "US", "ad_network"),
    "com.ogury":                    ("Ogury",                 "FR", "ad_network"),
    "com.adcolony":                 ("AdColony",              "US", "ad_network"),
    "com.startapp":                 ("StartApp",              "IL", "ad_network"),
    "com.tapjoy":                   ("Tapjoy",                "US", "ad_network"),
    "com.unity3d.ads":              ("Unity Ads",             "US", "ad_network"),
    "com.unity.ads":                ("Unity Ads",             "US", "ad_network"),
    "com.yandex.mobile.ads":        ("Yandex Ads",            "RU", "ad_network"),
    "com.my.target":                ("myTarget",              "RU", "ad_network"),
    "com.tencent.gdt":              ("Tencent GDT Ads",       "CN", "ad_network"),
    "com.qq.e.ads":                 ("Tencent QQ Ads",        "CN", "ad_network"),
    "com.baidu.mobads":             ("Baidu Ads",             "CN", "ad_network"),
    # Ad Mediation
    "com.applovin":                 ("AppLovin MAX",          "US", "ad_mediation"),
    "com.ironsource":               ("ironSource/LevelPlay",  "IL", "ad_mediation"),
    "com.unity3d.ironsourceads":    ("ironSource (Unity)",    "IL", "ad_mediation"),
    "com.fyber":                    ("Fyber/InnerActive",     "DE", "ad_mediation"),
    "com.mopub":                    ("MoPub (legacy)",        "US", "ad_mediation"),
    # Ad Exchange
    "io.bidmachine":                ("BidMachine",            "US", "ad_exchange"),
    "com.moloco":                   ("Moloco",                "US", "ad_exchange"),
    "net.pubnative":                ("PubNative/HyBid",       "DE", "ad_exchange"),
    "com.smaato":                   ("Smaato",                "DE", "ad_exchange"),
    "com.amazon.device.ads":        ("Amazon APS",            "US", "ad_exchange"),
    "com.amazon.aps":               ("Amazon APS",            "US", "ad_exchange"),
    # Attribution
    "com.adjust":                   ("Adjust",                "DE", "attribution"),
    "com.appsflyer":                ("AppsFlyer",             "IL", "attribution"),
    "com.singular":                 ("Singular",              "US", "attribution"),
    "io.branch":                    ("Branch",                "US", "attribution"),
    "com.kochava":                  ("Kochava",               "US", "attribution"),
    "com.tenjin":                   ("Tenjin",                "US", "attribution"),
    # Analytics
    "com.amplitude":                ("Amplitude",             "US", "analytics"),
    "com.mixpanel":                 ("Mixpanel",              "US", "analytics"),
    "com.clevertap":                ("CleverTap",             "IN", "analytics"),
    "com.braze":                    ("Braze",                 "US", "analytics"),
    "com.flurry":                   ("Flurry",                "US", "analytics"),
    "com.segment":                  ("Segment",               "US", "analytics"),
    "com.newrelic":                 ("New Relic",             "US", "analytics"),
    "ly.count.android":             ("Countly",               "GB", "analytics"),
    # Social
    "com.facebook":                 ("Facebook SDK",          "US", "social"),
    "com.snapchat.kit":             ("Snap Kit",              "US", "social"),
    "com.linecorp":                 ("LINE SDK",              "JP", "social"),
    "com.vk":                       ("VK SDK",                "RU", "social"),
    "com.kakao":                    ("Kakao SDK",             "KR", "social"),
    "com.tencent.mm":               ("WeChat SDK",            "CN", "social"),
    "com.tencent.tauth":            ("Tencent Auth",          "CN", "social"),
    "com.twitter":                  ("Twitter/X SDK",         "US", "social"),
    # Crash Reporting
    "io.sentry":                    ("Sentry",                "US", "crash_reporting"),
    "com.bugsnag":                  ("Bugsnag",               "US", "crash_reporting"),
    "com.crashlytics":              ("Crashlytics",           "US", "crash_reporting"),
    # Utility
    "com.squareup":                 ("Square (OkHttp etc)",   "US", "utility"),
    "com.bumptech.glide":           ("Glide",                 "US", "utility"),
    "com.jakewharton":              ("JakeWharton libs",      "US", "utility"),
    # Game Engine
    "com.unity3d.player":           ("Unity Engine",          "US", "game_engine"),
    "org.cocos2dx":                 ("Cocos2d-x",             "CN", "game_engine"),
    "com.epicgames":                ("Unreal Engine",         "US", "game_engine"),
    # SDK Management
    "com.safedk":                   ("SafeDK",                "IL", "sdk_mgmt"),
    # Carrier
    "com.digitalturbine":           ("Digital Turbine",       "US", "carrier"),
    # Push
    "com.onesignal":                ("OneSignal",             "US", "utility"),
    "com.pusher":                   ("Pusher",                "GB", "utility"),
    "com.airship":                  ("Airship",               "US", "utility"),
    # Payments
    "com.razorpay":                 ("Razorpay",              "IN", "utility"),
    "com.paytm":                    ("Paytm SDK",             "IN", "utility"),
    "com.stripe":                   ("Stripe",                "US", "utility"),
    # Chinese ecosystem
    "com.alibaba":                  ("Alibaba SDK",           "CN", "platform"),
    "com.alipay":                   ("Alipay SDK",            "CN", "utility"),
    "com.taobao":                   ("Taobao SDK",            "CN", "platform"),
    "com.huawei":                   ("Huawei Mobile Services","CN", "platform"),
    "com.xiaomi":                   ("Xiaomi SDK",            "CN", "platform"),
}

# Category normalization for counting
SDK_CATEGORIES = [
    "ad_network", "ad_mediation", "ad_exchange", "attribution", "analytics", "social",
    "crash_reporting", "utility", "game_engine", "platform", "sdk_mgmt",
    "carrier",
]

# SDK version detection keys in meta-data
VERSION_META_KEYS: Dict[str, str] = {
    "com.google.android.gms.version": "Google Play Services",
    "com.facebook.sdk.ApplicationId": "Facebook SDK",
    "com.bytedance.sdk.pangle.version": "Pangle",
    "com.appsflyer.api_version": "AppsFlyer",
    "com.google.android.play.billingclient.version": "Play Billing",
    "applovin.sdk.key": "AppLovin MAX",
    "ironsource.sdk.key": "ironSource",
}

# ═══════════════════════════════════════════════════════════════════════════════
# SECRET CLASSIFICATION PATTERNS (meta-data values)
# Three tiers: public_id, sensitive_token, possible_credential
# ═══════════════════════════════════════════════════════════════════════════════
SECRET_PATTERNS = {
    "public_id": [
        (r"^ca-app-pub-\d+[~:]\d+$", "admob_id"),
        (r"^\d{10,}$", "numeric_app_id"),
        (r"^fb\d{10,}$", "facebook_app_id"),
    ],
    "sensitive_token": [
        (r"^AIza[0-9A-Za-z\-_]{35}$", "google_api_key"),
        (r"^[a-f0-9]{32}$", "hex_token_32"),
        (r"^[a-f0-9]{40}$", "hex_token_40"),
    ],
    "possible_credential": [
        (r"^AKIA[0-9A-Z]{16}$", "aws_access_key"),
        (r"^eyJ[A-Za-z0-9+/=]{20,}", "jwt_token"),
        (r"^-----BEGIN (RSA |EC )?PRIVATE KEY-----", "private_key"),
    ],
}

SENSITIVE_META_KEY_PATTERNS = [
    "applicationid", "clienttoken", "application_id", "app_id",
    "api_key", "apikey", "api.key", "secret", "token", "client_id",
]
