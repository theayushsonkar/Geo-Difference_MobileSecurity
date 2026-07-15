"""
All constants, region maps, permission families, SDK database,
SDK catalog, and detection regexes.
"""

import re
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
# CURATED SDK CATALOG — later manifest + DEX enrichment
# Small human-maintained mapping; do not assume a clean Maven coordinate exists.
# ═══════════════════════════════════════════════════════════════════════════════
CURATED_SDK_CATALOG = (
    {
        "sdk_name": "Google Play Services",
        "sdk_prefix": "com.google.android.gms",
        "sdk_ecosystem": "maven",
        "sdk_identifier": "com.google.android.gms:play-services-basement",
        "vendor_country_code": "US",
        "vendor_region_group": "north_america",
        "sdk_category": "platform",
        "smali_aliases": ("com/google/android/gms",),
    },
    {
        "sdk_name": "Firebase",
        "sdk_prefix": "com.google.firebase",
        "sdk_ecosystem": "maven",
        "sdk_identifier": "com.google.firebase:firebase-common",
        "regex": re.compile(r'\bhttps?://[A-Za-z0-9_-]+\.(?:firebaseio\.com|firebasedatabase\.app)(?:/[^\"]*)?\b'),
        "vendor_country_code": "US",
        "vendor_region_group": "north_america",
        "sdk_category": "platform",
        "smali_aliases": ("com/google/firebase",),
    },
    {
        "sdk_name": "AndroidX",
        "sdk_prefix": "androidx",
        "sdk_ecosystem": "maven",
        "sdk_identifier": "androidx.core:core",
        "vendor_country_code": "US",
        "vendor_region_group": "north_america",
        "sdk_category": "platform",
        "smali_aliases": ("androidx/",),
    },
    {
        "sdk_name": "Google Play Core",
        "sdk_prefix": "com.google.android.play",
        "sdk_ecosystem": "maven",
        "sdk_identifier": "com.google.android.play:core",
        "vendor_country_code": "US",
        "vendor_region_group": "north_america",
        "sdk_category": "platform",
        "smali_aliases": ("com/google/android/play",),
    },
    {
        "sdk_name": "Play Billing",
        "sdk_prefix": "com.android.billingclient",
        "sdk_ecosystem": "maven",
        "sdk_identifier": "com.android.billingclient:billing",
        "vendor_country_code": "US",
        "vendor_region_group": "north_america",
        "sdk_category": "utility",
        "smali_aliases": ("com/android/billingclient",),
    },
    {
        "sdk_name": "AppLovin MAX",
        "sdk_prefix": "com.applovin",
        "sdk_ecosystem": "custom",
        "sdk_identifier": "com.applovin",
        "vendor_country_code": "US",
        "vendor_region_group": "north_america",
        "sdk_category": "ad_mediation",
        "smali_aliases": ("com/applovin",),
    },
    {
        "sdk_name": "ByteDance/Pangle",
        "sdk_prefix": "com.bytedance",
        "sdk_ecosystem": "custom",
        "sdk_identifier": "com.bytedance.sdk",
        "vendor_country_code": "CN",
        "vendor_region_group": "east_asia",
        "sdk_category": "ad_network",
        "smali_aliases": ("com/bytedance", "com/bytedance/sdk", "com/ss/android", "com/pangle"),
    },
    {
        "sdk_name": "Mintegral",
        "sdk_prefix": "com.mbridge",
        "sdk_ecosystem": "custom",
        "sdk_identifier": "com.mbridge",
        "vendor_country_code": "CN",
        "vendor_region_group": "east_asia",
        "sdk_category": "ad_network",
        "smali_aliases": ("com/mbridge", "com/mbridge/msdk"),
    },
    {
        "sdk_name": "ironSource/LevelPlay",
        "sdk_prefix": "com.ironsource",
        "sdk_ecosystem": "custom",
        "sdk_identifier": "com.ironsource.sdk",
        "vendor_country_code": "IL",
        "vendor_region_group": "middle_east",
        "sdk_category": "ad_mediation",
        "smali_aliases": ("com/ironsource", "com/unity3d/ironsourceads"),
    },
    {
        "sdk_name": "Unity Ads",
        "sdk_prefix": "com.unity3d.ads",
        "sdk_ecosystem": "maven",
        "sdk_identifier": "com.unity3d.ads:unity-ads",
        "vendor_country_code": "US",
        "vendor_region_group": "north_america",
        "sdk_category": "ad_network",
        "smali_aliases": ("com/unity3d/ads",),
    },
    {
        "sdk_name": "Facebook SDK",
        "sdk_prefix": "com.facebook",
        "sdk_ecosystem": "maven",
        "sdk_identifier": "com.facebook.android:facebook-core",
        "vendor_country_code": "US",
        "vendor_region_group": "north_america",
        "sdk_category": "social",
        "smali_aliases": ("com/facebook",),
    },
    {
        "sdk_name": "Sentry",
        "sdk_prefix": "io.sentry",
        "sdk_ecosystem": "maven",
        "sdk_identifier": "io.sentry:sentry-android-core",
        "vendor_country_code": "US",
        "vendor_region_group": "north_america",
        "sdk_category": "crash_reporting",
        "smali_aliases": ("io/sentry",),
    },
    {
        "sdk_name": "Glide",
        "sdk_prefix": "com.bumptech.glide",
        "sdk_ecosystem": "maven",
        "sdk_identifier": "com.github.bumptech.glide:glide",
        "vendor_country_code": "US",
        "vendor_region_group": "north_america",
        "sdk_category": "utility",
        "smali_aliases": ("com/bumptech/glide",),
    },
    {
        "sdk_name": "Unity Engine",
        "sdk_prefix": "com.unity3d.player",
        "sdk_ecosystem": "custom",
        "sdk_identifier": "com.unity3d.player",
        "vendor_country_code": "US",
        "vendor_region_group": "north_america",
        "sdk_category": "game_engine",
        "smali_aliases": ("com/unity3d/player",),
    },
    {
        "sdk_name": "ByteDance/Pangle",
        "sdk_prefix": "com.bytedance",
        "sdk_ecosystem": "custom",
        "sdk_identifier": "com.bytedance.sdk",
        "vendor_country_code": "CN",
        "vendor_region_group": "east_asia",
        "sdk_category": "ad_network",
        "smali_aliases": (
            "com/bytedance",
            "com/bytedance/sdk",
            "com/ss/android",
            "com/pangle",
        ),
    },
    {
        "sdk_name": "Mintegral",
        "sdk_prefix": "com.mbridge",
        "sdk_ecosystem": "custom",
        "sdk_identifier": "com.mbridge",
        "vendor_country_code": "CN",
        "vendor_region_group": "east_asia",
        "sdk_category": "ad_network",
        "smali_aliases": (
            "com/mbridge",
            "com/mbridge/msdk",
        ),
    },
)


def _compile_sdk_match(prefix: str) -> re.Pattern:
    escaped = re.escape(prefix)
    return re.compile(rf"(?i)(?:^|[./$]){escaped}(?:[./$]|$)")


SDK_DETECTION_REGEXES = {
    entry["sdk_name"]: {
        "prefix": _compile_sdk_match(entry["sdk_prefix"]),
        "smali_aliases": tuple(_compile_sdk_match(alias) for alias in entry.get("smali_aliases", ())),
    }
    for entry in CURATED_SDK_CATALOG
}

SDK_VERSION_REGEXES = (
    re.compile(r"(?i)\b(?:sdk[_\-\s]?version|version(?:name)?|ver)\b[=: \t]*([0-9]+(?:\.[0-9A-Za-z_-]+){0,3})"),
    re.compile(r"(?i)\b(?:v|version)\s*([0-9]+(?:\.[0-9A-Za-z_-]+){1,3})\b"),
    re.compile(r"(?i)\b([0-9]+(?:\.[0-9A-Za-z_-]+){1,3})\b"),
)

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

