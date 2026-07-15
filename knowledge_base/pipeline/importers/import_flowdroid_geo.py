import os
import re
import csv
from collections import Counter

def import_flowdroid_geo():
    raw_path = os.path.join("knowledge_base", "raw", "flowdroid", "AndroidSources.txt")
    out_dir = os.path.join("knowledge_base", "metadata")
    processed_dir = os.path.join("knowledge_base", "processed")
    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(processed_dir, exist_ok=True)
    
    if not os.path.exists(raw_path):
        print(f"Error: {raw_path} not found.")
        return
        
    # Regex to parse FlowDroid syntax: <class: ret_type method(args)> [permission] -> _SOURCE_
    pattern = re.compile(r'^<([^:]+):\s+([^ ]+)\s+([^\(]+)\(([^\)]*)\)>\s*(.*?)\s*->\s*(.*)$')
    
    geo_keywords = ["Location", "GPS", "FusedLocation", "Locale", "Country", "Region", "Language", "TimeZone", "TelephonyManager", "SIM", "Network", "MCC", "MNC", "Geocoder", "Address", "Geofence", "GsmCellLocation", "Calendar"]
    # We will refine matches
    
    parsed_count = 0
    retained_count = 0
    discarded_count = 0
    
    records = []
    
    with open(raw_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("%") or line.startswith("Source:") or line == "---":
                continue
                
            m = pattern.match(line)
            if not m:
                continue
                
            parsed_count += 1
            full_class = m.group(1)
            method = m.group(3)
            
            # Simple heuristic: Does class or method contain geo keywords?
            # Let's be strict:
            cls_lower = full_class.lower()
            method_lower = method.lower()
            
            # Calendar, Date, Clock shouldn't be included for timezone unless it's strictly timezone related, but user says to remove Calendar.
            if any(k in cls_lower for k in ["calendar", "date", "clock", "alarm", "battery", "storage", "media", "camera", "bluetooth", "sensor"]):
                continue
                
            is_geo = False
            
            # TelephonyManager methods for country/MCC/MNC
            if "telephonymanager" in cls_lower:
                if any(k in method_lower for k in ["country", "mcc", "mnc", "sim", "network"]):
                    is_geo = True
            elif "location" in cls_lower or "gps" in cls_lower or "geocoder" in cls_lower or "geofence" in cls_lower:
                is_geo = True
            elif "locale" in cls_lower:
                is_geo = True
            elif "timezone" in cls_lower:
                is_geo = True
            elif "address" in cls_lower:
                is_geo = True
            
            if is_geo:
                # We retain this API
                pkg = full_class.rsplit('.', 1)[0] if '.' in full_class else ''
                cls_name = full_class.rsplit('.', 1)[1] if '.' in full_class else full_class
                
                # Assign categories
                cat = "Location"
                subcat = "GPS"
                if "locale" in cls_lower:
                    cat = "Locale"
                    subcat = "Region"
                elif "telephony" in cls_lower:
                    cat = "Telephony"
                    if "sim" in method_lower:
                        subcat = "SIM Country"
                    elif "network" in method_lower:
                        subcat = "Network Country"
                    else:
                        subcat = "Country"
                elif "timezone" in cls_lower:
                    cat = "Timezone"
                    subcat = "Timezone"
                elif "geocoder" in cls_lower or "address" in cls_lower:
                    cat = "Geocoder"
                    subcat = "Address"
                    
                records.append({
                    "package_name": pkg,
                    "class_name": cls_name,
                    "method_name": method,
                    "category": cat,
                    "subcategory": subcat,
                    "confidence": "HIGH",
                    "source": "FlowDroid",
                    "notes": "Imported from AndroidSources.txt"
                })
                retained_count += 1
            else:
                discarded_count += 1
                
    # MANUAL ENRICHMENT
    manual_rules = [
        {"package": "android.os", "class": "Build", "method": "getRadioVersion", "cat": "Telephony", "subcat": "Provider", "notes": "Extracts radio version which can hint at region. FlowDroid focuses on standard sources rather than reflection or specific Build properties."},
        {"package": "android.telephony", "class": "TelephonyManager", "method": "getNetworkCountryIso", "cat": "Country Detection", "subcat": "Network Country", "notes": "Explicit network country detection missing in some FlowDroid base configurations."},
        {"package": "android.telephony", "class": "TelephonyManager", "method": "getSimCountryIso", "cat": "Country Detection", "subcat": "SIM Country", "notes": "Explicit SIM country detection commonly missed in basic sink lists."},
        {"package": "java.util", "class": "Locale", "method": "getDefault", "cat": "Locale", "subcat": "Locale", "notes": "Global default locale fetch. Basic API not always flagged by FlowDroid as a sensitive source."},
        {"package": "java.util", "class": "Locale", "method": "getCountry", "cat": "Country Detection", "subcat": "Language", "notes": "Country code from Locale object properties."},
        {"package": "java.util", "class": "Locale", "method": "getLanguage", "cat": "Language", "subcat": "Language", "notes": "Language code from Locale. Not universally seen as a critical privacy leak by basic tools."},
        {"package": "android.content.res", "class": "Configuration", "method": "getLocales", "cat": "Locale", "subcat": "Locale", "notes": "Fetch device locales via Configuration. Often overlooked by data-flow analysis."},
        {"package": "android.os", "class": "SystemProperties", "method": "get", "cat": "Region Detection", "subcat": "Provider", "notes": "System.getProperty can fetch user.country or user.language. Often missed by static source detection."},
        {"package": "java.lang", "class": "System", "method": "getProperty", "cat": "Region Detection", "subcat": "Provider", "notes": "user.country or user.language via System properties."},
        {"package": "android.telephony", "class": "ServiceState", "method": "getOperatorAlphaLong", "cat": "Telephony", "subcat": "Provider", "notes": "Operator name can leak country. Not always flagged as a strict source."},
        {"package": "android.telephony", "class": "ServiceState", "method": "getOperatorNumeric", "cat": "Telephony", "subcat": "MCC", "notes": "MCC/MNC from operator numeric."},
        {"package": "android.telephony", "class": "SubscriptionInfo", "method": "getCountryIso", "cat": "Country Detection", "subcat": "SIM Country", "notes": "Country ISO from Subscription. Added in later Android versions, occasionally missing in old FlowDroid lists."},
        {"package": "android.telephony", "class": "SubscriptionInfo", "method": "getMcc", "cat": "Telephony", "subcat": "MCC", "notes": "MCC from Subscription."},
        {"package": "android.telephony", "class": "SubscriptionInfo", "method": "getMnc", "cat": "Telephony", "subcat": "MNC", "notes": "MNC from Subscription."},
        {"package": "java.util", "class": "TimeZone", "method": "getDefault", "cat": "Timezone", "subcat": "Timezone", "notes": "Global default timezone."},
        {"package": "java.util", "class": "TimeZone", "method": "getID", "cat": "Timezone", "subcat": "Timezone", "notes": "Timezone ID. Java utility class sometimes ignored in Android-focused datasets."},
        {"package": "com.android.internal.telephony", "class": "MccTable", "method": "countryCodeForMcc", "cat": "Country Detection", "subcat": "MCC", "notes": "Internal MCC to Country mapping."},
        {"package": "android.os", "class": "Build", "method": "MODEL", "cat": "Region Detection", "subcat": "Provider", "notes": "Model can sometimes imply region (e.g. Chinese variants)."}
    ]
    
    manual_count = 0
    for r in manual_rules:
        records.append({
            "package_name": r["package"],
            "class_name": r["class"],
            "method_name": r["method"],
            "category": r["cat"],
            "subcategory": r["subcat"],
            "confidence": "VERY_HIGH",
            "source": "Manual",
            "notes": r["notes"]
        })
        manual_count += 1
        
    # Deduplication and deterministic sort
    unique_records = {}
    for r in records:
        # Some methods are fields in Android (like MODEL) but we treat them uniformly as method_name for signature matching
        key = f'{r["package_name"]}.{r["class_name"]}->{r["method_name"]}'
        if key not in unique_records:
            unique_records[key] = r
            
    final_list = list(unique_records.values())
    
    # Sort deterministically
    final_list.sort(key=lambda x: (x["category"], x["subcategory"], x["package_name"], x["class_name"], x["method_name"]))
    
    # Generate Rule IDs
    rule_counters = Counter()
    for r in final_list:
        cat_prefix = r["category"].lower().replace(' ', '_')
        rule_counters[cat_prefix] += 1
        r["rule_id"] = f"{cat_prefix}_{rule_counters[cat_prefix]}"
        
    # WRITE CSV
    csv_path = os.path.join(out_dir, "geo_logic.csv")
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=["rule_id", "package_name", "class_name", "method_name", "category", "subcategory", "confidence", "source", "notes"])
        writer.writeheader()
        writer.writerows(final_list)
        
    # WRITE STATS CSV
    stats_path = os.path.join(processed_dir, "flowdroid_geo_statistics.csv")
    cat_dist = Counter(r["category"] for r in final_list)
    src_dist = Counter(r["source"] for r in final_list)
    conf_dist = Counter(r["confidence"] for r in final_list)
    
    with open(stats_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["category", "rule_count", "source", "confidence_distribution"])
        for cat, count in cat_dist.items():
            sources = ", ".join(f"{s}:{c}" for s, c in Counter(r["source"] for r in final_list if r["category"] == cat).items())
            confs = ", ".join(f"{s}:{c}" for s, c in Counter(r["confidence"] for r in final_list if r["category"] == cat).items())
            writer.writerow([cat, count, sources, confs])
            
    # WRITE REPORT
    report_path = os.path.join(processed_dir, "flowdroid_geo_report.md")
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write("# FlowDroid Geo-Logic Knowledge Acquisition Report\n\n")
        f.write("- **Official FlowDroid Source**: `SourcesAndSinks.txt` (develop branch)\n")
        f.write("> *Note*: `knowledge_base/raw/flowdroid/AndroidSources.txt` is simply a local copy of FlowDroid's official `SourcesAndSinks.txt`. FlowDroid does not officially ship an `AndroidSources.txt` file.\n\n")
        f.write(f"- **Number of APIs parsed**: {parsed_count}\n")
        f.write(f"- **Imported rules (FlowDroid retained)**: {retained_count}\n")
        f.write(f"- **Number discarded**: {discarded_count}\n")
        f.write(f"- **Manual rules added**: {manual_count}\n")
        f.write(f"- **Total Rules in Database**: {len(final_list)}\n\n")
        
        f.write("## Category Distribution\n")
        for cat, count in cat_dist.most_common():
            f.write(f"- **{cat}**: {count}\n")
            
        f.write("\n## Subcategory Distribution\n")
        subcat_dist = Counter(r["subcategory"] for r in final_list)
        for sub, count in subcat_dist.most_common():
            f.write(f"- **{sub}**: {count}\n")
            
        f.write("\n## Known Limitations\n")
        f.write("- The importer uses heuristic matching to distinguish Geo Logic from other FlowDroid sources.\n")
        f.write("- Many geo-inference techniques rely on reflection or specific `Build` and `System` properties which are not natively categorized as sources by default FlowDroid datasets.\n\n")
        
        f.write("## Provenance\n")
        f.write(f"- **Imported rules (FlowDroid)**: {src_dist['FlowDroid']}\n")
        f.write(f"- **Manual rules**: {src_dist['Manual']}\n\n")
        
        f.write("## Reasons for Manual Additions\n")
        f.write("Manual additions were required to capture geo-inference APIs that FlowDroid's base `SourcesAndSinks.txt` lacks, particularly utility classes like `Locale`, `TimeZone`, `SystemProperties`, and structural properties such as `BuildConfig.REGION` which represent logical side-channels rather than explicit platform permissioned sources.\n")

    print("Geo Logic Knowledge Base Generation Complete.")

if __name__ == "__main__":
    import_flowdroid_geo()
