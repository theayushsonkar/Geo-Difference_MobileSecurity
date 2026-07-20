import sys

# Reconfigure stdout/stderr to avoid UnicodeEncodeError on Windows console
if sys.version_info >= (3, 7):
    try:
        sys.stdout.reconfigure(errors="replace")
        sys.stderr.reconfigure(errors="replace")
    except Exception:
        pass

from gplay_scraper import GPlayScraper
import pandas as pd
import time
import os

# --- Configuration ---
COUNTRIES = {
    # "ca": {"name": "Canada",        "region": "NA",      "fhif_score": 87, "fhif_status": "Free"},
    # "ua": {"name": "Ukraine",       "region": "Europe",  "fhif_score": 56, "fhif_status": "Partially Free"},
    # "de": {"name": "Germany",       "region": "Europe",  "fhif_score": 80, "fhif_status": "Free"},
    # "in": {"name": "India",         "region": "Asia",    "fhif_score": 55, "fhif_status": "Partially Free"},
    # "us": {"name": "United States", "region": "NA",      "fhif_score": 77, "fhif_status": "Free"},
    # "zw": {"name": "Zimbabwe",      "region": "Africa",  "fhif_score": 42, "fhif_status": "Partially Free"},
    # "gb": {"name": "United Kingdom","region": "Europe",  "fhif_score": 77, "fhif_status": "Free"},
    # "tr": {"name": "Turkey",        "region": "Europe",  "fhif_score": 37, "fhif_status": "Not Free"},
    # "au": {"name": "Australia",     "region": "Oceania", "fhif_score": 77, "fhif_status": "Free"},
    # "ru": {"name": "Russia",        "region": "Europe",  "fhif_score": 31, "fhif_status": "Not Free"},
    # "jp": {"name": "Japan",         "region": "Asia",    "fhif_score": 73, "fhif_status": "Free"},
    # "ve": {"name": "Venezuela",     "region": "SA",      "fhif_score": 30, "fhif_status": "Not Free"},
    # "hu": {"name": "Hungary",       "region": "Europe",  "fhif_score": 72, "fhif_status": "Free"},
    # "bh": {"name": "Bahrain",       "region": "Asia",    "fhif_score": 29, "fhif_status": "Not Free"},
    # "ke": {"name": "Kenya",         "region": "Africa",  "fhif_score": 68, "fhif_status": "Partially Free"},
    # "ae": {"name": "UAE",           "region": "Asia",    "fhif_score": 28, "fhif_status": "Not Free"},
    # "co": {"name": "Colombia",      "region": "SA",      "fhif_score": 67, "fhif_status": "Partially Free"},
    # "eg": {"name": "Egypt",         "region": "Africa",  "fhif_score": 26, "fhif_status": "Not Free"},
    # "kr": {"name": "South Korea",   "region": "Asia",    "fhif_score": 64, "fhif_status": "Partially Free"},
    # "ir": {"name": "Iran",          "region": "Asia",    "fhif_score": 15, "fhif_status": "Not Free"},
    # "tn": {"name": "Tunisia",       "region": "Africa",  "fhif_score": 64, "fhif_status": "Partially Free"},
    # "hk": {"name": "Hong Kong",     "region": "Asia",    "fhif_score": None, "fhif_status": "N/A"},
    # "mx": {"name": "Mexico",        "region": "NA",      "fhif_score": 60, "fhif_status": "Partially Free"},
    "ie": {"name": "Ireland",       "region": "Europe",  "fhif_score": None, "fhif_status": "N/A"},
    "sg": {"name": "Singapore",     "region": "Asia",    "fhif_score": 56, "fhif_status": "Partially Free"},
    "il": {"name": "Israel",        "region": "Asia",    "fhif_score": None, "fhif_status": "N/A"},
}

CATEGORIES = {
    "GAME":                "Games",
    "SOCIAL":              "Social",
    "COMMUNICATION":       "Communication",
    "PRODUCTIVITY":        "Productivity",
    "TOOLS":               "Tools",
    "BUSINESS":            "Business",
    "ENTERTAINMENT":       "Entertainment",
    "MUSIC_AND_AUDIO":     "Music & Audio",
    "VIDEO_PLAYERS":       "Video Players",
    "PHOTOGRAPHY":         "Photography",
    "NEWS_AND_MAGAZINES":  "News & Magazines",
    "BOOKS_AND_REFERENCE": "Books & Reference",
    "EDUCATION":           "Education",
    "HEALTH_AND_FITNESS":  "Health & Fitness",
    "LIFESTYLE":           "Lifestyle",
    "FOOD_AND_DRINK":      "Food & Drink",
    "SHOPPING":            "Shopping",
    "FINANCE":             "Finance",
    "TRAVEL_AND_LOCAL":    "Travel & Local",
    "MAPS_AND_NAVIGATION": "Maps & Navigation",
    "SPORTS":              "Sports",
    "WEATHER":             "Weather",
    "CHILDREN":            "Children",
    "MEDICAL":             "Medical"
}

OUTPUT_DIR = "output"
CHECKPOINT_FILE = f"{OUTPUT_DIR}/_checkpoint.csv"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Fields to EXCLUDE for now (we'll add them later according to usage)
EXCLUDE_COLUMNS = {
    "region", "summary", "genre_id", "ratings_count", "reviews_count",
    "min_installs", "max_installs", "offers_iap", "iap_price_range",
    "ad_supported", "editors_choice", "content_rating",
    "content_rating_description", "recent_changes", "header_image_url", "video_url"
}

def safe_get(d, key, default="N/A"):
    val = d.get(key)
    if val is None or val == "":
        return default
    return val

def load_checkpoint():
    if not os.path.exists(CHECKPOINT_FILE):
        return set(), []
    if os.path.exists(CHECKPOINT_FILE) and os.path.getsize(CHECKPOINT_FILE) == 0:
        print("Checkpoint file exists but is empty. Ignoring and deleting it.")
        try:
            os.remove(CHECKPOINT_FILE)
        except Exception:
            pass
        return set(), []
    try:
        df = pd.read_csv(CHECKPOINT_FILE, encoding='utf-8')
        done = set(zip(df["country_code"], df["category_code"], df["app_id"]))
        records = df.to_dict("records")
        return done, records
    except Exception as e:
        print(f"Error loading checkpoint file: {e}. Starting fresh.")
        try:
            os.remove(CHECKPOINT_FILE)
        except Exception:
            pass
        return set(), []

def save_checkpoint(records):
    pd.DataFrame(records).to_csv(CHECKPOINT_FILE, index=False, encoding='utf-8', errors='replace')

def main():
    scraper = GPlayScraper()
    done_set, all_data = load_checkpoint()
    if done_set:
        print(f"Resuming - {len(done_set)} app entries already collected.\n")

    total_country_cat_pairs = len(COUNTRIES) * len(CATEGORIES)
    processed_pairs = 0

    for country_code, country_meta in COUNTRIES.items():
        country_name = country_meta["name"]
        fhif_score = country_meta["fhif_score"]
        fhif_status = country_meta["fhif_status"]

        for category_code, category_name in CATEGORIES.items():
            processed_pairs += 1
            print(f"\n[{processed_pairs}/{total_country_cat_pairs}] {country_name} / {category_name} ...", flush=True)

            try:
                top_apps = scraper.list_analyze(
                    collection="TOP_FREE",
                    category=category_code,
                    country=country_code,
                    lang="en",
                    count=200,
                )
            except Exception as e:
                print(f"  Failed to fetch top apps list: {e}")
                continue

            if not top_apps:
                print("  No apps returned.")
                continue 

            for rank, app_summary in enumerate(top_apps, 1):
                app_id = app_summary.get("appId")
                if not app_id:
                    continue

                if (country_code, category_code, app_id) in done_set:
                    continue

                try:
                    app_details = scraper.app_analyze(app_id=app_id, country=country_code, lang="en")
                except Exception as e:
                    print(f"  ERROR fetching details for {app_id}: {e}")
                    continue

                record = {
                    "country_code": country_code,
                    "country_name": country_name,
                    "fhif_score": fhif_score,
                    "fhif_status": fhif_status,
                    "category_code": category_code,
                    "category_name": category_name,
                    "rank": rank,
                }

                # Copy all fields from app_details, skip excluded columns and None values
                for key, value in app_details.items():
                    if key in EXCLUDE_COLUMNS:
                        continue
                    if value is None or value == "":
                        record[key] = "N/A"
                    else:
                        if isinstance(value, (list, dict)):
                            record[key] = str(value)
                        else:
                            record[key] = value

                # Manually add important fields (safe_get handles missing)
                record["app_id"] = app_id
                record["app_name"] = safe_get(app_details, "title")
                record["developer"] = safe_get(app_details, "developer")
                record["developer_id"] = safe_get(app_details, "developerId")
                record["developer_email"] = safe_get(app_details, "developerEmail")
                record["developer_website"] = safe_get(app_details, "developerWebsite")
                record["developer_address"] = safe_get(app_details, "developerAddress")
                record["privacy_policy_url"] = safe_get(app_details, "privacyPolicy")
                record["version"] = safe_get(app_details, "version")
                record["updated"] = safe_get(app_details, "updated")
                record["released"] = safe_get(app_details, "released")
                # record["installs"] = safe_get(app_details, "installs")
                record["price"] = safe_get(app_details, "price")
                record["free"] = safe_get(app_details, "free")
                record["currency"] = safe_get(app_details, "currency")
                # record["rating"] = safe_get(app_details, "score")
                # record["content_rating"] = safe_get(app_details, "contentRating")
                record["genre"] = safe_get(app_details, "genre")
                # record["icon_url"] = safe_get(app_details, "icon")

                all_data.append(record)
                done_set.add((country_code, category_code, app_id))

                save_checkpoint(all_data)  # Now uses UTF-8
                print(f"    [OK] {rank}. {app_id} -> {record.get('app_name', 'N/A')[:40]}")
                time.sleep(0.5)  # Sleep briefly to avoid hitting rate limits

            time.sleep(1)  # Sleep between country-category pairs

    if not all_data:
        print("\nNo data collected. Check your internet connection or scraper config.")
        return

    df = pd.DataFrame(all_data)
    cols_to_drop = [c for c in EXCLUDE_COLUMNS if c in df.columns]
    if cols_to_drop:
        df = df.drop(columns=cols_to_drop)

    csv_path = f"{OUTPUT_DIR}/top_apps_full.csv"
    df.to_csv(csv_path, index=False, encoding='utf-8', errors='replace')

    if os.path.exists(CHECKPOINT_FILE):
        os.remove(CHECKPOINT_FILE)

    print(f"\n{'='*60}")
    print(f"  Saved {len(df):,} rows -> {csv_path}")
    print(f"  Countries : {df['country_code'].nunique()} / {len(COUNTRIES)}")
    print(f"  Categories: {df['category_code'].nunique()} / {len(CATEGORIES)}")
    print(f"  Columns   : {len(df.columns)}")
    print(f"{'='*60}")

if __name__ == "__main__":
    main()
