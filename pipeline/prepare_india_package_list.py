import pandas as pd
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

INPUT_CSV = PROJECT_ROOT / "output" / "top_apps_full.csv"

OUTPUT_DIR = PROJECT_ROOT / "data/package_lists"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

PACKAGE_FILE = OUTPUT_DIR / "india_packages.txt"
METADATA_FILE = OUTPUT_DIR / "india_packages_metadata.csv"


def main():

    print("[*] Loading CSV...")

    df = pd.read_csv(INPUT_CSV, low_memory=False)

    print(f"[*] Total rows: {len(df)}")

    # -------------------------------------------------
    # Keep only India rows
    # -------------------------------------------------

    india_df = df[
        df["country_code"].astype(str).str.upper() == "IN"
    ].copy()

    print(f"[*] India rows: {len(india_df)}")

    # -------------------------------------------------
    # Remove rows without package names
    # -------------------------------------------------

    india_df = india_df.sort_values(
        by=["category_code", "rank"]
    )

    # -------------------------------------------------
    # Unique packages
    # -------------------------------------------------

    india_df = india_df.drop_duplicates(
        subset=["appId"],
        keep="first"
    )

    print(f"[*] Unique packages: {len(india_df)}")

    # -------------------------------------------------
    # Save package list
    # -------------------------------------------------

    with open(PACKAGE_FILE, "w", encoding="utf-8") as f:
        for package_name in india_df["appId"]:
            f.write(f"{package_name}\n")

    # -------------------------------------------------
    # Save metadata
    # -------------------------------------------------

    keep_cols = [
        "country_code",
        "country_name",

        "category_code",
        "category_name",

        "rank",

        "appId",
        "title",

        "developer",
        "publisherCountry",

        "installs",
        "score",

        "appUrl",
    ]

    available_cols = [
        c for c in keep_cols
        if c in india_df.columns
    ]

    india_df[available_cols].to_csv(
        METADATA_FILE,
        index=False
    )

    print()
    print(f"[+] Package list saved:")
    print(f"    {PACKAGE_FILE}")

    print()
    print(f"[+] Metadata saved:")
    print(f"    {METADATA_FILE}")


if __name__ == "__main__":
    main()
