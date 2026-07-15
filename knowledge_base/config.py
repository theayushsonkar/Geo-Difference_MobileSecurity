"""Configuration constants for the knowledge base."""
import pathlib

ROOT_DIR: pathlib.Path = pathlib.Path(__file__).parent.resolve()
RAW_DIR: pathlib.Path = ROOT_DIR / "raw"
PROCESSED_DIR: pathlib.Path = ROOT_DIR / "processed"
BUILD_OUTPUTS_DIR: pathlib.Path = ROOT_DIR / "build_outputs"
METADATA_DIR: pathlib.Path = ROOT_DIR / "metadata"

AXPLORER_DIR: pathlib.Path = RAW_DIR / "axplorer"
PSCOUT_DIR: pathlib.Path = RAW_DIR / "pscout"
GMS_DIR: pathlib.Path = RAW_DIR / "gms"

PRIVACY_CATEGORIES_CSV: pathlib.Path = METADATA_DIR / "privacy_categories.csv"
PACKAGE_CATEGORY_MAPPING_CSV: pathlib.Path = METADATA_DIR / "package_category_mapping.csv"
ANDROID_PERMISSION_GROUPS_CSV: pathlib.Path = METADATA_DIR / "android_permission_groups.csv"
GROUP_TO_PRIVACY_CATEGORY_CSV: pathlib.Path = METADATA_DIR / "group_to_privacy_category.csv"
