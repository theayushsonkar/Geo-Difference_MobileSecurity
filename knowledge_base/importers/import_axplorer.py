"""
Axplorer Importer.

Reads Axplorer mapping files and converts every valid API mapping into canonical PrivacyAPIRecord objects.

===============================================================================
AXPLORER DATASET FORMAT SUMMARY
===============================================================================
- Format: Plain text files named `framework-map-*.txt`.
- Organization: Directories encode API version (e.g. `permissions/api-23/`).
- Record representation: `<fully-qualified API signature>  ::  <permission>`
- Separator: `::` (with surrounding whitespace).
- Signatures: `<package>.<class>.<method>(<params>)<return_type>`.
  - The last `.` before `(` separates the class and method.
  - The preceding `.` separates the package and class.
  - Classes can contain `$`.
- Casing: Original casing for classes and methods is preserved.
- Blank lines and comments: Ignored.
- Duplicates: First occurrence kept.
===============================================================================
"""
import datetime
import pathlib
import csv
import re
from typing import List, Dict, Tuple, Optional, Any

from knowledge_base.config import AXPLORER_DIR, BUILD_OUTPUTS_DIR, ANDROID_PERMISSION_GROUPS_CSV, GROUP_TO_PRIVACY_CATEGORY_CSV
from knowledge_base.schemas.privacy_api_schema import PrivacyAPIRecord
from knowledge_base.logger import get_logger
from knowledge_base.utils.csv_utils import write_csv

logger = get_logger(__name__)

class AxplorerImporter:
    """Importer for processing the Axplorer dataset into the canonical PrivacyAPIRecord format."""

    def __init__(self) -> None:
        """Initializes the Axplorer importer."""
        self.raw_dir: pathlib.Path = AXPLORER_DIR
        self.output_file: pathlib.Path = BUILD_OUTPUTS_DIR / "axplorer_import.csv"
        self._permission_group_map, self._group_category_map = self._load_taxonomy()
        self.records: List[PrivacyAPIRecord] = []

    def _load_taxonomy(self) -> Tuple[Dict[str, str], Dict[str, str]]:
        """Loads the permission group and privacy category taxonomy from configuration.
        
        Returns:
            Tuple[Dict[str, str], Dict[str, str]]: Permission-to-group map and group-to-category map.
        """
        perm_group_map: Dict[str, str] = {}
        if ANDROID_PERMISSION_GROUPS_CSV.exists():
            with open(ANDROID_PERMISSION_GROUPS_CSV, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    clean_perm = row['permission'].replace('android.permission.', '').strip().upper()
                    perm_group_map[clean_perm] = row['android_permission_group']
                    
        group_cat_map: Dict[str, str] = {}
        if GROUP_TO_PRIVACY_CATEGORY_CSV.exists():
            with open(GROUP_TO_PRIVACY_CATEGORY_CSV, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    group_cat_map[row['android_permission_group'].strip()] = row['privacy_category']
                    
        return perm_group_map, group_cat_map

    def discover_files(self) -> List[pathlib.Path]:
        """Returns only framework-map-*.txt files recursively.
        
        Returns:
            List[pathlib.Path]: A list of file paths.
            
        Raises:
            FileNotFoundError: If the dataset directory does not exist.
        """
        if not self.raw_dir.exists():
            raise FileNotFoundError(f"Missing dataset directory: {self.raw_dir}")
        
        return list(self.raw_dir.rglob("framework-map-*.txt"))

    def run(self) -> Dict[str, Any]:
        """Main pipeline to parse Axplorer files and generate output CSV.
        
        Returns:
            Dict[str, Any]: Summary statistics of the import process.
        """
        logger.info("Importer started")
        try:
            files = self.discover_files()
        except FileNotFoundError as e:
            logger.error(str(e))
            raise

        logger.info("Dataset discovered")
        logger.info(f"Files discovered: {len(files)}")

        if not files:
            logger.warning("Empty dataset")
            write_csv(self.output_file, [])
            return {
                "files_discovered": 0,
                "files_processed": 0,
                "rows_parsed": 0,
                "rows_generated": 0,
                "rows_skipped": 0,
                "duplicates_removed": 0,
                "unknown_permissions": 0,
                "output_file": str(self.output_file)
            }

        stats: Dict[str, Any] = {
            "files_discovered": len(files),
            "files_processed": 0,
            "rows_parsed": 0,
            "rows_generated": 0,
            "rows_skipped": 0,
            "unknown_permissions": 0,
            "duplicates_removed": 0,
            "output_file": str(self.output_file)
        }

        for path in files:
            logger.info(f"Current file: {path}")
            parsed, skipped, generated, unknown = self.parse_file(path)
            stats["files_processed"] += 1
            stats["rows_parsed"] += parsed
            stats["rows_skipped"] += skipped
            stats["rows_generated"] += generated
            stats["unknown_permissions"] += unknown

        duplicates_removed = self.deduplicate()
        stats["duplicates_removed"] = duplicates_removed
        stats["rows_generated"] = len(self.records)

        self.write_output()
        logger.info("Importer completed")

        return stats

    def parse_file(self, path: pathlib.Path) -> Tuple[int, int, int, int]:
        """Reads one file and parses API mapping lines.
        
        Args:
            path (pathlib.Path): The path to the file to parse.
            
        Returns:
            Tuple[int, int, int, int]: Parsed count, skipped count, generated count, unknown count.
        """
        parsed_count = 0
        skipped_count = 0
        generated_count = 0
        unknown_count = 0

        api_version_str = path.parent.name
        min_api: Optional[int] = None
        if api_version_str.startswith("api-"):
            try:
                min_api = int(api_version_str.split('-')[1])
            except ValueError:
                pass

        logger.info(f"Current API version: {api_version_str}")

        try:
            with open(path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#') or line.startswith('//'):
                        continue
                    
                    parsed_count += 1
                    
                    obj = self.parse_line(line)
                    if obj is None:
                        logger.warning(f"Malformed line skipped: {line}")
                        skipped_count += 1
                        continue
                    
                    obj["min_api"] = min_api
                    obj["source_version"] = api_version_str
                    
                    record = self.create_record(obj)
                    if record.category == "Unknown":
                        unknown_count += 1

                    self.records.append(record)
                    generated_count += 1
        except Exception as e:
            logger.error(f"Malformed file or error reading {path}: {e}")

        logger.info(f"Rows parsed: {parsed_count}")
        logger.info(f"Rows skipped: {skipped_count}")
        logger.info(f"Rows generated: {generated_count}")
        logger.info(f"Unknown permissions: {unknown_count}")
        
        return parsed_count, skipped_count, generated_count, unknown_count

    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parses one Axplorer API mapping strictly.
        
        Args:
            line (str): The line to parse.
            
        Returns:
            Optional[Dict[str, Any]]: Parsed mapping properties or None if malformed.
        """
        if '::' not in line:
            return None
            
        parts = line.split('::', 1)
        if len(parts) != 2:
            return None
            
        signature = parts[0].strip()
        permission = parts[1].strip()

        sig_info = self.extract_signature(signature)
        if not sig_info:
            return None

        return {
            "signature_info": sig_info,
            "permission": permission
        }

    def extract_signature(self, signature: str) -> Optional[Dict[str, str]]:
        """Extracts package, class, method, and api type from a raw signature.
        
        Args:
            signature (str): The raw string signature.
            
        Returns:
            Optional[Dict[str, str]]: Extracted signature details.
        """
        paren_idx = signature.find('(')
        if paren_idx == -1:
            return None
            
        path_method = signature[:paren_idx]
        
        last_dot = path_method.rfind('.')
        if last_dot == -1:
            return None
            
        method_name = path_method[last_dot+1:]
        package_class = path_method[:last_dot]
        
        class_dot = package_class.rfind('.')
        if class_dot == -1:
            package_name = ""
            class_name = package_class
        else:
            package_name = package_class[:class_dot]
            class_name = package_class[class_dot+1:]

        package_name = " ".join(package_name.strip().split())
        class_name = " ".join(class_name.strip().split())
        method_name = " ".join(method_name.strip().split())

        return {
            "package_name": package_name,
            "class_name": class_name,
            "method_name": method_name,
            "api_name": method_name,
            "api_type": "method"
        }

    def map_permission(self, permission: str) -> str:
        """Maps a permission to a privacy category using official taxonomy.
        
        Args:
            permission (str): The permission to lookup.
            
        Returns:
            str: The mapped privacy category, or 'Unknown'.
        """
        lookup_key = permission.strip().upper()
        if lookup_key.startswith("ANDROID.PERMISSION."):
            lookup_key = lookup_key.replace("ANDROID.PERMISSION.", "")
            
        group = self._permission_group_map.get(lookup_key, "")
        if not group:
            return "Unknown"
            
        return self._group_category_map.get(group, "Unknown")

    def create_record(self, obj: Dict[str, Any]) -> PrivacyAPIRecord:
        """Converts an extracted API mapping into a canonical PrivacyAPIRecord.
        
        Args:
            obj (Dict[str, Any]): The extracted object.
            
        Returns:
            PrivacyAPIRecord: The canonical record.
        """
        sig = obj["signature_info"]
        permission = obj["permission"]
        min_api = obj["min_api"]
        source_version = obj["source_version"]
        
        category = self.map_permission(permission)
        import_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

        return PrivacyAPIRecord(
            record_id="",
            category=category,
            subcategory="",
            framework="Android Framework",
            package_name=sig['package_name'],
            class_name=sig['class_name'],
            method_name=sig['method_name'],
            api_name=sig['api_name'],
            api_type=sig['api_type'],
            permission=permission,
            sources=["Axplorer"],
            source_versions=[source_version] if source_version else ["unknown"],
            supported_android_versions=[min_api] if min_api is not None else [],
            import_timestamp=import_timestamp,
            min_android_api=min_api,
            max_android_api=None,
            confidence="high",
            deprecated=False,
            documentation_url="",
            notes=""
        )

    def deduplicate(self) -> int:
        """Merges duplicate APIs across Android versions.
        
        Returns:
            int: Number of duplicates merged.
        """
        unique_records: Dict[Tuple[str, str, str, str, str], PrivacyAPIRecord] = {}
        duplicates = 0
        
        for record in self.records:
            key = (
                record.framework,
                record.package_name,
                record.class_name,
                record.method_name,
                record.permission
            )
            if key not in unique_records:
                unique_records[key] = record
            else:
                duplicates += 1
                existing = unique_records[key]
                
                if record.supported_android_versions:
                    existing.supported_android_versions.extend(record.supported_android_versions)
                    
                if record.source_versions:
                    for sv in record.source_versions:
                        if sv not in existing.source_versions:
                            existing.source_versions.append(sv)

        for rec in unique_records.values():
            if rec.supported_android_versions:
                rec.supported_android_versions = sorted(list(set(rec.supported_android_versions)))
                rec.min_android_api = min(rec.supported_android_versions)
                rec.max_android_api = max(rec.supported_android_versions)
                
        self.records = list(unique_records.values())
        logger.info(f"Duplicates merged: {duplicates}")
        return duplicates

    def write_output(self) -> None:
        """Writes processed/axplorer_import.csv using csv_utils.
        
        Returns:
            None
        """
        write_csv(self.output_file, self.records)
        logger.info("CSV written")

if __name__ == "__main__":
    importer = AxplorerImporter()
    summary = importer.run()
    logger.info("Summary:")
    for k, v in summary.items():
        logger.info(f"  {k}: {v}")
