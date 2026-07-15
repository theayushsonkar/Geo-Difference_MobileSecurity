"""
PScout Importer.

Reads DroidPerm/PScout XML and TXT mapping files and converts every valid API mapping 
into canonical PrivacyAPIRecord objects.
"""
import datetime
import pathlib
import csv
import xml.etree.ElementTree as ET
from typing import List, Dict, Tuple, Optional, Any

from knowledge_base.config import (
    PSCOUT_DIR, 
    BUILD_OUTPUTS_DIR, 
    ANDROID_PERMISSION_GROUPS_CSV, 
    GROUP_TO_PRIVACY_CATEGORY_CSV
)
from knowledge_base.schemas.privacy_api_schema import PrivacyAPIRecord
from knowledge_base.logger import get_logger
from knowledge_base.utils.csv_utils import write_csv

logger = get_logger(__name__)

class PScoutImporter:
    """Importer for processing the PScout dataset into the canonical PrivacyAPIRecord format."""

    def __init__(self) -> None:
        """Initializes the PScout importer."""
        self.raw_dir: pathlib.Path = PSCOUT_DIR / "config"
        self.output_file: pathlib.Path = BUILD_OUTPUTS_DIR / "pscout_import.csv"
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
        """Returns the specific XML and TXT mapping files.
        
        Returns:
            List[pathlib.Path]: A list of file paths.
            
        Raises:
            FileNotFoundError: If the dataset directory does not exist.
        """
        if not self.raw_dir.exists():
            raise FileNotFoundError(f"Missing dataset directory: {self.raw_dir}")
        
        supported_files = [
            "perm-def-API-23.xml",
            "perm-def-API-25.xml",
            "perm-def-manual.xml",
            "javadoc-perm-def-API-23.xml",
            "perm-def-default.txt"
        ]
        
        discovered = []
        for file_name in supported_files:
            file_path = self.raw_dir / file_name
            if file_path.exists():
                discovered.append(file_path)
            else:
                logger.warning(f"Expected file missing: {file_path}")
                
        return discovered

    def run(self) -> Dict[str, Any]:
        """Main pipeline to parse PScout files and generate output CSV.
        
        Returns:
            Dict[str, Any]: Summary statistics of the import process.
        """
        logger.info("PScout Importer started")
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
                "xml_records_parsed": 0,
                "txt_records_parsed": 0,
                "rows_generated": 0,
                "rows_skipped": 0,
                "duplicates_removed": 0,
                "unknown_permissions": 0,
                "output_file": str(self.output_file)
            }

        stats: Dict[str, Any] = {
            "files_discovered": len(files),
            "files_processed": 0,
            "xml_records_parsed": 0,
            "txt_records_parsed": 0,
            "rows_generated": 0,
            "rows_skipped": 0,
            "unknown_permissions": 0,
            "duplicates_removed": 0,
            "output_file": str(self.output_file)
        }

        for path in files:
            logger.info(f"Current file: {path.name}")
            if path.suffix == ".xml":
                parsed, skipped, generated, unknown = self.parse_xml(path)
                stats["xml_records_parsed"] += parsed
            elif path.suffix == ".txt":
                parsed, skipped, generated, unknown = self.parse_txt(path)
                stats["txt_records_parsed"] += parsed
            else:
                continue
                
            stats["files_processed"] += 1
            stats["rows_skipped"] += skipped
            stats["rows_generated"] += generated
            stats["unknown_permissions"] += unknown

        duplicates_removed = self.deduplicate()
        stats["duplicates_removed"] = duplicates_removed
        stats["rows_generated"] = len(self.records)

        self.write_output()
        logger.info("Importer completed")

        return stats

    def _determine_versions(self, filename: str) -> Tuple[str, Optional[int]]:
        """Extracts source version and minimum API version from filename.
        
        Args:
            filename (str): The name of the file.
            
        Returns:
            Tuple[str, Optional[int]]: The source version and min API (if determinable).
        """
        if "API-23" in filename:
            return ("API-23", 23)
        if "API-25" in filename:
            return ("API-25", 25)
        if "manual" in filename:
            return ("Manual", None)
        if "default" in filename:
            return ("TXT", None)
        return ("Unknown", None)

    def parse_xml(self, path: pathlib.Path) -> Tuple[int, int, int, int]:
        """Reads one XML file and parses API mappings.
        
        Args:
            path (pathlib.Path): The path to the XML file.
            
        Returns:
            Tuple[int, int, int, int]: Parsed count, skipped count, generated count, unknown count.
        """
        parsed_count = 0
        skipped_count = 0
        generated_count = 0
        unknown_count = 0

        source_version, min_api = self._determine_versions(path.name)

        try:
            tree = ET.parse(path)
            root = tree.getroot()
            
            for perm_def in root.findall("permissionDef"):
                class_name_full = perm_def.get("className")
                target = perm_def.get("target")
                target_kind = perm_def.get("targetKind")
                
                if not class_name_full or not target or not target_kind:
                    skipped_count += 1
                    continue
                    
                parsed_count += 1
                
                sig_info = self.extract_signature(class_name_full, target, target_kind)
                if not sig_info:
                    logger.warning(f"Could not extract signature from: {class_name_full} -> {target}")
                    skipped_count += 1
                    continue
                
                permissions = perm_def.findall("permission")
                if not permissions:
                    skipped_count += 1
                    continue
                    
                for perm_node in permissions:
                    permission = perm_node.get("name")
                    if not permission:
                        continue
                        
                    obj = {
                        "signature_info": sig_info,
                        "permission": permission.strip(),
                        "min_api": min_api,
                        "source_version": source_version
                    }
                    
                    record = self.create_record(obj)
                    if record.category == "Unknown":
                        unknown_count += 1

                    self.records.append(record)
                    generated_count += 1
                    
        except Exception as e:
            logger.error(f"Malformed XML file or error reading {path}: {e}")

        logger.info(f"XML Rows parsed: {parsed_count}")
        logger.info(f"XML Rows skipped: {skipped_count}")
        logger.info(f"XML Rows generated: {generated_count}")
        logger.info(f"Unknown permissions: {unknown_count}")
        
        return parsed_count, skipped_count, generated_count, unknown_count

    def parse_txt(self, path: pathlib.Path) -> Tuple[int, int, int, int]:
        """Reads one TXT file and parses API mappings.
        
        Args:
            path (pathlib.Path): The path to the TXT file.
            
        Returns:
            Tuple[int, int, int, int]: Parsed count, skipped count, generated count, unknown count.
        """
        parsed_count = 0
        skipped_count = 0
        generated_count = 0
        unknown_count = 0

        source_version, min_api = self._determine_versions(path.name)

        try:
            with open(path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('%'):
                        continue
                    
                    # Example line: <android.location.LocationManager: android.location.Location getLastKnownLocation(java.lang.String)> -> ACCESS_COARSE_LOCATION, ACCESS_FINE_LOCATION
                    if "->" not in line:
                        continue
                        
                    parsed_count += 1
                    
                    parts = line.split("->")
                    sig_part = parts[0].strip()
                    perms_part = parts[1].strip()
                    
                    if not sig_part.startswith('<') or not sig_part.endswith('>'):
                        skipped_count += 1
                        continue
                        
                    sig_inner = sig_part[1:-1]
                    if ":" not in sig_inner:
                        skipped_count += 1
                        continue
                        
                    class_name_full, target = sig_inner.split(":", 1)
                    class_name_full = class_name_full.strip()
                    target = target.strip()
                    
                    # Heuristically determine target kind for TXT
                    target_kind = "Method" if "(" in target else "Field"
                    
                    sig_info = self.extract_signature(class_name_full, target, target_kind)
                    if not sig_info:
                        logger.warning(f"Could not extract signature from: {class_name_full} -> {target}")
                        skipped_count += 1
                        continue
                        
                    perms = [p.strip() for p in perms_part.split(",")]
                    
                    for permission in perms:
                        # Sometimes permissions lack android.permission prefix in TXT, we standardise it
                        if not permission.startswith("android.permission.") and "." not in permission:
                            permission = "android.permission." + permission
                            
                        obj = {
                            "signature_info": sig_info,
                            "permission": permission,
                            "min_api": min_api,
                            "source_version": source_version
                        }
                        
                        record = self.create_record(obj)
                        if record.category == "Unknown":
                            unknown_count += 1

                        self.records.append(record)
                        generated_count += 1
        except Exception as e:
            logger.error(f"Malformed TXT file or error reading {path}: {e}")

        logger.info(f"TXT Rows parsed: {parsed_count}")
        logger.info(f"TXT Rows skipped: {skipped_count}")
        logger.info(f"TXT Rows generated: {generated_count}")
        logger.info(f"Unknown permissions: {unknown_count}")
        
        return parsed_count, skipped_count, generated_count, unknown_count

    def extract_signature(self, class_name_full: str, target: str, target_kind: str) -> Optional[Dict[str, str]]:
        """Extracts package, class, method, api_name, and api_type.
        
        Args:
            class_name_full (str): The fully qualified class name.
            target (str): The target method or field signature.
            target_kind (str): Either "Method" or "Field".
            
        Returns:
            Optional[Dict[str, str]]: Extracted signature details.
        """
        last_dot = class_name_full.rfind('.')
        if last_dot == -1:
            package_name = ""
            class_name = class_name_full
        else:
            package_name = class_name_full[:last_dot]
            class_name = class_name_full[last_dot+1:]

        package_name = " ".join(package_name.strip().split())
        class_name = " ".join(class_name.strip().split())
        
        if target_kind.lower() == "method":
            paren_idx = target.find('(')
            if paren_idx == -1:
                return None
            prefix = target[:paren_idx].strip()
            method_name = prefix.split(' ')[-1]
            api_type = "method"
        elif target_kind.lower() == "field":
            method_name = target.strip().split(' ')[-1]
            api_type = "field"
        else:
            return None

        return {
            "package_name": package_name,
            "class_name": class_name,
            "method_name": method_name,
            "api_name": method_name,
            "api_type": api_type
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
            sources=["PScout"],
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
        """Writes processed/pscout_import.csv using csv_utils.
        
        Returns:
            None
        """
        write_csv(self.output_file, self.records)
        logger.info("CSV written")

if __name__ == "__main__":
    importer = PScoutImporter()
    summary = importer.run()
    logger.info("Summary:")
    for k, v in summary.items():
        logger.info(f"  {k}: {v}")
