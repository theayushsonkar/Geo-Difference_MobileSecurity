"""
Google Play Services (GMS) Importer.

Parses local official GMS artifacts extracting classes.jar,
and parses Java bytecode deterministically to generate PrivacyAPIRecord objects.
Zero privacy heuristics or filtering logic is applied during import.
Fully offline implementation based on metadata/gms_artifacts.csv.
"""
import os
import pathlib
import datetime
import zipfile
import csv
import sys
from typing import List, Dict, Tuple, Any

from jawa.cf import ClassFile

from knowledge_base.config import RAW_DIR, BUILD_OUTPUTS_DIR
from knowledge_base.schemas.privacy_api_schema import PrivacyAPIRecord
from knowledge_base.logger import get_logger
from knowledge_base.utils.csv_utils import write_csv

logger = get_logger(__name__)

class GMSImporter:
    """Importer for processing Google Play Services artifacts into PrivacyAPIRecord format (Offline)."""

    def __init__(self) -> None:
        """Initializes the offline GMS importer."""
        self.raw_dir: pathlib.Path = RAW_DIR / "gms"
        self.metadata_file: pathlib.Path = pathlib.Path("d:/New folder/Geo-Difference_MobileSecurity/knowledge_base/metadata/gms_artifacts.csv")
        self.output_file: pathlib.Path = BUILD_OUTPUTS_DIR / "gms_import.csv"
        self.manifest_file: pathlib.Path = BUILD_OUTPUTS_DIR / "gms_manifest.csv"
        self.records: List[PrivacyAPIRecord] = []
        self.manifest_data: List[Dict[str, Any]] = []

    def load_metadata(self) -> List[Dict[str, str]]:
        """Reads enabled artifacts from the metadata CSV."""
        artifacts = []
        if not self.metadata_file.exists():
            logger.error(f"Metadata file not found: {self.metadata_file}")
            sys.exit(1)
            
        with open(self.metadata_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row.get("enabled", "").strip().lower() == "true":
                    artifacts.append(row)
        return artifacts

    def validate_inputs(self, artifacts: List[Dict[str, str]]) -> None:
        """Validates that all required AAR files exist locally."""
        missing = []
        for row in artifacts:
            filename = row.get("file", "")
            if not filename.endswith(".aar"):
                missing.append(f"{filename} (Not .aar)")
                continue
                
            path = self.raw_dir / filename
            if not path.exists():
                missing.append(filename)
                
        if missing:
            logger.error("Missing required GMS artifacts:")
            for m in missing:
                logger.error(f"  - {m}")
            logger.error("Terminating gracefully. Please ensure all enabled artifacts are present in raw/gms/")
            sys.exit(1)
            
        logger.info("All enabled artifacts are present locally.")

    def process_artifact(self, row: Dict[str, str]) -> Dict[str, int]:
        """Extracts and parses classes.jar from the AAR."""
        artifact = row["artifact"]
        version = row["version"]
        framework = row["framework"]
        filename = row["file"]
        
        logger.info(f"Processing {artifact} v{version}")
        
        aar_path = self.raw_dir / filename
        classes_jar_path = self.raw_dir / f"{artifact}-{version}-classes.jar"
        
        if not classes_jar_path.exists():
            with zipfile.ZipFile(aar_path, "r") as z:
                with z.open("classes.jar") as src, open(classes_jar_path, "wb") as dst:
                    dst.write(src.read())
                    
        class_count = 0
        method_count = 0
        field_count = 0
        records_generated = 0
        
        with zipfile.ZipFile(classes_jar_path, "r") as jar:
            for item in jar.namelist():
                if item.endswith(".class"):
                    with jar.open(item) as f:
                        try:
                            cf = ClassFile(f)
                        except Exception as e:
                            logger.error(f"Malformed class {item} in {artifact}: {e}")
                            continue
                            
                        if not cf.access_flags.acc_public:
                            continue
                            
                        class_count += 1
                        
                        full_class_name = cf.this.name.value.replace("/", ".")
                        parts = full_class_name.rsplit(".", 1)
                        if len(parts) == 2:
                            package_name, class_name = parts
                        else:
                            package_name, class_name = "", full_class_name
                            
                        for m in cf.methods:
                            if m.access_flags.acc_public:
                                method_count += 1
                                self.create_record(artifact, version, framework, package_name, class_name, m.name.value, "method")
                                records_generated += 1
                                
                        for fd in cf.fields:
                            if fd.access_flags.acc_public:
                                field_count += 1
                                self.create_record(artifact, version, framework, package_name, class_name, fd.name.value, "field")
                                records_generated += 1
                                
        self.manifest_data.append({
            "artifact": artifact,
            "version": version,
            "classes": class_count,
            "methods": method_count,
            "fields": field_count,
            "records_generated": records_generated
        })
        
        return {
            "classes": class_count,
            "methods": method_count,
            "fields": field_count,
            "records": records_generated
        }

    def create_record(self, artifact: str, version: str, framework: str, pkg: str, cls: str, api: str, api_type: str) -> None:
        """Converts extracted data into a canonical PrivacyAPIRecord."""
        import_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        record = PrivacyAPIRecord(
            record_id="",
            category="Unknown",
            subcategory="Unknown",
            framework=framework,
            package_name=pkg,
            class_name=cls,
            method_name=api,
            api_name=api,
            api_type=api_type,
            permission="",
            sources=["Google Maven"],
            source_versions=[version],
            supported_android_versions=[],
            import_timestamp=import_timestamp,
            min_android_api=None,
            max_android_api=None,
            confidence="Medium",
            deprecated=False,
            documentation_url="",
            notes=artifact
        )
        self.records.append(record)

    def deduplicate(self) -> int:
        """Merges duplicate APIs."""
        unique_records: Dict[Tuple[str, str, str], PrivacyAPIRecord] = {}
        duplicates = 0
        
        for record in self.records:
            key = (record.package_name, record.class_name, record.method_name)
            if key not in unique_records:
                unique_records[key] = record
            else:
                duplicates += 1
                
        self.records = list(unique_records.values())
        logger.info(f"Duplicates merged: {duplicates}")
        return duplicates

    def run(self) -> Dict[str, Any]:
        """Main pipeline execution."""
        logger.info("GMS Importer started (Offline Mode)")
        
        artifacts = self.load_metadata()
        self.validate_inputs(artifacts)
        
        total_classes = 0
        total_methods = 0
        total_fields = 0
        
        for row in artifacts:
            try:
                stats = self.process_artifact(row)
                total_classes += stats["classes"]
                total_methods += stats["methods"]
                total_fields += stats["fields"]
            except Exception as e:
                logger.error(f"Failed to process {row['artifact']}: {e}")
                
        duplicates = self.deduplicate()
        
        write_csv(self.output_file, self.records)
        if self.manifest_data:
            with open(self.manifest_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=self.manifest_data[0].keys())
                writer.writeheader()
                writer.writerows(self.manifest_data)
        
        logger.info(f"Importer completed. {len(self.records)} unique records generated.")
        return {
            "artifacts_processed": len(self.manifest_data),
            "classes_parsed": total_classes,
            "methods_parsed": total_methods,
            "fields_parsed": total_fields,
            "duplicates_removed": duplicates,
            "unique_records": len(self.records)
        }

if __name__ == "__main__":
    importer = GMSImporter()
    summary = importer.run()
    logger.info("Summary:")
    for k, v in summary.items():
        logger.info(f"  {k}: {v}")
