"""Dataset Manager for handling dataset directories."""
import pathlib
from typing import Dict, Any

from knowledge_base.config import (
    RAW_DIR,
    PROCESSED_DIR,
    AXPLORER_DIR,
    PSCOUT_DIR,
    GMS_DIR
)
from knowledge_base.logger import get_logger
from knowledge_base.version import KB_VERSION
import json
import csv
import hashlib
from typing import List, TypeVar, Type, Callable, Optional

try:
    import geoip2.database
    _GEOIP2_AVAILABLE = True
except ImportError:
    _GEOIP2_AVAILABLE = False

from pcap.schemas import TrackerFact, DNSResolverFact

logger = get_logger(__name__)

class DatasetManager:
    """Manages the creation and verification of dataset directories."""

    def __init__(self) -> None:
        """Initializes the DatasetManager and sets dataset paths."""
        self._dataset_paths: Dict[str, pathlib.Path] = {
            "axplorer": AXPLORER_DIR,
            "pscout": PSCOUT_DIR,
            "gms": GMS_DIR
        }

    def ensure_directories(self) -> None:
        """Creates all required directories if they do not exist.
        
        Returns:
            None
        """
        RAW_DIR.mkdir(parents=True, exist_ok=True)
        PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
        (RAW_DIR / "geolite2").mkdir(parents=True, exist_ok=True)
        
        for path in self._dataset_paths.values():
            path.mkdir(parents=True, exist_ok=True)

    def get_dataset_path(self, dataset_name: str) -> pathlib.Path:
        """Returns the Path object of the requested dataset.
        
        Args:
            dataset_name (str): The name of the dataset.
            
        Returns:
            pathlib.Path: The absolute path to the dataset directory.
            
        Raises:
            ValueError: If the dataset name is unknown.
        """
        if dataset_name not in self._dataset_paths:
            raise ValueError(f"Unknown dataset name: {dataset_name}")
        return self._dataset_paths[dataset_name]

    def dataset_exists(self, dataset_name: str) -> bool:
        """Checks if a given dataset directory exists.
        
        Args:
            dataset_name (str): The name of the dataset.
            
        Returns:
            bool: True if the dataset directory exists, False otherwise.
        """
        path = self.get_dataset_path(dataset_name)
        return path.exists() and path.is_dir()

    def dataset_is_empty(self, dataset_name: str) -> bool:
        """Checks if the given dataset directory is empty.
        
        Args:
            dataset_name (str): The name of the dataset.
            
        Returns:
            bool: True if the dataset directory is empty (ignoring .gitkeep), False otherwise.
        """
        path = self.get_dataset_path(dataset_name)
        if not path.exists():
            return True
        for item in path.iterdir():
            if item.name != ".gitkeep":
                return False
        return True

    def get_status(self) -> Dict[str, Any]:
        """Returns the status of all datasets.
        
        Returns:
            Dict[str, Any]: A dictionary containing knowledge base version and individual dataset statuses.
        """
        status: Dict[str, Dict[str, Any]] = {}
        for name in self._dataset_paths:
            status[name] = {
                "path": str(self.get_dataset_path(name)),
                "exists": self.dataset_exists(name),
                "empty": self.dataset_is_empty(name)
            }
        
        return {
            "knowledge_base_version": KB_VERSION,
            "datasets": status
        }

    def _verify_sha256(self, file_path: pathlib.Path, expected_hash: str) -> None:
        """Verifies the SHA256 hash of a file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        actual_hash = sha256_hash.hexdigest()
        if actual_hash != expected_hash:
            raise ValueError(f"Hash mismatch for {file_path}. Expected: {expected_hash}, Actual: {actual_hash}")

    def load_network_trackers(self) -> List[TrackerFact]:
        """Loads and validates the tracker network dataset."""
        network_dir = pathlib.Path(__file__).parent / "network"
        metadata_path = network_dir / "metadata" / "metadata.json"
        
        if not metadata_path.exists():
            raise FileNotFoundError(f"Network metadata not found at {metadata_path}")
            
        with open(metadata_path, 'r', encoding='utf-8') as f:
            metadata = json.load(f)
            
        tracker_meta = metadata.get("trackers", {})
        expected_hash = tracker_meta.get("sha256")
        
        csv_path = network_dir / "processed" / "trackers.csv"
        if not csv_path.exists():
            raise FileNotFoundError(f"Processed tracker CSV not found at {csv_path}")
            
        if expected_hash:
            self._verify_sha256(csv_path, expected_hash)
            
        facts = []
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                fact = TrackerFact(
                    domain_suffix=row['domain_suffix'],
                    vendor=row['vendor'],
                    canonical_vendor=row['canonical_vendor'],
                    category=row['category'],
                    source_dataset=row['source_dataset'],
                    source_version=row.get('source_version', '')
                )
                facts.append(fact)
                
        return facts

    def load_dns_resolvers(self) -> List[DNSResolverFact]:
        """Loads and validates the DNS resolver dataset."""
        network_dir = pathlib.Path(__file__).parent / "network"
        csv_path = network_dir / "processed" / "dns_resolvers.csv"
        
        if not csv_path.exists():
            raise FileNotFoundError(f"Processed DNS resolver CSV not found at {csv_path}")
            
        facts = []
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                fact = DNSResolverFact(
                    ip_address=row['ip_address'],
                    provider=row['provider'],
                    canonical_provider=row.get('canonical_provider', row['provider']),
                    resolver_name=row['resolver_name'],
                    provider_country=row['provider_country'],
                    supports_doh=row.get('supports_doh', 'false').lower() == 'true',
                    supports_dot=row.get('supports_dot', 'false').lower() == 'true',
                    supports_dnscrypt=row.get('supports_dnscrypt', 'false').lower() == 'true',
                    source_dataset=row.get('source_dataset', ''),
                    source_version=row.get('source_version', ''),
                    confidence=row.get('confidence', 'MEDIUM')
                )
                facts.append(fact)
                
        return facts

    def load_geolite(self) -> Optional["GeoMapper"]:
        """Loads GeoLite2 databases and returns a GeoMapper instance."""
        if not _GEOIP2_AVAILABLE:
            logger.warning("geoip2 module not installed. GeoLite2 lookups disabled.")
            return None
            
        geolite_dir = RAW_DIR / "geolite2"
        country_db = geolite_dir / "GeoLite2-Country.mmdb"
        asn_db = geolite_dir / "GeoLite2-ASN.mmdb"
        
        if not country_db.exists():
            raise FileNotFoundError(f"GeoLite2-Country database not found at {country_db}")
        if not asn_db.exists():
            raise FileNotFoundError(f"GeoLite2-ASN database not found at {asn_db}")
            
        # Initialize readers (DatasetManager validates and initializes, GeoMapper consumes them)
        country_reader = geoip2.database.Reader(str(country_db))
        asn_reader = geoip2.database.Reader(str(asn_db))
        
        from pcap.matchers.geo_mapper import GeoMapper
        return GeoMapper(country_reader, asn_reader)

    def load_pii_patterns(self) -> list[dict]:
        """Loads PII patterns from the processed KB directory."""
        network_dir = pathlib.Path(__file__).parent / "network"
        csv_path = network_dir / 'processed' / 'pii_patterns.csv'
        if not csv_path.exists():
            logger.warning(f"PII patterns file not found at {csv_path}")
            return []
            
        patterns = []
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                patterns.append(row)
        
        logger.info(f"Loaded {len(patterns)} PII patterns from KB.")
        return patterns

if __name__ == "__main__":
    manager = DatasetManager()
    manager.ensure_directories()
    
    logger.info("Dataset Status")
    status = manager.get_status()
    logger.info(f"Knowledge Base Version: {status['knowledge_base_version']}")
    for name, info in status['datasets'].items():
        logger.info(f"{name.capitalize()}")
        logger.info(f"Exists : {info['exists']}")
        logger.info(f"Empty  : {info['empty']}")
        logger.info(f"Path   : {info['path']}")
