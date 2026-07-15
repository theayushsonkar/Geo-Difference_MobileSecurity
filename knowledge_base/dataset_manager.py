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
