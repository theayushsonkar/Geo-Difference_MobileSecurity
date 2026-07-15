"""
Abstract base classes for the SDK detection pipeline.

Detectors     — produce DetectedLibrary lists from an APK directory.
Classifiers   — annotate DetectedLibrary lists with tracker information.

New detectors (e.g. LibRadar) implement BaseDetector.
New classifiers implement BaseClassifier.
Neither requires changes to inventory.py or any downstream module.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List

from sdk_detection.models import DetectedLibrary, DetectionContext


class BaseDetector(ABC):
    """
    Contract for SDK/library detectors.

    Implementations must be stateless after __init__.
    detect() must never raise — it should return an empty list on any failure.
    """

    @abstractmethod
    def detect(self, context: DetectionContext) -> List[DetectedLibrary]:
        """
        Detect third-party SDKs using the provided execution context.

        Args:
            context: DetectionContext encapsulating apk_path, decoded_dir,
                     and pre-parsed manifest/smali/meta evidence.

        Returns:
            List of DetectedLibrary objects, one per detected SDK.
            Empty list if nothing detected or on any error.
        """
