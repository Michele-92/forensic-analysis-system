"""
Utility Functions und Helper-Klassen.

Enthält:
- File Detector: Dateityp-Erkennung
- Logger: Logging-Setup
"""

from .file_detector import detect_input_type, FileTypeDetector
from .logger import setup_logger, get_logger

__all__ = [
    # File Detection
    "detect_input_type",
    "FileTypeDetector",

    # Logging
    "setup_logger",
    "get_logger",
]