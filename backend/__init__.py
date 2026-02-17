"""
Forensic Analysis System Backend.

Hauptmodul für forensische Analyse-Pipeline mit LLM-Integration.
"""

from .pipeline import run_pipeline
from .api import app
from .config import (
    BASE_DIR,
    UPLOAD_DIR,
    OUTPUT_DIR,
    MAX_FILE_SIZE,
    UAC_PATH
)

__version__ = "1.0.0"
__author__ = "Your Name"
__license__ = "MIT"

__all__ = [
    # Core Functions
    "run_pipeline",
    
    # API
    "app",
    
    # Config
    "BASE_DIR",
    "UPLOAD_DIR",
    "OUTPUT_DIR",
    "MAX_FILE_SIZE",
    "UAC_PATH",
]


# Package-level metadata
PACKAGE_INFO = {
    "name": "forensic-analysis-system",
    "version": __version__,
    "description": "Automated forensic analysis with LLM integration",
    "author": __author__,
    "license": __license__,
    "repository": "https://github.com/yourusername/forensic-analysis-system",
}


def get_version() -> str:
    """Returns package version."""
    return __version__


def get_info() -> dict:
    """Returns package metadata."""
    return PACKAGE_INFO.copy()