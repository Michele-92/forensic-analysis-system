"""
Zentrale Konfiguration für das Forensic Analysis System.
"""

from pathlib import Path
import os
from typing import Dict, Any

# Basis-Verzeichnisse
BASE_DIR = Path(__file__).parent.parent
BACKEND_DIR = BASE_DIR / "backend"
DATA_DIR = BASE_DIR / "data"
TOOLS_DIR = BASE_DIR / "tools"
LOGS_DIR = BASE_DIR / "logs"
PROMPTS_DIR = BASE_DIR / "prompts"
RAG_DIR = BASE_DIR / "rag"

# Data-Verzeichnisse
UPLOAD_DIR = DATA_DIR / "uploads"
OUTPUT_DIR = DATA_DIR / "outputs"
SAMPLES_DIR = DATA_DIR / "samples"
LLM_CACHE_DIR = DATA_DIR / "llm_cache"

# RAG-Verzeichnisse
VECTOR_STORE_DIR = RAG_DIR / "vector_store"
KNOWLEDGE_BASE_DIR = RAG_DIR / "knowledge_base"
EMBEDDINGS_DIR = RAG_DIR / "embeddings"

# Erstelle Verzeichnisse
for directory in [
    UPLOAD_DIR, OUTPUT_DIR, SAMPLES_DIR, LLM_CACHE_DIR,
    LOGS_DIR, VECTOR_STORE_DIR, KNOWLEDGE_BASE_DIR, EMBEDDINGS_DIR
]:
    directory.mkdir(parents=True, exist_ok=True)

# Tool-Pfade
UAC_PATH = TOOLS_DIR / "uac" / "uac"
VOLATILITY_PATH = TOOLS_DIR / "volatility" / "vol.py"

# Datei-Limits
MAX_FILE_SIZE = int(os.getenv("MAX_FILE_SIZE", 10 * 1024 * 1024 * 1024))  # 10GB
MAX_TIMELINE_EVENTS = int(os.getenv("MAX_TIMELINE_EVENTS", 1_000_000))

# UAC-Konfiguration
UAC_PROFILE = os.getenv("UAC_PROFILE", "ir_triage")
UAC_TIMEOUT = int(os.getenv("UAC_TIMEOUT", 600))  # 10 Minuten

# Dissect-Konfiguration
DISSECT_PLUGINS = ["mft", "evtx", "registry", "users"]
DISSECT_TIMEOUT = int(os.getenv("DISSECT_TIMEOUT", 3600))  # 1 Stunde

# TSK-Konfiguration
TSK_MAX_DEPTH = int(os.getenv("TSK_MAX_DEPTH", 10))
TSK_RECURSIVE = os.getenv("TSK_RECURSIVE", "true").lower() == "true"

# LLM-Konfiguration
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
DEFAULT_LLM_MODEL = os.getenv("DEFAULT_LLM_MODEL", "llama3.1")
LLM_TIMEOUT = int(os.getenv("LLM_TIMEOUT", 120))  # 2 Minuten

LLM_TEMPERATURE = {
    "anomaly_detection": float(os.getenv("LLM_TEMP_ANOMALY", 0.3)),
    "timeline_interpretation": float(os.getenv("LLM_TEMP_TIMELINE", 0.5)),
    "report_generation": float(os.getenv("LLM_TEMP_REPORT", 0.4)),
}

LLM_MAX_TOKENS = int(os.getenv("LLM_MAX_TOKENS", 2000))

# RAG-Konfiguration
RAG_ENABLED = os.getenv("RAG_ENABLED", "true").lower() == "true"
RAG_TOP_K = int(os.getenv("RAG_TOP_K", 5))
RAG_SIMILARITY_THRESHOLD = float(os.getenv("RAG_SIMILARITY_THRESHOLD", 0.7))

# API-Konfiguration
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", 8000))
API_WORKERS = int(os.getenv("API_WORKERS", 4))
API_RELOAD = os.getenv("API_RELOAD", "false").lower() == "true"

# CORS-Konfiguration
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*").split(",")
CORS_ALLOW_CREDENTIALS = os.getenv("CORS_ALLOW_CREDENTIALS", "true").lower() == "true"

# Logging-Konfiguration
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FORMAT = os.getenv("LOG_FORMAT", "text")  # text oder json
LOG_FILE = LOGS_DIR / "forensic.log"

# Anomalie-Detection-Konfiguration
ANOMALY_CONTAMINATION = float(os.getenv("ANOMALY_CONTAMINATION", 0.1))
ANOMALY_THRESHOLD = float(os.getenv("ANOMALY_THRESHOLD", 0.5))

# Job-Konfiguration
JOB_CLEANUP_DAYS = int(os.getenv("JOB_CLEANUP_DAYS", 7))  # Lösche Jobs nach 7 Tagen
JOB_MAX_CONCURRENT = int(os.getenv("JOB_MAX_CONCURRENT", 3))

# Security
ALLOWED_EXTENSIONS = {
    '.dd', '.raw', '.img', '.e01', '.ewf', '.vdi', '.vmdk',  # Disk Images
    '.mem', '.dmp', '.dump',  # Memory
    '.log', '.txt', '.syslog', '.evtx',  # Logs
    '.pcap', '.pcapng',  # Network
    '.zip', '.tar', '.gz',  # Archives
}

BLOCKED_PATHS = [
    '/etc/shadow',
    '/etc/passwd',
    'C:\\Windows\\System32\\config\\SAM',
]

# Feature-Flags
FEATURES = {
    "web_search": os.getenv("FEATURE_WEB_SEARCH", "false").lower() == "true",
    "llm_analysis": os.getenv("FEATURE_LLM_ANALYSIS", "true").lower() == "true",
    "rag": os.getenv("FEATURE_RAG", "true").lower() == "true",
    "anomaly_detection": os.getenv("FEATURE_ANOMALY_DETECTION", "true").lower() == "true",
    "auto_cleanup": os.getenv("FEATURE_AUTO_CLEANUP", "true").lower() == "true",
}


def get_config() -> Dict[str, Any]:
    """
    Gibt komplette Konfiguration als Dict zurück.
    
    Returns:
        Config-Dictionary
    """
    return {
        "directories": {
            "base": str(BASE_DIR),
            "upload": str(UPLOAD_DIR),
            "output": str(OUTPUT_DIR),
            "logs": str(LOGS_DIR),
        },
        "limits": {
            "max_file_size": MAX_FILE_SIZE,
            "max_timeline_events": MAX_TIMELINE_EVENTS,
        },
        "llm": {
            "model": DEFAULT_LLM_MODEL,
            "base_url": OLLAMA_BASE_URL,
            "temperature": LLM_TEMPERATURE,
            "max_tokens": LLM_MAX_TOKENS,
        },
        "api": {
            "host": API_HOST,
            "port": API_PORT,
            "workers": API_WORKERS,
        },
        "features": FEATURES,
    }


def validate_config():
    """Validiert Konfiguration beim Start."""
    errors = []
    
    # UAC-Binary-Check
    if not UAC_PATH.exists():
        errors.append(f"UAC-Binary nicht gefunden: {UAC_PATH}")
    
    # Ollama-Check (optional)
    import requests
    try:
        requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=2)
    except:
        errors.append(f"Ollama nicht erreichbar: {OLLAMA_BASE_URL}")
    
    if errors:
        print("⚠️  Konfigurationswarnungen:")
        for error in errors:
            print(f"  - {error}")
    
    return len(errors) == 0


# Beispiel-Usage
if __name__ == "__main__":
    print("=== Forensic Analysis System Configuration ===\n")
    config = get_config()
    
    import json
    print(json.dumps(config, indent=2))
    
    print("\n=== Validation ===")
    validate_config()