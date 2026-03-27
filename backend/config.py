"""
================================================================================
CONFIG — Zentrale Konfiguration des Forensic Analysis Systems
================================================================================
Dieses Modul ist der einzige Ort für alle konfigurierbaren Parameter des Systems.
Alle Werte werden aus Umgebungsvariablen geladen (mit sinnvollen Standardwerten),
sodass das System per .env-Datei oder Docker-Compose konfiguriert werden kann,
ohne den Quellcode anfassen zu müssen.

Aufgaben:
    - Verzeichnisstruktur definieren und bei Import automatisch anlegen
    - Tool-Pfade (UAC, Volatility) auflösen
    - LLM-, RAG-, API- und Anomalie-Parameter bereitstellen
    - Feature-Flags für optionale Systemkomponenten verwalten
    - Konfiguration als Dict exportieren und beim Start validieren

Verwendung:
    from backend.config import OLLAMA_BASE_URL, OUTPUT_DIR, FEATURES
    from backend.config import get_config, validate_config

Abhängigkeiten:
    - os, pathlib (stdlib)
    - python-dotenv (für .env-Datei, wird von uvicorn automatisch geladen)
    - requests (nur in validate_config für Ollama-Health-Check)

Kontext: LFX Forensic Analysis System — Bachelor-Arbeit Forensik-Tool
"""

from pathlib import Path
import os
from typing import Dict, Any


# ── Pfad-Konfiguration ────────────────────────────────────────────────────────
# BASE_DIR zeigt auf das Projekt-Root (zwei Ebenen über dieser Datei:
#   backend/config.py → backend/ → project-root/)
BASE_DIR = Path(__file__).parent.parent
BACKEND_DIR = BASE_DIR / "backend"
DATA_DIR = BASE_DIR / "data"
TOOLS_DIR = BASE_DIR / "tools"
LOGS_DIR = BASE_DIR / "logs"
PROMPTS_DIR = BASE_DIR / "prompts"
RAG_DIR = BASE_DIR / "rag"

# ── Data-Verzeichnisse ────────────────────────────────────────────────────────
# Unterverzeichnisse von DATA_DIR für die verschiedenen Daten-Kategorien
UPLOAD_DIR = DATA_DIR / "uploads"       # Hochgeladene Analyse-Dateien
OUTPUT_DIR = DATA_DIR / "outputs"       # Analyse-Ergebnisse pro Job
SAMPLES_DIR = DATA_DIR / "samples"      # Test-Samples (nicht in Git)
LLM_CACHE_DIR = DATA_DIR / "llm_cache"  # Gecachte LLM-Antworten

# ── RAG-Verzeichnisse ─────────────────────────────────────────────────────────
# Retrieval-Augmented-Generation: Wissensbasis und Vektor-Index
VECTOR_STORE_DIR = RAG_DIR / "vector_store"       # Faiss/Chroma Index
KNOWLEDGE_BASE_DIR = RAG_DIR / "knowledge_base"   # IOCs, MITRE, Malware-Signaturen
EMBEDDINGS_DIR = RAG_DIR / "embeddings"           # Vorberechnete Embeddings

# Alle benötigten Verzeichnisse beim Importieren dieses Moduls anlegen.
# parents=True: Erstellt fehlende Zwischenverzeichnisse.
# exist_ok=True: Kein Fehler, wenn Verzeichnis bereits existiert.
for directory in [
    UPLOAD_DIR, OUTPUT_DIR, SAMPLES_DIR, LLM_CACHE_DIR,
    LOGS_DIR, VECTOR_STORE_DIR, KNOWLEDGE_BASE_DIR, EMBEDDINGS_DIR
]:
    directory.mkdir(parents=True, exist_ok=True)

# ── Externe Tool-Pfade ────────────────────────────────────────────────────────
# UAC (Unix Artifact Collector) — Live-Forensik-Collection-Tool
# Volatility — RAM-Dump-Analyse (derzeit als optionales Feature geplant)
UAC_PATH = TOOLS_DIR / "uac" / "uac"
VOLATILITY_PATH = TOOLS_DIR / "volatility" / "vol.py"

# ── Datei-Limits ──────────────────────────────────────────────────────────────
# Schutzmechanismen gegen zu große Eingaben, die Speicher oder Disk füllen könnten
MAX_FILE_SIZE = int(os.getenv("MAX_FILE_SIZE", 10 * 1024 * 1024 * 1024))  # 10GB
MAX_TIMELINE_EVENTS = int(os.getenv("MAX_TIMELINE_EVENTS", 1_000_000))

# ── UAC-Konfiguration ─────────────────────────────────────────────────────────
# ir_triage = Incident-Response-Profil (sammelt die für IR relevantesten Artefakte)
UAC_PROFILE = os.getenv("UAC_PROFILE", "ir_triage")
UAC_TIMEOUT = int(os.getenv("UAC_TIMEOUT", 600))  # 10 Minuten

# ── Dissect-Konfiguration ─────────────────────────────────────────────────────
# Welche Dissect-Plugins bei der Artefakt-Extraktion ausgeführt werden sollen.
# Jedes Plugin entspricht einer Methode auf dem dissect.target.Target-Objekt.
DISSECT_PLUGINS = ["mft", "users", "services", "runkeys"]
DISSECT_TIMEOUT = int(os.getenv("DISSECT_TIMEOUT", 3600))  # 1 Stunde

# ── Sleuth Kit (TSK) Konfiguration ───────────────────────────────────────────
# TSK_MAX_DEPTH: Verhindert endlose Rekursion bei Symlink-Schleifen im Dateisystem
TSK_MAX_DEPTH = int(os.getenv("TSK_MAX_DEPTH", 10))
TSK_RECURSIVE = os.getenv("TSK_RECURSIVE", "true").lower() == "true"

# ── LLM-Konfiguration ─────────────────────────────────────────────────────────
# Ollama läuft lokal und stellt das LLM bereit. Standardmäßig llama3.1:8b,
# was auf normalen CPUs in akzeptabler Zeit läuft (~5–15 Minuten für einen Report).
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
DEFAULT_LLM_MODEL = os.getenv("DEFAULT_LLM_MODEL", "llama3.1:8b")
LLM_TIMEOUT = int(os.getenv("LLM_TIMEOUT", 600))  # 10 Minuten (CPU-Inferenz ist langsam)

# ── Threat Intelligence ───────────────────────────────────────────────────────
# AbuseIPDB-API-Key für IP-Reputation-Lookups (optionales Feature)
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

# Unterschiedliche Temperaturen je nach Aufgabe:
# - Anomalie-Erkennung: niedriger (deterministischer, präziser)
# - Timeline-Interpretation: mittel (ausgewogen)
# - Report-Generierung: mittel (flüssiger, lesbarer Text)
LLM_TEMPERATURE = {
    "anomaly_detection": float(os.getenv("LLM_TEMP_ANOMALY", 0.3)),
    "timeline_interpretation": float(os.getenv("LLM_TEMP_TIMELINE", 0.5)),
    "report_generation": float(os.getenv("LLM_TEMP_REPORT", 0.4)),
}

LLM_MAX_TOKENS = int(os.getenv("LLM_MAX_TOKENS", 2000))

# ── RAG-Konfiguration ─────────────────────────────────────────────────────────
# RAG (Retrieval-Augmented Generation): Relevante Wissensbasis-Chunks werden
# vor dem LLM-Aufruf gesucht und als Kontext beigefügt.
# RAG_TOP_K: Anzahl der ähnlichsten Chunks die abgerufen werden
# RAG_SIMILARITY_THRESHOLD: Minimaler Ähnlichkeitsscore (0–1) für einen Chunk
RAG_ENABLED = os.getenv("RAG_ENABLED", "true").lower() == "true"
RAG_TOP_K = int(os.getenv("RAG_TOP_K", 5))
RAG_SIMILARITY_THRESHOLD = float(os.getenv("RAG_SIMILARITY_THRESHOLD", 0.7))

# ── API-Konfiguration ─────────────────────────────────────────────────────────
# FastAPI / Uvicorn Server-Einstellungen
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", 8000))
API_WORKERS = int(os.getenv("API_WORKERS", 4))
API_RELOAD = os.getenv("API_RELOAD", "false").lower() == "true"

# ── CORS-Konfiguration ────────────────────────────────────────────────────────
# Im Development: "*" erlaubt (Frontend auf Port 5173 kann Backend auf 8000 ansprechen).
# In Produktion: Auf die tatsächliche Frontend-Domain einschränken.
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*").split(",")
CORS_ALLOW_CREDENTIALS = os.getenv("CORS_ALLOW_CREDENTIALS", "true").lower() == "true"

# ── Logging-Konfiguration ─────────────────────────────────────────────────────
# LOG_FORMAT "text" = menschenlesbar (für Development)
# LOG_FORMAT "json" = strukturiert (für Log-Aggregatoren wie ELK/Loki)
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FORMAT = os.getenv("LOG_FORMAT", "text")  # text oder json
LOG_FILE = LOGS_DIR / "forensic.log"

# ── Anomalie-Detection-Konfiguration ─────────────────────────────────────────
# ANOMALY_CONTAMINATION: Erwarteter Anteil anomaler Events im Datensatz (IsolationForest).
# 0.1 = ~10% der Events werden als Anomalie eingestuft.
# ANOMALY_THRESHOLD: Score-Grenzwert (0–1) ab dem ein Event als Anomalie gilt.
ANOMALY_CONTAMINATION = float(os.getenv("ANOMALY_CONTAMINATION", 0.1))
ANOMALY_THRESHOLD = float(os.getenv("ANOMALY_THRESHOLD", 0.5))

# ── Job-Konfiguration ─────────────────────────────────────────────────────────
# Jobs werden in-memory gespeichert (nicht persistent). Alte Job-Daten werden
# nach JOB_CLEANUP_DAYS Tagen aus dem Output-Verzeichnis gelöscht (Auto-Cleanup).
JOB_CLEANUP_DAYS = int(os.getenv("JOB_CLEANUP_DAYS", 7))  # Lösche Jobs nach 7 Tagen
JOB_MAX_CONCURRENT = int(os.getenv("JOB_MAX_CONCURRENT", 3))

# ── Security: Erlaubte Datei-Erweiterungen ───────────────────────────────────
# Nur diese Endungen dürfen über die API hochgeladen werden.
# Verhindert Upload von ausführbaren Dateien (.exe, .sh, .py).
ALLOWED_EXTENSIONS = {
    '.dd', '.raw', '.img', '.e01', '.ewf', '.vdi', '.vmdk',  # Disk Images
    '.vhdx', '.qcow2', '.aff',                               # Weitere Disk-Image-Formate
    '.log', '.txt', '.syslog', '.evtx',                      # Logs
    '.zip', '.tar', '.gz',                                   # Archives
}

# Pfade, auf die niemals direkt zugegriffen werden darf
# (z.B. beim Auslesen von Artefakten aus Live-Systemen)
BLOCKED_PATHS = [
    '/etc/shadow',
    '/etc/passwd',
    'C:\\Windows\\System32\\config\\SAM',
]

# ── Feature-Flags ─────────────────────────────────────────────────────────────
# Ermöglicht das gezielte Deaktivieren von Systemkomponenten ohne Code-Änderungen.
# Nützlich für Tests, Deployments ohne Ollama, oder ressourcenbeschränkte Umgebungen.
FEATURES = {
    "web_search": os.getenv("FEATURE_WEB_SEARCH", "false").lower() == "true",
    "llm_analysis": os.getenv("FEATURE_LLM_ANALYSIS", "true").lower() == "true",
    "rag": os.getenv("FEATURE_RAG", "true").lower() == "true",
    "anomaly_detection": os.getenv("FEATURE_ANOMALY_DETECTION", "true").lower() == "true",
    "auto_cleanup": os.getenv("FEATURE_AUTO_CLEANUP", "true").lower() == "true",
}


# ── Hilfsfunktionen ───────────────────────────────────────────────────────────

def get_config() -> Dict[str, Any]:
    """
    Gibt die komplette aktive Konfiguration als serialisierbares Dictionary zurück.

    Wird hauptsächlich für das /config-Endpunkt der API und für Debug-Ausgaben
    verwendet. Enthält keine Secrets (API-Keys werden nicht exportiert).

    Returns:
        Dictionary mit allen Konfigurations-Kategorien:
        directories, limits, llm, api, features
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
    """
    Validiert die Konfiguration beim System-Start und gibt Warnungen aus.

    Prüft:
    - Existenz des UAC-Binaries (optional, aber häufig benötigt)
    - Erreichbarkeit des Ollama-API-Endpunkts (non-blocking, nur Warnung)

    Diese Funktion blockiert den Start nicht bei Fehlern, da alle externen
    Tools als optional behandelt werden (Graceful Degradation).

    Returns:
        True wenn keine Fehler gefunden wurden, False bei Warnungen
    """
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


# ── Direkt-Ausführung (Debug-Ausgabe) ────────────────────────────────────────
# python backend/config.py → gibt die aktive Konfiguration aus und validiert sie
if __name__ == "__main__":
    print("=== Forensic Analysis System Configuration ===\n")
    config = get_config()

    import json
    print(json.dumps(config, indent=2))

    print("\n=== Validation ===")
    validate_config()
