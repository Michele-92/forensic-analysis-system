"""
================================================================================
FASTAPI REST-SERVER — Forensic Analysis System Backend
================================================================================
Haupt-API-Server der Forensik-Plattform. Empfängt Datei-Uploads, startet die
8-stufige Analyse-Pipeline im Hintergrund und stellt alle Ergebnisse bereit.

Job-Tracking erfolgt im Arbeitsspeicher (dict 'jobs'). Ergänzend wird nach
jeder abgeschlossenen Analyse eine job_meta.json auf Disk geschrieben, damit
Jobs auch nach einem Server-Neustart per _resolve_job() wiederhergestellt
werden können. Eine vollständige Redis-Integration ist für die Zukunft geplant.

API-Endpunkte (Übersicht):
    POST   /analyze                          → Datei hochladen, Analyse starten (→ job_id)
    GET    /status/{job_id}                  → Analyse-Fortschritt abfragen (0–100 %)
    GET    /results/{job_id}                 → Output-Dateien eines abgeschlossenen Jobs
    GET    /download/{job_id}/{filename}     → Einzelne Output-Datei herunterladen
    GET    /system-profile/{job_id}          → Automatisch erstelltes System-Profil
    GET    /antiforensics/{job_id}           → Anti-Forensics-Befunde (Timestomping, Wiping …)
    POST   /verify/{job_id}                  → MD5+SHA256 Integritätsprüfung der Quelldatei
    POST   /threat-intel/lookup              → IOC-Abgleich gegen Knowledge-Base / AbuseIPDB
    POST   /llm-analyze                      → Schnelle LLM-Analyse via Ollama (synchron)
    POST   /export-pdf/{job_id}             → Standard PDF-Report generieren (ReportLab)
    POST   /export-full-pdf/{job_id}        → Vollständiger PDF-Report inkl. Multi-Agent-KI
    GET    /agent-analyze/{job_id}          → Multi-Agent SSE-Stream (Triage → DFIR → Reporter)
    POST   /case-correlate                  → Fallübergreifende Korrelationsanalyse (SSE)
    POST   /export-case-pdf                 → Fall-Korrelations-PDF generieren
    POST   /cases                           → Neuen Fall erstellen (persistente Speicherung)
    GET    /cases                           → Alle Fälle auflisten
    GET    /cases/{case_id}                 → Einzelnen Fall abrufen
    PUT    /cases/{case_id}                 → Fall-Metadaten aktualisieren
    DELETE /cases/{case_id}                 → Fall löschen (nur Metadaten)
    POST   /cases/{case_id}/jobs/{job_id}   → Job einem Fall zuordnen
    DELETE /cases/{case_id}/jobs/{job_id}   → Job-Zuordnung aufheben
    GET    /                                → API-Info und Endpunkt-Übersicht

Abhängigkeiten:
    - fastapi, uvicorn
    - pipeline.run_pipeline         (8-stufige Analyse-Pipeline)
    - modules.evidence_tracker      (MD5/SHA256 Dual-Hash + Audit-Trail)
    - modules.pdf_generator         (ForensicPDFGenerator, CasePDFGenerator via ReportLab)
    - modules.threat_intel          (ThreatIntelLookup)
    - llm_agent.ollama_client       (OllamaClient — direkter Ollama-HTTP-Client)
    - llm_agent.multi_agent         (MultiAgentOrchestrator — 3-Agenten-Pipeline)
    - llm_agent.case_correlator     (CaseCorrelationAgent)

Kontext: LFX Forensic Analysis System — Bachelor-Arbeit, API-Schicht
"""

from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse, FileResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Optional
from pathlib import Path
import sys
import shutil
import uuid
import json
import logging
from datetime import datetime

# ── Python-Path-Initialisierung ───────────────────────────────────────────────
# Stelle sicher, dass backend/ im Python-Path ist (egal von wo gestartet)
BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from pipeline import run_pipeline, detect_input_type
from modules.evidence_tracker import EvidenceTracker

# ── FastAPI-Anwendung ─────────────────────────────────────────────────────────
app = FastAPI(title="Forensic Analysis API", version="1.0.0")

# CORS für Frontend (erlaubt Zugriff von beliebigen Origins inkl. localhost:5173)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,   # False bei allow_origins=["*"] (Browser-Kompatibilität)
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Logging-Konfiguration ─────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s.%(msecs)03d | API | %(levelname)-8s | %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

# ── Verzeichnis-Setup ─────────────────────────────────────────────────────────
# Absolute Pfade basierend auf Projektstruktur (funktioniert egal wo uvicorn gestartet wird)
PROJECT_ROOT = BACKEND_DIR.parent
DATA_DIR = PROJECT_ROOT / "data"
UPLOAD_DIR = DATA_DIR / "uploads"    # Hochgeladene Quelldateien
OUTPUT_DIR = DATA_DIR / "outputs"    # Analyse-Ergebnisse, je ein Unterverzeichnis pro job_id
CASES_DIR = DATA_DIR / "cases"       # Fall-Metadaten als JSON-Dateien

# Verzeichnisse anlegen falls nicht vorhanden
for directory in [DATA_DIR, UPLOAD_DIR, OUTPUT_DIR, CASES_DIR]:
    directory.mkdir(exist_ok=True, parents=True)

logger.info(f"PROJECT_ROOT: {PROJECT_ROOT}")
logger.info(f"UPLOAD_DIR:   {UPLOAD_DIR}")
logger.info(f"OUTPUT_DIR:   {OUTPUT_DIR}")

# ── In-Memory Job-Tracking ────────────────────────────────────────────────────
# Speichert den Zustand aller laufenden und abgeschlossenen Analyse-Jobs.
# Schlüssel: job_id (str), Wert: dict mit Status, Fortschritt, Metadaten.
# WICHTIG: Dieser Dict wird bei Server-Neustart geleert.
# Fallback: job_meta.json auf Disk (wird von _resolve_job() gelesen).
jobs = {}


# ── Hilfsfunktionen ───────────────────────────────────────────────────────────

def _resolve_job(job_id: str) -> dict:
    """Gibt Job-Metadaten zurück – aus Memory oder job_meta.json (Fallback nach Neustart)."""
    if job_id in jobs:
        return jobs[job_id]
    meta_file = OUTPUT_DIR / job_id / "job_meta.json"
    if meta_file.exists():
        return json.loads(meta_file.read_text(encoding="utf-8"))
    raise HTTPException(status_code=404, detail="Job nicht gefunden")


# ── Datei-Upload & Analyse-Start ──────────────────────────────────────────────

@app.post("/analyze")
async def analyze_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...)
):
    """
    Nimmt eine forensische Datei entgegen und startet die Analyse-Pipeline.

    Die Datei wird temporär in UPLOAD_DIR gespeichert, eine eindeutige
    job_id vergeben und die 8-stufige Pipeline als Hintergrundtask gestartet.
    Der Client pollt danach GET /status/{job_id}, bis progress=100 erreicht ist.

    Unterstützte Formate:
        - Disk-Images: .dd, .raw, .img, .e01, .ewf, .vdi, .vmdk, .vhdx, .qcow2, .aff
        - Logs:        .log, .syslog, .txt, .evtx
        - Archive:     .zip, .tar, .gz

    Args:
        file: Hochgeladene forensische Datei (Disk-Image, Log-Archiv, UAC-Dump)

    Returns:
        JSON mit job_id, erkanntem input_type, MD5+SHA256, Status "processing"

    HTTP: 202 Accepted
    """
    try:
        # Generiere eindeutige Job-ID mit Timestamp-Präfix für bessere Sortierbarkeit
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        job_id = f"{timestamp}_{str(uuid.uuid4())[:8]}"

        # Hochgeladene Datei mit konsistentem Pfad (job_id_originalname) speichern
        file_path = UPLOAD_DIR / f"{job_id}_{file.filename}"
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        file_size = file_path.stat().st_size
        logger.info(f"✓ Datei hochgeladen: {file.filename} ({file_size} bytes)")
        logger.info(f"  Job-ID: {job_id}")

        # Evidence Integrity: MD5 + SHA256 Dual-Hash berechnen
        file_hashes = EvidenceTracker.compute_dual_hash(file_path)
        logger.info(f"  MD5:    {file_hashes['md5']}")
        logger.info(f"  SHA256: {file_hashes['sha256']}")

        # Erkenne Input-Typ (disk_image / logs / uac_dump / ram_dump) mit Logging
        input_type = detect_input_type(file_path)
        logger.info(f"✓ Input-Typ erkannt: {input_type}")

        # Audit-Trail starten — erster Eintrag: Datei-Upload mit Hashes
        audit_trail = [
            EvidenceTracker.create_audit_entry("upload", {
                "filename": file.filename,
                "file_size": file_size,
                "md5_hash": file_hashes["md5"],
                "sha256_hash": file_hashes["sha256"],
            })
        ]

        # Job-Status mit erweiterten Metadaten initialisieren
        jobs[job_id] = {
            "job_id": job_id,
            "status": "processing",
            "filename": file.filename,
            "input_type": input_type,
            "progress": 0,
            "created_at": datetime.now().isoformat(),
            "file_size": file_size,
            "file_hash": file_hashes["sha256"],   # Rückwärtskompatibilität
            "md5_hash": file_hashes["md5"],
            "sha256_hash": file_hashes["sha256"],
            "audit_trail": audit_trail,
            "output_path": None,
            "error": None
        }

        # Output-Verzeichnis anlegen und Analyse als Hintergrundtask starten
        output_path = OUTPUT_DIR / job_id
        output_path.mkdir(parents=True, exist_ok=True)
        background_tasks.add_task(run_analysis, job_id, file_path, output_path)

        logger.info(f"  → Analyse im Hintergrund gestartet")
        logger.info(f"  → Output wird gespeichert in: {output_path}")

        return JSONResponse({
            "job_id": job_id,
            "filename": file.filename,
            "input_type": input_type,
            "status": "processing",
            "progress": 0,
            "file_hash": file_hashes["sha256"],
            "md5_hash": file_hashes["md5"],
            "sha256_hash": file_hashes["sha256"],
            "message": "Analyse gestartet. Nutze /status/{job_id} zum Tracking.",
            "created_at": jobs[job_id]["created_at"]
        }, status_code=202)

    except Exception as e:
        logger.error(f"✗ Upload-Fehler: {e}")
        raise HTTPException(status_code=500, detail=str(e))


def run_analysis(job_id: str, file_path: Path, output_path: Path):
    """
    Hintergrundtask: Führt die vollständige 8-stufige Analyse-Pipeline aus.

    Wird von analyze_file() als BackgroundTask gestartet. Aktualisiert den
    Fortschritt im jobs-Dict während der Ausführung:
      10 % → Initialisierung
      20 % → Pipeline-Start
      90 % → Pipeline abgeschlossen
     100 % → Finalisierung & job_meta.json geschrieben

    Schritte:
        1. Detektiert Input-Typ (Disk-Image / Logs / UAC-Dump / RAM)
        2. Extrahiert Artefakte (Dissect + Sleuth Kit)
        3. Normalisiert alle Events in gemeinsames Schema
        4. Anomalie-Erkennung mit IsolationForest (ML)
        5. Filtert Top-1000-Events für KI-Analyse
        6. Generiert LLM-Report (Ollama/Llama 3.1)
        7. Exportiert alle Output-Dateien

    Args:
        job_id:      Eindeutige Job-ID (wird für Status-Updates verwendet)
        file_path:   Pfad zur hochgeladenen Quelldatei
        output_path: Zielverzeichnis für alle Output-Dateien
    """
    try:
        logger.info(f"=" * 80)
        logger.info(f"STARTE ANALYSE [Job: {job_id}]")
        logger.info(f"  Eingabe: {file_path.name}")
        logger.info(f"  Output: {output_path}")
        logger.info(f"=" * 80)

        jobs[job_id]["progress"] = 10
        logger.info(f"Progress: {jobs[job_id]['progress']}% - Initialisierung")

        # Audit-Trail: Analyse gestartet
        jobs[job_id]["audit_trail"].append(
            EvidenceTracker.create_audit_entry("analysis_started", {"output_path": str(output_path)})
        )

        logger.info(f"Progress: 20% - Starte Pipeline...")
        jobs[job_id]["progress"] = 20

        # Haupt-Pipeline ausführen — gibt dict mit allen Ergebnissen zurück
        result = run_pipeline(file_path, output_path)

        logger.info(f"Progress: 90% - Pipeline abgeschlossen")
        jobs[job_id]["progress"] = 90

        # Alle generierten Output-Dateien inventarisieren und loggen
        result_files = list(output_path.glob("*"))
        logger.info(f"✓ {len(result_files)} Output-Dateien erstellt:")
        for f in sorted(result_files):
            logger.info(f"  - {f.name} ({f.stat().st_size} bytes)")

        # Evidence Integrity: Beide Hashes nachträglich in analysis_summary.json einbetten
        summary_file = output_path / "analysis_summary.json"
        if summary_file.exists():
            summary_data = json.loads(summary_file.read_text(encoding="utf-8"))
            summary_data["file_hash"] = jobs[job_id].get("sha256_hash", "")
            summary_data["md5_hash"] = jobs[job_id].get("md5_hash", "")
            summary_data["sha256_hash"] = jobs[job_id].get("sha256_hash", "")
            summary_file.write_text(json.dumps(summary_data, indent=2, ensure_ascii=False), encoding="utf-8")

        # Audit-Trail: Analyse erfolgreich abgeschlossen
        jobs[job_id]["audit_trail"].append(
            EvidenceTracker.create_audit_entry("analysis_completed", {
                "result_files": [f.name for f in result_files],
            })
        )

        # Job-Status finalisieren
        jobs[job_id]["status"] = "completed"
        jobs[job_id]["progress"] = 100
        jobs[job_id]["output_path"] = str(output_path)
        jobs[job_id]["completed_at"] = datetime.now().isoformat()
        jobs[job_id]["result_files"] = [f.name for f in result_files]

        # job_meta.json speichern – ermöglicht Wiederherstellung nach Neustart
        # (wird von _resolve_job() gelesen, wenn job_id nicht mehr im Memory-Dict ist)
        meta_file = output_path / "job_meta.json"
        meta_file.write_text(json.dumps({
            "job_id": job_id,
            "status": "completed",
            "filename": jobs[job_id].get("filename", "Unbekannt"),
            "input_type": jobs[job_id].get("input_type", "Unbekannt"),
            "file_hash": jobs[job_id].get("sha256_hash", ""),
            "md5_hash": jobs[job_id].get("md5_hash", ""),
            "sha256_hash": jobs[job_id].get("sha256_hash", ""),
            "completed_at": jobs[job_id]["completed_at"],
        }, ensure_ascii=False, indent=2), encoding="utf-8")

        logger.info(f"=" * 80)
        logger.info(f"✓✓✓ ANALYSE ERFOLGREICH ABGESCHLOSSEN [Job: {job_id}]")
        logger.info(f"    Status: COMPLETED (100%)")
        logger.info(f"    Output-Verzeichnis: {output_path}")
        logger.info(f"=" * 80)

    except Exception as e:
        logger.error(f"=" * 80)
        logger.error(f"✗✗✗ ANALYSE FEHLGESCHLAGEN [Job: {job_id}]")
        logger.error(f"    Error: {str(e)}")
        logger.error(f"=" * 80)

        jobs[job_id]["status"] = "failed"
        jobs[job_id]["error"] = str(e)
        jobs[job_id]["failed_at"] = datetime.now().isoformat()


# ── Status-Abfrage ────────────────────────────────────────────────────────────

@app.get("/status/{job_id}")
async def get_status(job_id: str):
    """
    Gibt den aktuellen Status und Fortschritt eines Analyse-Jobs zurück.

    Der Client pollt diesen Endpoint im 2-Sekunden-Intervall (useJobs.js),
    bis progress=100 oder status="failed" gemeldet wird.

    Args:
        job_id: Eindeutige Job-ID (aus POST /analyze)

    Returns:
        Vollständiges Job-Dict mit status, progress, filename, timestamps, error

    HTTP: 200 OK | 404 Not Found
    """
    if job_id not in jobs:
        logger.warning(f"⚠ Status-Anfrage für unbekannte Job-ID: {job_id}")
        raise HTTPException(status_code=404, detail="Job nicht gefunden")

    job = jobs[job_id]
    logger.debug(f"✓ Status-Abfrage für Job {job_id}: {job['status']} ({job['progress']}%)")

    return JSONResponse(job)


# ── Datei-Download ────────────────────────────────────────────────────────────

@app.get("/download/{job_id}/{filename}")
async def download_result(job_id: str, filename: str):
    """
    Gibt eine einzelne Output-Datei eines abgeschlossenen Jobs zurück.

    Verfügbare Output-Dateien (abhängig von Input-Typ):
        - report.md               → Haupt-Forensikbericht (Markdown)
        - timeline.csv            → Timeline aller Events
        - anomalies_detected.json → ML-erkannte Anomalien mit Scores
        - interpretation.json     → LLM-Interpretation mit MITRE-Mapping
        - analysis_summary.json   → Zusammenfassung inkl. Datei-Hashes
        - ai_preprocessed.json    → Gefilterte Top-1000-Events für KI
        - normalized_output.json  → Alle normalisierten Events

    Args:
        job_id:   Eindeutige Job-ID
        filename: Name der gewünschten Output-Datei

    Returns:
        FileResponse mit der angeforderten Datei

    HTTP: 200 OK | 400 Bad Request (Job läuft noch) | 404 Not Found
    """
    if job_id not in jobs:
        logger.warning(f"⚠ Download-Anfrage für unbekannte Job-ID: {job_id}")
        raise HTTPException(status_code=404, detail="Job nicht gefunden")

    if jobs[job_id]["status"] != "completed":
        logger.warning(f"⚠ Download-Anfrage für nicht-fertige Analyse: {job_id}")
        raise HTTPException(status_code=400, detail=f"Analyse noch nicht abgeschlossen (Status: {jobs[job_id]['status']})")

    file_path = OUTPUT_DIR / job_id / filename

    if not file_path.exists():
        logger.warning(f"⚠ Download: Datei nicht gefunden: {file_path}")
        raise HTTPException(status_code=404, detail=f"Datei nicht gefunden: {filename}")

    logger.info(f"✓ Download: {filename} ({file_path.stat().st_size} bytes)")
    return FileResponse(file_path, filename=filename)


# ── Ergebnisübersicht ─────────────────────────────────────────────────────────

@app.get("/results/{job_id}")
async def get_results(job_id: str):
    """
    Gibt eine Übersicht aller verfügbaren Output-Dateien eines abgeschlossenen Jobs.

    Solange die Analyse noch läuft, wird ein Zwischen-Status mit progress zurückgegeben.
    Nach Abschluss enthält die Antwort die vollständige Dateiliste mit Download-URLs.

    Args:
        job_id: Eindeutige Job-ID

    Returns:
        JSON mit status, output_files (Liste), download_urls (Liste), Zeitstempeln

    HTTP: 200 OK | 404 Not Found
    """
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job nicht gefunden")

    job = jobs[job_id]

    if job["status"] != "completed":
        return JSONResponse({
            "job_id": job_id,
            "status": job["status"],
            "progress": job["progress"],
            "message": f"Analyse läuft noch... ({job['progress']}%)"
        })

    output_path = OUTPUT_DIR / job_id
    result_files = sorted([f.name for f in output_path.glob("*")])

    logger.info(f"✓ Results-Abfrage für Job {job_id}: {len(result_files)} Dateien")

    return JSONResponse({
        "job_id": job_id,
        "status": "completed",
        "progress": 100,
        "created_at": job.get("created_at"),
        "completed_at": job.get("completed_at"),
        "input_file": job.get("filename"),
        "input_type": job.get("input_type"),
        "file_size": job.get("file_size"),
        "output_files": result_files,
        "download_urls": [f"/download/{job_id}/{f}" for f in result_files]
    })


# ── System-Profil ─────────────────────────────────────────────────────────────

@app.get("/system-profile/{job_id}")
async def get_system_profile(job_id: str):
    """
    Gibt das automatisch erstellte System-Profil für einen Job zurück.

    Das Profil wird während der Pipeline-Stage SYSTEM_PROFILING (5b) erstellt
    und in system_profile.json gespeichert. Es enthält:
        - OS-Typ, Distribution, Kernel-Version
        - Hostname, Zeitzone
        - Benutzerliste (Top-20 nach Häufigkeit)
        - Installierte Pakete und laufende Dienste
        - Netzwerk-Interfaces / IPs
        - Verdächtige Verzeichnisse (/tmp, /dev/shm, …)
        - Konfidenz-Bewertung (high / medium / low)

    Args:
        job_id: Eindeutige Job-ID

    Returns:
        JSON mit system_profile-Objekt

    HTTP: 200 OK | 404 Not Found (Analyse noch nicht abgeschlossen oder kein Profil erzeugt)
    """
    job = _resolve_job(job_id)
    profile_file = OUTPUT_DIR / job_id / "system_profile.json"

    if not profile_file.exists():
        raise HTTPException(
            status_code=404,
            detail="System-Profil nicht gefunden. Analyse noch nicht abgeschlossen?"
        )

    profile = json.loads(profile_file.read_text(encoding="utf-8"))
    return JSONResponse({"job_id": job_id, "system_profile": profile})


# ── Anti-Forensics ────────────────────────────────────────────────────────────

@app.get("/antiforensics/{job_id}")
async def get_antiforensics(job_id: str):
    """
    Gibt den Anti-Forensics-Report für einen Job zurück.

    Der Report wird während der Pipeline-Stage ANTI_FORENSICS_CHECK (5c) erstellt
    und in antiforensics_report.json gespeichert. Er enthält:
        - findings:    Liste der erkannten Manipulations-Hinweise
        - risk_score:  0–100 (je höher, desto mehr Spuren verwischt)
        - risk_level:  none / low / medium / high / critical
        - summary:     Zusammenfassung in lesbarem Text

    Erkannte Kategorien:
        - timestomping:          Manipulierte Datei-Zeitstempel (mtime < ctime)
        - log_gap:               Unerwartete Zeitlücken in der Timeline
        - timestamp_cluster:     Massenhafte identische Timestamps
        - wiping:                Bekannte Wipe-Tools (shred, srm, dd if=/dev/zero)
        - log_clearing:          Log- / History-Löschung
        - time_manipulation:     Systemzeit-Änderungen
        - rootkit_indicator:     LD_PRELOAD, insmod aus /tmp, /proc-Zugriffe
        - truncated_logs:        Leere /var/log-Dateien
        - suspicious_deletion:   rm -rf auf forensisch relevante Pfade

    Args:
        job_id: Eindeutige Job-ID

    Returns:
        JSON mit antiforensics-Objekt

    HTTP: 200 OK | 404 Not Found
    """
    job = _resolve_job(job_id)
    af_file = OUTPUT_DIR / job_id / "antiforensics_report.json"

    if not af_file.exists():
        raise HTTPException(
            status_code=404,
            detail="Anti-Forensics-Report nicht gefunden. Analyse noch nicht abgeschlossen?"
        )

    report = json.loads(af_file.read_text(encoding="utf-8"))
    return JSONResponse({"job_id": job_id, "antiforensics": report})


# ── Evidence Integrity / Verifikation ────────────────────────────────────────

@app.post("/verify/{job_id}")
async def verify_evidence(job_id: str):
    """
    Verifiziert die Integrität einer hochgeladenen Quelldatei.

    Berechnet MD5 + SHA256 der original Upload-Datei neu und vergleicht
    sie mit den beim Upload gespeicherten Referenzwerten. Erweitert den
    Audit-Trail mit dem Verifikationsergebnis.

    Wichtig für gerichtsfeste Dokumentation: Zeigt nach, dass die Datei
    seit dem Upload nicht manipuliert wurde.

    Args:
        job_id: Eindeutige Job-ID

    Returns:
        JSON mit verified (bool), original_/current_ MD5+SHA256, Audit-Trail

    HTTP: 200 OK | 400 Bad Request (kein Hash vorhanden) | 404 Not Found
    """
    job = _resolve_job(job_id)

    original_sha256 = job.get("sha256_hash") or job.get("file_hash", "")
    original_md5 = job.get("md5_hash", "")
    if not original_sha256:
        raise HTTPException(status_code=400, detail="Kein Hash fuer diesen Job vorhanden")

    # Originaldatei in UPLOAD_DIR finden (Format: {job_id}_{originalname})
    matching = list(UPLOAD_DIR.glob(f"{job_id}_*"))
    if not matching:
        raise HTTPException(status_code=404, detail="Upload-Datei nicht mehr vorhanden")

    file_path = matching[0]
    result = EvidenceTracker.verify_dual_hash(file_path, {
        "md5": original_md5,
        "sha256": original_sha256,
    })

    # Audit-Trail erweitern (nur wenn Job noch im Memory-Dict)
    if job_id in jobs:
        jobs[job_id].setdefault("audit_trail", []).append(
            EvidenceTracker.create_audit_entry("verification", {
                "md5_verified": result["md5_verified"],
                "sha256_verified": result["sha256_verified"],
                "overall": result["overall"],
            })
        )

    status = "BESTANDEN" if result["overall"] else "FEHLGESCHLAGEN"
    logger.info(f"Evidence-Verifikation Job {job_id}: {status}")

    return JSONResponse({
        "verified": result["overall"],
        "md5_verified": result["md5_verified"],
        "sha256_verified": result["sha256_verified"],
        "original_md5": original_md5,
        "original_sha256": original_sha256,
        "current_md5": result["current_md5"],
        "current_sha256": result["current_sha256"],
        "filename": job.get("filename"),
        "audit_trail": jobs[job_id].get("audit_trail", []) if job_id in jobs else [],
    })


# ── Threat Intelligence Lookup ────────────────────────────────────────────────

class ThreatIntelRequest(BaseModel):
    """
    Request-Modell für den IOC-Threat-Intelligence-Abgleich.

    Attributes:
        indicators: Dict mit kategorisierten IOCs, z.B.:
            {"ips": ["1.2.3.4"], "domains": ["evil.com"], "hashes": ["abc123"]}
    """
    indicators: Dict = {}  # {"ips": [...], "domains": [...], ...}


@app.post("/threat-intel/lookup")
def threat_intel_lookup(request: ThreatIntelRequest):
    """
    Gleicht IOCs gegen lokale Knowledge-Base und optional AbuseIPDB ab.

    Ruft ThreatIntelLookup aus modules/threat_intel.py auf und prüft
    IPs, Domains und Hashes gegen bekannte Bedrohungsdaten.

    Synchron (def statt async def) weil ThreatIntelLookup ggf. HTTP-Calls macht.

    Args:
        request: ThreatIntelRequest mit indicators-Dict

    Returns:
        JSON mit results-Liste (ein Eintrag pro IOC mit Bewertung)

    HTTP: 200 OK | 500 Internal Server Error
    """
    try:
        from modules.threat_intel import ThreatIntelLookup
        ti = ThreatIntelLookup()
        results = ti.lookup_batch(request.indicators)
        logger.info(f"Threat-Intel-Lookup: {len(results)} IOCs geprueft")
        return JSONResponse({"results": results})
    except Exception as e:
        logger.error(f"Threat-Intel-Lookup Fehler: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ── PDF-Report-Export ─────────────────────────────────────────────────────────

class PDFExportRequest(BaseModel):
    """
    Request-Modell für die PDF-Report-Generierung.

    Enthält optionale Metadaten für die gerichtsfeste Dokumentation.

    Attributes:
        case_name:      Name des Falles (erscheint auf Titelseite)
        case_number:    Aktenzeichen / Fallnummer
        analyst:        Name des Analysten / Gutachters
        qualifikation:  Gutachter-Qualifikation (für gerichtsfeste Reports)
        auftraggeber:   Auftraggeber, Gericht oder Institution
        ort_datum:      Unterschriftszeile, z.B. "München, 04.03.2026"
        unterschrift:   Getippter Name als digitale Signatur
        agent_analysis: Multi-Agent-Ergebnisse (nur für vollständigen Report)
    """
    case_name: Optional[str] = None
    case_number: Optional[str] = None
    analyst: Optional[str] = None
    qualifikation: Optional[str] = None   # Gutachter-Qualifikation (gerichtsfest)
    auftraggeber: Optional[str] = None    # Auftraggeber / Gericht / Institution
    ort_datum: Optional[str] = None       # z.B. "München, 04.03.2026"
    unterschrift: Optional[str] = None    # getippter Name als Signatur
    agent_analysis: Optional[Dict] = None # Multi-Agent Ergebnisse (nur für Vollständigen Report)


@app.post("/export-pdf/{job_id}")
def export_pdf(job_id: str, request: PDFExportRequest = None):
    """
    Generiert einen forensischen Standard-PDF-Report für einen abgeschlossenen Job.

    Lädt alle relevanten Output-Dateien (summary, anomalies, preprocessed)
    und gibt sie zusammen mit den Case-Metadaten an ForensicPDFGenerator weiter.
    Der Generator erstellt einen ReportLab-basierten PDF-Report.

    Synchron (def statt async def), da ReportLab blockierend ist und im
    Async-Event-Loop zu Problemen führen würde.

    Args:
        job_id:  Eindeutige Job-ID (muss status="completed" haben)
        request: Optionale PDF-Metadaten (Case-Name, Analyst, Auftraggeber …)

    Returns:
        FileResponse mit PDF (forensic_report_{job_id}.pdf)

    HTTP: 200 OK | 400 Bad Request (Analyse läuft noch) | 500 Internal Server Error
    """
    job_meta = _resolve_job(job_id)
    if job_meta.get("status") != "completed":
        raise HTTPException(status_code=400, detail="Analyse noch nicht abgeschlossen")

    output_path = OUTPUT_DIR / job_id

    # Basis-Jobdaten zusammenstellen
    job_data = {
        "job_id": job_id,
        "filename": job_meta.get("filename", "Unbekannt"),
        "input_type": job_meta.get("input_type", "Unbekannt"),
        "file_hash": job_meta.get("file_hash", ""),
        "md5_hash": job_meta.get("md5_hash", ""),
        "sha256_hash": job_meta.get("sha256_hash", "") or job_meta.get("file_hash", ""),
        "created_at": job_meta.get("created_at", ""),
    }

    # Case-Info aus Request übernehmen, falls angegeben
    if request:
        if request.case_name:
            job_data["case_name"] = request.case_name
        if request.case_number:
            job_data["case_number"] = request.case_number
        if request.analyst:
            job_data["analyst"] = request.analyst
        job_data["qualifikation"] = request.qualifikation or "Nicht angegeben"
        job_data["auftraggeber"] = request.auftraggeber or "Nicht angegeben"
        job_data["ort_datum"]    = request.ort_datum or ""
        job_data["unterschrift"] = request.unterschrift or ""

    # Analyse-Zusammenfassung laden
    summary_file = output_path / "analysis_summary.json"
    if summary_file.exists():
        job_data["summary"] = json.loads(summary_file.read_text(encoding="utf-8"))

    # ML-erkannte Anomalien laden (kann als Liste oder {"anomalies": [...]} vorliegen)
    anomalies_file = output_path / "anomalies_detected.json"
    if anomalies_file.exists():
        anomalies_data = json.loads(anomalies_file.read_text(encoding="utf-8"))
        job_data["anomalies"] = anomalies_data if isinstance(anomalies_data, list) else anomalies_data.get("anomalies", [])

    # Preprocessed-Daten für IOC-Liste laden
    preprocessed_file = output_path / "ai_preprocessed.json"
    if preprocessed_file.exists():
        preprocessed = json.loads(preprocessed_file.read_text(encoding="utf-8"))
        job_data["indicators"] = preprocessed.get("indicators", {})

    # Fundstellen-Nachweis laden (von ProvenanceEnricher in der Pipeline erstellt)
    provenance_file = output_path / "provenance.json"
    if provenance_file.exists():
        job_data["provenance"] = json.loads(provenance_file.read_text(encoding="utf-8"))

    try:
        from modules.pdf_generator import ForensicPDFGenerator
        generator = ForensicPDFGenerator()
        pdf_path = generator.generate(output_path, job_data)
        logger.info(f"PDF-Report generiert fuer Job {job_id}: {pdf_path}")
        return FileResponse(
            str(pdf_path),
            filename=f"forensic_report_{job_id}.pdf",
            media_type="application/pdf",
        )
    except Exception as e:
        logger.error(f"PDF-Generierung fehlgeschlagen: {e}")
        raise HTTPException(status_code=500, detail=f"PDF-Generierung fehlgeschlagen: {str(e)}")


@app.post("/export-full-pdf/{job_id}")
def export_full_pdf(job_id: str, request: PDFExportRequest = None):
    """
    Generiert den vollständigen PDF-Report inkl. Multi-Agent KI-Analyse.

    Im Unterschied zu /export-pdf enthält dieser Report:
        - Sektion 9:  Reporter-Agent Forensikbericht (Ollama/Llama 3.1)
        - Anhang A:   Triage-Klassifizierung (SOC L1 Agent)
        - Anhang B:   DFIR-Tiefenanalyse (DFIR Analyst Agent)

    Die KI-Ergebnisse werden über request.agent_analysis übergeben
    (zuvor von GET /agent-analyze/{job_id} gestreamt und im Frontend aggregiert).

    Synchron (def statt async def) wegen blockierendem ReportLab.

    Args:
        job_id:  Eindeutige Job-ID (muss status="completed" haben)
        request: PDFExportRequest mit agent_analysis-Dict und Metadaten

    Returns:
        FileResponse mit vollständigem PDF (forensic_full_report_{job_id}.pdf)

    HTTP: 200 OK | 400 Bad Request | 500 Internal Server Error
    """
    job_meta = _resolve_job(job_id)
    if job_meta.get("status") != "completed":
        raise HTTPException(status_code=400, detail="Analyse noch nicht abgeschlossen")

    output_path = OUTPUT_DIR / job_id

    job_data = {
        "job_id": job_id,
        "filename": job_meta.get("filename", "Unbekannt"),
        "input_type": job_meta.get("input_type", "Unbekannt"),
        "file_hash": job_meta.get("file_hash", ""),
        "md5_hash": job_meta.get("md5_hash", ""),
        "sha256_hash": job_meta.get("sha256_hash", "") or job_meta.get("file_hash", ""),
        "created_at": job_meta.get("created_at", ""),
    }

    if request:
        if request.case_name:
            job_data["case_name"] = request.case_name
        if request.case_number:
            job_data["case_number"] = request.case_number
        if request.analyst:
            job_data["analyst"] = request.analyst
        job_data["qualifikation"] = request.qualifikation or "Nicht angegeben"
        job_data["auftraggeber"]  = request.auftraggeber or "Nicht angegeben"
        job_data["ort_datum"]     = request.ort_datum or ""
        job_data["unterschrift"]  = request.unterschrift or ""
        # Multi-Agent-Ergebnisse (Triage + DFIR + Reporter) aus Frontend übergeben
        job_data["agent_analysis"] = request.agent_analysis or {}

    summary_file = output_path / "analysis_summary.json"
    if summary_file.exists():
        job_data["summary"] = json.loads(summary_file.read_text(encoding="utf-8"))

    anomalies_file = output_path / "anomalies_detected.json"
    if anomalies_file.exists():
        anomalies_data = json.loads(anomalies_file.read_text(encoding="utf-8"))
        job_data["anomalies"] = anomalies_data if isinstance(anomalies_data, list) else anomalies_data.get("anomalies", [])

    preprocessed_file = output_path / "ai_preprocessed.json"
    if preprocessed_file.exists():
        preprocessed = json.loads(preprocessed_file.read_text(encoding="utf-8"))
        job_data["indicators"] = preprocessed.get("indicators", {})

    # Fundstellen-Nachweis laden (von ProvenanceEnricher in der Pipeline erstellt)
    provenance_file = output_path / "provenance.json"
    if provenance_file.exists():
        job_data["provenance"] = json.loads(provenance_file.read_text(encoding="utf-8"))

    try:
        from modules.pdf_generator import ForensicPDFGenerator
        generator = ForensicPDFGenerator()
        pdf_path = generator.generate_full(output_path, job_data)
        logger.info(f"Vollständiger PDF-Report generiert für Job {job_id}: {pdf_path}")
        return FileResponse(
            str(pdf_path),
            filename=f"forensic_full_report_{job_id}.pdf",
            media_type="application/pdf",
        )
    except Exception as e:
        logger.error(f"Vollständiger PDF-Report fehlgeschlagen: {e}")
        raise HTTPException(status_code=500, detail=f"PDF-Generierung fehlgeschlagen: {str(e)}")


# ── Lokale LLM-Analyse (Ollama) ───────────────────────────────────────────────

class LLMAnalyzeRequest(BaseModel):
    """
    Request-Modell für die direkte LLM-Analyse via Ollama.

    Attributes:
        anomalies:  Liste von Anomalie-Dicts (aus anomalies_detected.json)
        indicators: IOC-Dict (IPs, Domains, Prozesse, …)
        summary:    Analyse-Zusammenfassung (aus analysis_summary.json)
        mode:       "quick" → kurze Priorisierung (max. 300 Wörter)
                    "full"  → Executive Report mit MITRE-Mapping (max. 800 Wörter)
    """
    anomalies: List[Dict] = []
    indicators: Optional[Dict] = None
    summary: Optional[Dict] = None
    mode: str = "quick"  # "quick" = kurze Analyse, "full" = ausfuehrlicher Report


def _compact_anomaly(a: dict) -> str:
    """
    Komprimiert eine Anomalie zu einer kurzen Textzeile für den LLM-Prompt.

    Spart ~80 % der Input-Tokens gegenüber der vollständigen JSON-Darstellung.
    Format: "[timestamp] event_type (score=X.XX) | host=... | ip=... | description"

    Args:
        a: Anomalie-Dict aus anomalies_detected.json

    Returns:
        Kompakte Einzeilen-Darstellung der Anomalie
    """
    meta = a.get('metadata', {}) if isinstance(a.get('metadata'), dict) else {}
    ts = a.get('timestamp', '?')
    etype = a.get('event_type', meta.get('event_type', '?'))
    score = a.get('anomaly_score', 0)
    desc = (a.get('description', '') or meta.get('message', ''))[:150]
    host = meta.get('hostname', '')
    src_ip = meta.get('src_ip', '')
    parts = [f"[{ts}] {etype} (score={score:.2f})"]
    if host:
        parts.append(f"host={host}")
    if src_ip:
        parts.append(f"ip={src_ip}")
    parts.append(desc)
    return " | ".join(parts)


@app.post("/llm-analyze")
def llm_analyze(request: LLMAnalyzeRequest):
    """
    Direkte LLM-Analyse der Anomalie-Daten via Ollama (lokales Llama 3.1).

    Im "quick"-Modus: Kompakte Zusammenfassung der Top-10-Anomalien (max. 800 Tokens).
    Im "full"-Modus:  Vollständiger Executive Report mit Summary, Indicators und
                      MITRE ATT&CK-Mapping (max. 1500 Tokens).

    WICHTIG: Synchron implementiert (def statt async def), weil OllamaClient
    intern requests.post() verwendet, das den Async-Event-Loop blockieren würde.

    Args:
        request: LLMAnalyzeRequest mit Anomalien, Indicators, Summary und Modus

    Returns:
        JSON mit {"result": "<Markdown-Text>", "model": "<Modellname>"}

    HTTP: 200 OK | 503 Service Unavailable (Ollama nicht erreichbar) | 500 Error
    """
    try:
        from llm_agent.ollama_client import OllamaClient
        client = OllamaClient()

        if request.mode == "quick":
            # Kompakte Darstellung statt volles JSON (spart ~80% Input-Tokens)
            anomaly_lines = [_compact_anomaly(a) for a in request.anomalies[:10]]
            anomaly_text = "\n".join(anomaly_lines)
            prompt = (
                "Analysiere diese forensischen Anomalien als DFIR-Experte.\n"
                "Gib eine kurze, priorisierte Zusammenfassung der kritischsten Bedrohungen.\n\n"
                f"{anomaly_text}\n\n"
                "Antworte auf Deutsch in Markdown. Maximal 300 Woerter.\n"
                "Fokus auf: Was ist passiert? Wie gefaehrlich? Was tun?"
            )
            max_tokens = 800
        else:
            # Ausfuehrlicher Report — aber kompakte Daten
            data_parts = []
            if request.summary:
                # Nur die wichtigsten Summary-Felder
                s = request.summary
                data_parts.append(
                    f"Analyse: {s.get('input_file', '?')} | Typ: {s.get('input_type', '?')} | "
                    f"Events: {s.get('total_events', 0)} | Anomalien: {s.get('anomalies_found', 0)} | "
                    f"IOCs: {s.get('iocs_identified', 0)}"
                )
            if request.anomalies:
                anomaly_lines = [_compact_anomaly(a) for a in request.anomalies[:10]]
                data_parts.append(f"## Anomalien ({len(request.anomalies)} total, Top 10):\n" + "\n".join(anomaly_lines))
            if request.indicators:
                # Kompakte Indicator-Liste
                ind = request.indicators
                ind_parts = []
                for key in ['ips', 'users', 'hostnames', 'processes', 'files']:
                    vals = ind.get(key, [])
                    if vals:
                        ind_parts.append(f"{key}: {', '.join(str(v) for v in vals[:10])}")
                if ind_parts:
                    data_parts.append("## Indicators:\n" + "\n".join(ind_parts))

            prompt = (
                "Du bist ein DFIR-Experte. Erstelle einen Executive Report auf Deutsch in Markdown.\n\n"
                + "\n\n".join(data_parts) +
                "\n\nStruktur: Executive Summary, Key Findings (MITRE ATT&CK), "
                "Empfehlungen (Sofort/Kurzfristig/Langfristig), IOCs.\n"
                "Maximal 800 Woerter."
            )
            max_tokens = 1500

        system_prompt = (
            "Du bist ein digitaler Forensik-Experte. "
            "Analysiere die Daten und gib strukturierte, faktische Einschaetzungen ab. Antworte auf Deutsch."
        )

        logger.info(f"LLM-Analyse gestartet (mode={request.mode}, anomalies={len(request.anomalies)}, prompt_len={len(prompt)})")
        response = client.generate(
            system_prompt=system_prompt,
            user_prompt=prompt,
            temperature=0.4,
            max_tokens=max_tokens
        )
        logger.info(f"LLM-Analyse abgeschlossen ({len(response)} Zeichen)")

        return JSONResponse({"result": response, "model": client.model})

    except (ConnectionError, TimeoutError) as e:
        logger.error(f"LLM-Analyse Fehler: {e}")
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        logger.error(f"LLM-Analyse Fehler: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ── Multi-Agent-Analyse (SSE) ─────────────────────────────────────────────────

@app.get("/agent-analyze/{job_id}")
def agent_analyze(job_id: str, mode: str = "standard"):
    """
    Startet eine Multi-Agent-Analyse und streamt die Ergebnisse via SSE.

    Drei Agenten werden sequenziell ausgeführt:
        1. Triage-Agent (SOC L1):  Schnelle Erstklassifizierung der Anomalien
        2. DFIR-Analyst-Agent:     Tiefenanalyse mit MITRE ATT&CK-Mapping
        3. Reporter-Agent:         Executive Summary & Handlungsempfehlungen

    Die Agents laufen in einem eigenen Thread. Jedes Ergebnis wird sofort als
    SSE-Event an den Client gestreamt. Keepalive-Pings alle 30 s verhindern
    Proxy-Timeouts bei langsamer LLM-Antwort.

    Query-Parameter:
        mode: "standard"       → Opfer-Perspektive (Standard)
              "attacker_infra" → Täterinfrastruktur-Perspektive

    WICHTIG: Synchron (def statt async def) weil OllamaClient blockierend ist.

    Args:
        job_id: Eindeutige Job-ID (muss status="completed" haben)
        mode:   Analyse-Perspektive (standard / attacker_infra)

    Returns:
        StreamingResponse mit text/event-stream (SSE)
        Events: {"type": "triage"|"analysis"|"report"|"complete"|"error"|"keepalive", ...}

    HTTP: 200 OK (Streaming) | 400 Bad Request | 404 Not Found
    """
    job_meta = _resolve_job(job_id)
    if job_meta.get("status") != "completed":
        raise HTTPException(status_code=400, detail="Analyse noch nicht abgeschlossen")

    output_path = OUTPUT_DIR / job_id

    # Anomalien laden — Pflichtdaten für Multi-Agent-Analyse
    anomalies = []
    anomalies_file = output_path / "anomalies_detected.json"
    if anomalies_file.exists():
        anomalies_data = json.loads(anomalies_file.read_text(encoding="utf-8"))
        anomalies = anomalies_data if isinstance(anomalies_data, list) else anomalies_data.get("anomalies", [])

    if not anomalies:
        raise HTTPException(status_code=400, detail="Keine Anomalien fuer Analyse vorhanden")

    # Summary laden
    summary = {}
    summary_file = output_path / "analysis_summary.json"
    if summary_file.exists():
        summary = json.loads(summary_file.read_text(encoding="utf-8"))

    # Indicators laden — versuche zuerst ai_preprocessed.json, dann preprocessed_for_llm.json
    indicators = {}
    for fname in ["ai_preprocessed.json", "preprocessed_for_llm.json"]:
        prep_file = output_path / fname
        if prep_file.exists():
            preprocessed = json.loads(prep_file.read_text(encoding="utf-8"))
            indicators = preprocessed.get("indicators", {})
            break

    analysis_mode = mode if mode in ("standard", "attacker_infra") else "standard"
    logger.info(
        f"Multi-Agent-Analyse gestartet fuer Job {job_id}: "
        f"{len(anomalies)} Anomalien [Modus: {analysis_mode}]"
    )

    def event_stream():
        """
        Generator-Funktion für den SSE-Stream.

        Startet den MultiAgentOrchestrator in einem separaten Thread und
        überträgt Events über eine Queue in den Generator. Sentinel-Wert
        None signalisiert das Ende des Streams.
        """
        import threading
        import queue
        from llm_agent.multi_agent import MultiAgentOrchestrator

        orchestrator = MultiAgentOrchestrator(analysis_mode=analysis_mode)
        q = queue.Queue()

        def run_agents():
            """Führt alle Agenten durch und legt Events in die Queue."""
            try:
                for ev in orchestrator.run(anomalies, summary, indicators):
                    q.put(ev)
            finally:
                q.put(None)  # Sentinel: Stream beendet

        thread = threading.Thread(target=run_agents, daemon=True)
        thread.start()

        while True:
            try:
                ev = q.get(timeout=30)  # Max 30s auf naechstes Event warten
            except queue.Empty:
                # Keepalive senden damit Proxy/Browser die Verbindung nicht trennt
                yield f"data: {json.dumps({'type': 'keepalive'})}\n\n"
                continue

            if ev is None:  # Sentinel empfangen → fertig
                break

            yield f"data: {json.dumps(ev, ensure_ascii=False)}\n\n"

        thread.join(timeout=5)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # Nginx-Buffering deaktivieren für SSE
        },
    )


# ── Case-Korrelationsanalyse (SSE) ────────────────────────────────────────────

class CaseCorrelateRequest(BaseModel):
    """
    Request-Modell für die fallübergreifende Korrelationsanalyse.

    Attributes:
        job_ids:      Liste von mindestens 2 Job-IDs
        case_name:    Optionaler Fallname für den Report
        case_number:  Optionales Aktenzeichen
        analyst:      Optionaler Analytiker-Name
    """
    job_ids: List[str]
    case_name: Optional[str] = None
    case_number: Optional[str] = None
    analyst: Optional[str] = None


@app.post("/case-correlate")
def case_correlate(request: CaseCorrelateRequest):
    """
    Fallübergreifende Korrelationsanalyse via SSE (Server-Sent Events).

    Aggregiert Anomalie-Daten aus mehreren Jobs und identifiziert
    quellenübergreifende Muster (gleiche IPs, Nutzer, Zeitkorrelationen).
    Der CaseCorrelationAgent läuft in einem eigenen Thread und streamt
    Zwischenergebnisse live zum Client.

    Mindestens 2 Jobs erforderlich. Alle Jobs müssen abgeschlossene
    anomalies_detected.json-Dateien haben.

    WICHTIG: Synchron (def statt async def) weil OllamaClient blockierend ist.

    Args:
        request: CaseCorrelateRequest mit mindestens 2 job_ids

    Returns:
        StreamingResponse mit text/event-stream (SSE)

    HTTP: 200 OK (Streaming) | 400 Bad Request (< 2 Jobs / fehlende Daten) | 404 Not Found
    """
    if len(request.job_ids) < 2:
        raise HTTPException(
            status_code=400,
            detail="Mindestens 2 Jobs fuer Korrelationsanalyse erforderlich"
        )

    # Validiere dass alle Jobs Output-Daten haben
    job_output_paths = []
    for job_id in request.job_ids:
        output_path = OUTPUT_DIR / job_id
        if not output_path.exists():
            raise HTTPException(status_code=404, detail=f"Job-Output nicht gefunden: {job_id}")
        anomalies_file = output_path / "anomalies_detected.json"
        if not anomalies_file.exists():
            raise HTTPException(
                status_code=400,
                detail=f"Job {job_id} hat keine Anomalie-Daten"
            )
        job_output_paths.append(output_path)

    case_meta = {
        "case_name": request.case_name,
        "case_number": request.case_number,
        "analyst": request.analyst,
    }

    logger.info(
        f"Case-Korrelation gestartet: {len(request.job_ids)} Jobs, "
        f"Fall: {request.case_name or '—'}"
    )

    def event_stream():
        """
        Generator-Funktion für den Korrelations-SSE-Stream.

        Startet CaseCorrelationAgent in eigenem Thread, überträgt Events
        über eine Queue. Keepalive alle 30 s gegen Proxy-Timeouts.
        """
        import threading
        from llm_agent.case_correlator import CaseCorrelationAgent

        agent = CaseCorrelationAgent()
        import queue as _queue
        q = _queue.Queue()

        def run_correlation():
            """Führt die Korrelationsanalyse durch und befüllt die Queue."""
            try:
                for ev in agent.run(job_output_paths, case_meta):
                    q.put(ev)
            finally:
                q.put(None)  # Sentinel

        thread = threading.Thread(target=run_correlation, daemon=True)
        thread.start()

        while True:
            try:
                ev = q.get(timeout=30)
            except _queue.Empty:
                yield f"data: {json.dumps({'type': 'keepalive'})}\n\n"
                continue

            if ev is None:
                break

            yield f"data: {json.dumps(ev, ensure_ascii=False)}\n\n"

        thread.join(timeout=5)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ── Case-PDF-Export ───────────────────────────────────────────────────────────

class CasePDFExportRequest(BaseModel):
    """
    Request-Modell für den fallübergreifenden PDF-Report.

    Attributes:
        job_ids:            Liste der Job-IDs, die in den Report einfließen
        case_name:          Fallname für Titelseite
        case_number:        Aktenzeichen
        analyst:            Analytiker-Name
        correlation_report: Text des Korrelations-Reports (aus /case-correlate)
        shared_iocs:        Gemeinsame IOCs über alle Jobs hinweg
        metadata:           Zusätzliche Fall-Metadaten
    """
    job_ids: List[str]
    case_name: Optional[str] = None
    case_number: Optional[str] = None
    analyst: Optional[str] = None
    correlation_report: Optional[str] = None
    shared_iocs: Optional[Dict] = None
    metadata: Optional[Dict] = None


@app.post("/export-case-pdf")
def export_case_pdf(request: CasePDFExportRequest):
    """
    Generiert einen fallübergreifenden Korrelations-PDF-Report.

    Lädt Summary, Anomalien und Indicators aller angegebenen Jobs und
    erstellt damit einen kombinierten Fall-Report via CasePDFGenerator.
    Der Report wird im Arbeitsspeicher gebaut und direkt als StreamingResponse
    zurückgegeben (kein Disk-Write, da kein fester job_id-Kontext).

    Args:
        request: CasePDFExportRequest mit job_ids, Metadaten und Korrelationsdaten

    Returns:
        StreamingResponse mit PDF (case_report_{case_name}.pdf)

    HTTP: 200 OK | 404 Not Found | 500 Internal Server Error
    """
    # Quelldaten pro Job laden
    sources = []
    for job_id in request.job_ids:
        output_path = OUTPUT_DIR / job_id
        if not output_path.exists():
            raise HTTPException(status_code=404, detail=f"Job nicht gefunden: {job_id}")

        source = {"job_id": job_id}

        summary_file = output_path / "analysis_summary.json"
        if summary_file.exists():
            source["summary"] = json.loads(summary_file.read_text(encoding="utf-8"))

        anomalies_file = output_path / "anomalies_detected.json"
        if anomalies_file.exists():
            raw = json.loads(anomalies_file.read_text(encoding="utf-8"))
            source["anomalies"] = raw if isinstance(raw, list) else raw.get("anomalies", [])

        for fname in ["ai_preprocessed.json", "preprocessed_for_llm.json"]:
            prep_file = output_path / fname
            if prep_file.exists():
                preprocessed = json.loads(prep_file.read_text(encoding="utf-8"))
                source["indicators"] = preprocessed.get("indicators", {})
                break

        sources.append(source)

    case_data = {
        "case_name": request.case_name or "Unbekannt",
        "case_number": request.case_number or "",
        "analyst": request.analyst or "",
        "correlation_report": request.correlation_report or "",
        "shared_iocs": request.shared_iocs or {},
        "metadata": request.metadata or {},
        "sources": sources,
    }

    try:
        from modules.pdf_generator import CasePDFGenerator
        import tempfile

        generator = CasePDFGenerator()
        # Temporäres Verzeichnis — wird nach dem Read automatisch gelöscht
        with tempfile.TemporaryDirectory() as tmp:
            pdf_path = generator.generate(Path(tmp), case_data)
            pdf_bytes = pdf_path.read_bytes()

        safe_name = (request.case_name or "case_report").replace(" ", "_")[:50]
        return StreamingResponse(
            iter([pdf_bytes]),
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="case_report_{safe_name}.pdf"'},
        )
    except Exception as e:
        logger.error(f"Case-PDF-Generierung fehlgeschlagen: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ── Case Management (Backend-Persistenz) ──────────────────────────────────────
# Fälle werden als einzelne JSON-Dateien in CASES_DIR gespeichert.
# Dateiname: {case_id}.json
# Jeder Fall speichert Metadaten + eine Liste zugehöriger job_ids.
# Die eigentlichen Job-Ergebnisse liegen weiterhin in OUTPUT_DIR/{job_id}/.

class CaseCreateRequest(BaseModel):
    """
    Request-Modell für die Fall-Erstellung.

    Attributes:
        name:         Pflichtfeld — Fallbezeichnung
        case_number:  Optionales Aktenzeichen
        description:  Optionale Fallbeschreibung
        analyst:      Optionaler zuständiger Analytiker
        job_ids:      Bereits zugeordnete Job-IDs (können auch später ergänzt werden)
    """
    name: str
    case_number: Optional[str] = None
    description: Optional[str] = None
    analyst: Optional[str] = None
    job_ids: Optional[List[str]] = []


class CaseUpdateRequest(BaseModel):
    """
    Request-Modell für die Fall-Aktualisierung (alle Felder optional / PATCH-Semantik).

    Attributes:
        name:         Neuer Fallname
        case_number:  Neues Aktenzeichen
        description:  Neue Beschreibung
        analyst:      Neuer Analytiker
        job_ids:      Vollständige Job-ID-Liste (ersetzt die bisherige)
    """
    name: Optional[str] = None
    case_number: Optional[str] = None
    description: Optional[str] = None
    analyst: Optional[str] = None
    job_ids: Optional[List[str]] = None


def _case_file(case_id: str) -> Path:
    """Gibt den absoluten Pfad zur JSON-Datei eines Falles zurück."""
    return CASES_DIR / f"{case_id}.json"


def _load_case(case_id: str) -> dict:
    """
    Lädt einen Fall aus der JSON-Datei.

    Args:
        case_id: Eindeutige Fall-ID

    Returns:
        Fall-Dict mit allen Metadaten

    Raises:
        HTTPException 404: Fall nicht gefunden
    """
    f = _case_file(case_id)
    if not f.exists():
        raise HTTPException(status_code=404, detail="Fall nicht gefunden")
    return json.loads(f.read_text(encoding="utf-8"))


@app.post("/cases")
async def create_case(request: CaseCreateRequest):
    """
    Erstellt einen neuen forensischen Fall und speichert ihn persistent auf Disk.

    Erzeugt eine 12-Zeichen UUID als case_id und schreibt alle Metadaten in
    CASES_DIR/{case_id}.json. Im Gegensatz zu Job-Daten überleben Fälle
    Server-Neustarts.

    Args:
        request: CaseCreateRequest mit Name (Pflicht) und optionalen Feldern

    Returns:
        JSON mit vollständigem Fall-Objekt inkl. generierter case_id

    HTTP: 201 Created
    """
    case_id = str(uuid.uuid4())[:12]
    case = {
        "case_id": case_id,
        "name": request.name,
        "case_number": request.case_number or "",
        "description": request.description or "",
        "analyst": request.analyst or "",
        "job_ids": request.job_ids or [],
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat(),
    }
    _case_file(case_id).write_text(json.dumps(case, indent=2, ensure_ascii=False), encoding="utf-8")
    logger.info(f"Fall erstellt: {case_id} ({request.name})")
    return JSONResponse(case, status_code=201)


@app.get("/cases")
async def list_cases():
    """
    Listet alle gespeicherten forensischen Fälle auf.

    Sortierung: Neueste zuerst (nach Änderungsdatum der JSON-Datei).
    Defekte JSON-Dateien werden stillschweigend übersprungen.

    Returns:
        JSON-Array aller Fall-Objekte

    HTTP: 200 OK
    """
    cases = []
    for f in sorted(CASES_DIR.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
        try:
            cases.append(json.loads(f.read_text(encoding="utf-8")))
        except Exception:
            continue
    return JSONResponse(cases)


@app.get("/cases/{case_id}")
async def get_case(case_id: str):
    """
    Gibt einen einzelnen Fall mit allen Metadaten zurück.

    Args:
        case_id: Eindeutige Fall-ID

    Returns:
        JSON mit Fall-Objekt

    HTTP: 200 OK | 404 Not Found
    """
    return JSONResponse(_load_case(case_id))


@app.put("/cases/{case_id}")
async def update_case(case_id: str, request: CaseUpdateRequest):
    """
    Aktualisiert Metadaten eines bestehenden Falls (PATCH-Semantik).

    Nur übergebene Felder werden überschrieben. updated_at wird automatisch gesetzt.

    Args:
        case_id:  Eindeutige Fall-ID
        request:  CaseUpdateRequest mit den zu ändernden Feldern

    Returns:
        JSON mit aktualisiertem Fall-Objekt

    HTTP: 200 OK | 404 Not Found
    """
    case = _load_case(case_id)
    if request.name is not None:
        case["name"] = request.name
    if request.case_number is not None:
        case["case_number"] = request.case_number
    if request.description is not None:
        case["description"] = request.description
    if request.analyst is not None:
        case["analyst"] = request.analyst
    if request.job_ids is not None:
        case["job_ids"] = request.job_ids
    case["updated_at"] = datetime.now().isoformat()
    _case_file(case_id).write_text(json.dumps(case, indent=2, ensure_ascii=False), encoding="utf-8")
    logger.info(f"Fall aktualisiert: {case_id}")
    return JSONResponse(case)


@app.delete("/cases/{case_id}")
async def delete_case(case_id: str):
    """
    Löscht einen Fall (nur die Metadaten-Datei).

    WICHTIG: Die eigentlichen Job-Ergebnisse in OUTPUT_DIR/{job_id}/ werden
    NICHT gelöscht. Nur die Fall-Metadaten in CASES_DIR werden entfernt.

    Args:
        case_id: Eindeutige Fall-ID

    Returns:
        JSON mit {"deleted": true, "case_id": "..."}

    HTTP: 200 OK | 404 Not Found
    """
    f = _case_file(case_id)
    if not f.exists():
        raise HTTPException(status_code=404, detail="Fall nicht gefunden")
    f.unlink()
    logger.info(f"Fall geloescht: {case_id}")
    return JSONResponse({"deleted": True, "case_id": case_id})


@app.post("/cases/{case_id}/jobs/{job_id}")
async def add_job_to_case(case_id: str, job_id: str):
    """
    Ordnet einen abgeschlossenen Job einem Fall zu.

    Idempotent: Doppelte Hinzufügungen werden ignoriert.

    Args:
        case_id: Eindeutige Fall-ID
        job_id:  Eindeutige Job-ID

    Returns:
        JSON mit aktualisiertem Fall-Objekt (inkl. neuer job_ids-Liste)

    HTTP: 200 OK | 404 Not Found
    """
    case = _load_case(case_id)
    if job_id not in case["job_ids"]:
        case["job_ids"].append(job_id)
        case["updated_at"] = datetime.now().isoformat()
        _case_file(case_id).write_text(json.dumps(case, indent=2, ensure_ascii=False), encoding="utf-8")
    return JSONResponse(case)


@app.delete("/cases/{case_id}/jobs/{job_id}")
async def remove_job_from_case(case_id: str, job_id: str):
    """
    Entfernt die Zuordnung eines Jobs aus einem Fall.

    WICHTIG: Löscht nicht die Job-Ergebnisse selbst, nur die Zuordnung.

    Args:
        case_id: Eindeutige Fall-ID
        job_id:  Zu entfernende Job-ID

    Returns:
        JSON mit aktualisiertem Fall-Objekt

    HTTP: 200 OK | 404 Not Found
    """
    case = _load_case(case_id)
    case["job_ids"] = [j for j in case["job_ids"] if j != job_id]
    case["updated_at"] = datetime.now().isoformat()
    _case_file(case_id).write_text(json.dumps(case, indent=2, ensure_ascii=False), encoding="utf-8")
    return JSONResponse(case)


# ── Root / API-Info ───────────────────────────────────────────────────────────

@app.get("/")
async def root():
    """
    Gibt eine Übersicht aller verfügbaren API-Endpunkte zurück.

    Nützlich als Schnell-Referenz beim Entwickeln und Testen.

    Returns:
        JSON mit API-Name, Version und Endpunkt-Beschreibungen

    HTTP: 200 OK
    """
    return {
        "name": "Forensic Analysis API",
        "version": "1.0.0",
        "endpoints": {
            "POST /analyze": "Datei hochladen & analysieren",
            "GET /status/{job_id}": "Status pruefen",
            "GET /download/{job_id}/{filename}": "Ergebnis herunterladen",
            "POST /llm-analyze": "Lokale LLM-Analyse (Ollama)",
            "POST /verify/{job_id}": "Evidence-Integritaet verifizieren (SHA256)",
            "POST /threat-intel/lookup": "Threat Intelligence IOC-Abgleich",
            "POST /export-pdf/{job_id}": "PDF-Report generieren",
            "GET /agent-analyze/{job_id}": "Multi-Agent SSE-Analyse (Triage → Analyst → Reporter)",
            "POST /case-correlate": "Case-Korrelationsanalyse (SSE)",
            "POST /export-case-pdf": "Fall-PDF-Report generieren",
            "POST /cases": "Fall erstellen (persistente Backend-Speicherung)",
            "GET /cases": "Alle Faelle auflisten",
            "GET /cases/{case_id}": "Fall-Detail abrufen",
            "PUT /cases/{case_id}": "Fall aktualisieren",
            "DELETE /cases/{case_id}": "Fall loeschen",
            "POST /cases/{case_id}/jobs/{job_id}": "Job zu Fall hinzufuegen",
            "DELETE /cases/{case_id}/jobs/{job_id}": "Job aus Fall entfernen",
        }
    }


# ── Direktstart (nur für lokale Entwicklung) ──────────────────────────────────
# In Produktion: uvicorn backend.api:app --host 0.0.0.0 --port 8000
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
