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

# Stelle sicher, dass backend/ im Python-Path ist (egal von wo gestartet)
BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from pipeline import run_pipeline, detect_input_type
from modules.evidence_tracker import EvidenceTracker

app = FastAPI(title="Forensic Analysis API", version="1.0.0")

# CORS für Frontend (erlaubt Zugriff von beliebigen Origins inkl. localhost:5173)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,   # False bei allow_origins=["*"] (Browser-Kompatibilität)
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s.%(msecs)03d | API | %(levelname)-8s | %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

# Absolute Pfade basierend auf Projektstruktur (funktioniert egal wo uvicorn gestartet wird)
PROJECT_ROOT = BACKEND_DIR.parent
DATA_DIR = PROJECT_ROOT / "data"
UPLOAD_DIR = DATA_DIR / "uploads"
OUTPUT_DIR = DATA_DIR / "outputs"

for directory in [DATA_DIR, UPLOAD_DIR, OUTPUT_DIR]:
    directory.mkdir(exist_ok=True, parents=True)

logger.info(f"PROJECT_ROOT: {PROJECT_ROOT}")
logger.info(f"UPLOAD_DIR:   {UPLOAD_DIR}")
logger.info(f"OUTPUT_DIR:   {OUTPUT_DIR}")

# Job-Tracking (in Produktion: Redis/DB verwenden)
jobs = {}


def _resolve_job(job_id: str) -> dict:
    """Gibt Job-Metadaten zurück – aus Memory oder job_meta.json (Fallback nach Neustart)."""
    if job_id in jobs:
        return jobs[job_id]
    meta_file = OUTPUT_DIR / job_id / "job_meta.json"
    if meta_file.exists():
        return json.loads(meta_file.read_text(encoding="utf-8"))
    raise HTTPException(status_code=404, detail="Job nicht gefunden")

@app.post("/analyze")
async def analyze_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...)
):
    """
    REPARATUR #31: Überarbeiteter Upload-Endpoint mit besserem Logging & Status-Tracking.
    
    Analysiert hochgeladene Dateien (Disk-Images, Logs, UAC-Dumps).
    
    Unterstützte Formate:
    - Disk-Images: .dd, .raw, .img, .e01, .ewf, .vdi, .vmdk
    - Logs: .log, .syslog, .txt
    - Memory: .mem, .dump, .dmp
    """
    try:
        # REPARATUR #32: Generiere eindeutige Job-ID mit Timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        job_id = f"{timestamp}_{str(uuid.uuid4())[:8]}"
        
        # REPARATUR #33: Speichere hochgeladene Datei mit konsistentem Pfad
        file_path = UPLOAD_DIR / f"{job_id}_{file.filename}"
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        file_size = file_path.stat().st_size
        logger.info(f"✓ Datei hochgeladen: {file.filename} ({file_size} bytes)")
        logger.info(f"  Job-ID: {job_id}")

        # Evidence Integrity: SHA256-Hash berechnen
        file_hash = EvidenceTracker.compute_hash(file_path)
        logger.info(f"  SHA256: {file_hash}")

        # REPARATUR #34: Erkenne Input-Typ mit Logging
        input_type = detect_input_type(file_path)
        logger.info(f"✓ Input-Typ erkannt: {input_type}")

        # Audit-Trail starten
        audit_trail = [
            EvidenceTracker.create_audit_entry("upload", {
                "filename": file.filename,
                "file_size": file_size,
                "file_hash": file_hash,
            })
        ]

        # REPARATUR #35: Job-Status mit erweiterten Metadaten initialisieren
        jobs[job_id] = {
            "job_id": job_id,
            "status": "processing",
            "filename": file.filename,
            "input_type": input_type,
            "progress": 0,
            "created_at": datetime.now().isoformat(),
            "file_size": file_size,
            "file_hash": file_hash,
            "audit_trail": audit_trail,
            "output_path": None,
            "error": None
        }
        
        # REPARATUR #36: Starte Analyse im Hintergrund mit Output-Verzeichnis
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
            "file_hash": file_hash,
            "message": "✓ Analyse gestartet. Nutze /status/{job_id} zum Tracking.",
            "created_at": jobs[job_id]["created_at"]
        }, status_code=202)
        
    except Exception as e:
        logger.error(f"✗ Upload-Fehler: {e}")
        raise HTTPException(status_code=500, detail=str(e))

def run_analysis(job_id: str, file_path: Path, output_path: Path):
    """
    REPARATUR #37: Überarbeitete Background-Analysis mit detailliertem Logging & Error-Handling.
    
    Führt komplette Pipeline aus:
    1. Detektiert Input-Typ
    2. Extrahiert Daten (Dissect + Sleuth Kit)
    3. Normalisiert Daten
    4. Generiert Anomalieerkennung (ML)
    5. Filtert Events für KI (Top-1000)
    6. Generiert KI-Report
    """
    try:
        logger.info(f"=" * 80)
        logger.info(f"STARTE ANALYSE [Job: {job_id}]")
        logger.info(f"  Eingabe: {file_path.name}")
        logger.info(f"  Output: {output_path}")
        logger.info(f"=" * 80)
        
        # REPARATUR #38: Update Progress während Analyse
        jobs[job_id]["progress"] = 10
        logger.info(f"Progress: {jobs[job_id]['progress']}% - Initialisierung")

        # Audit-Trail: Analyse gestartet
        jobs[job_id]["audit_trail"].append(
            EvidenceTracker.create_audit_entry("analysis_started", {"output_path": str(output_path)})
        )

        # REPARATUR #39: Führe Pipeline aus mit vollständiger Orchestrierung
        logger.info(f"Progress: 20% - Starte Pipeline...")
        jobs[job_id]["progress"] = 20

        result = run_pipeline(file_path, output_path)

        logger.info(f"Progress: 90% - Pipeline abgeschlossen")
        jobs[job_id]["progress"] = 90
        
        # REPARATUR #40: Erstelle Job-Summary
        result_files = list(output_path.glob("*"))
        logger.info(f"✓ {len(result_files)} Output-Dateien erstellt:")
        for f in sorted(result_files):
            logger.info(f"  - {f.name} ({f.stat().st_size} bytes)")
        
        # Evidence Integrity: Hash in analysis_summary.json einbetten
        summary_file = output_path / "analysis_summary.json"
        if summary_file.exists():
            summary_data = json.loads(summary_file.read_text(encoding="utf-8"))
            summary_data["file_hash"] = jobs[job_id].get("file_hash", "")
            summary_file.write_text(json.dumps(summary_data, indent=2, ensure_ascii=False), encoding="utf-8")

        # Audit-Trail: Analyse abgeschlossen
        jobs[job_id]["audit_trail"].append(
            EvidenceTracker.create_audit_entry("analysis_completed", {
                "result_files": [f.name for f in result_files],
            })
        )

        # REPARATUR #41: Finalisiere Job-Status
        jobs[job_id]["status"] = "completed"
        jobs[job_id]["progress"] = 100
        jobs[job_id]["output_path"] = str(output_path)
        jobs[job_id]["completed_at"] = datetime.now().isoformat()
        jobs[job_id]["result_files"] = [f.name for f in result_files]

        # job_meta.json speichern – ermöglicht Wiederherstellung nach Neustart
        meta_file = output_path / "job_meta.json"
        meta_file.write_text(json.dumps({
            "job_id": job_id,
            "status": "completed",
            "filename": jobs[job_id].get("filename", "Unbekannt"),
            "input_type": jobs[job_id].get("input_type", "Unbekannt"),
            "file_hash": jobs[job_id].get("file_hash", ""),
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

@app.get("/status/{job_id}")
async def get_status(job_id: str):
    """
    REPARATUR #42: Verbesserts Status-Endpoint mit vollständigen Job-Informationen.
    """
    if job_id not in jobs:
        logger.warning(f"⚠ Status-Anfrage für unbekannte Job-ID: {job_id}")
        raise HTTPException(status_code=404, detail="Job nicht gefunden")
    
    job = jobs[job_id]
    logger.debug(f"✓ Status-Abfrage für Job {job_id}: {job['status']} ({job['progress']}%)")
    
    return JSONResponse(job)

@app.get("/download/{job_id}/{filename}")
async def download_result(job_id: str, filename: str):
    """
    REPARATUR #43: Verbesserter Download-Endpoint mit Validierung.
    
    Ermöglicht Download von:
    - report.md (Hauptbericht)
    - timeline.csv (Timeline-Export)
    - anomalies_detected.json (Anomalien)
    - interpretation.json (KI-Interpretation)
    - analysis_summary.json (Zusammenfassung)
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

@app.get("/results/{job_id}")
async def get_results(job_id: str):
    """
    REPARATUR #44: NEUER ENDPOINT - Gibt Übersicht aller verfügbaren Ergebnisse
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

## ── Evidence Integrity / Verifikation ─────────────────────────────────────────

@app.post("/verify/{job_id}")
async def verify_evidence(job_id: str):
    """
    Verifiziert die Integritaet einer hochgeladenen Datei.
    Berechnet den aktuellen SHA256-Hash und vergleicht mit dem Original.
    """
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job nicht gefunden")

    job = jobs[job_id]
    original_hash = job.get("file_hash")
    if not original_hash:
        raise HTTPException(status_code=400, detail="Kein Hash fuer diesen Job vorhanden")

    # Originaldatei finden
    matching = list(UPLOAD_DIR.glob(f"{job_id}_*"))
    if not matching:
        raise HTTPException(status_code=404, detail="Upload-Datei nicht mehr vorhanden")

    file_path = matching[0]
    current_hash = EvidenceTracker.compute_hash(file_path)
    verified = current_hash == original_hash

    # Audit-Trail erweitern
    job.setdefault("audit_trail", []).append(
        EvidenceTracker.create_audit_entry("verification", {
            "verified": verified,
            "current_hash": current_hash,
        })
    )

    logger.info(f"Evidence-Verifikation Job {job_id}: {'BESTANDEN' if verified else 'FEHLGESCHLAGEN'}")

    return JSONResponse({
        "verified": verified,
        "original_hash": original_hash,
        "current_hash": current_hash,
        "filename": job.get("filename"),
        "audit_trail": job.get("audit_trail", []),
    })


## ── Threat Intelligence Lookup ────────────────────────────────────────────────

class ThreatIntelRequest(BaseModel):
    indicators: Dict = {}  # {"ips": [...], "domains": [...], ...}


@app.post("/threat-intel/lookup")
def threat_intel_lookup(request: ThreatIntelRequest):
    """
    IOCs gegen lokale Knowledge-Base und optional AbuseIPDB abgleichen.
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


## ── PDF-Report-Export ────────────────────────────────────────────────────────

class PDFExportRequest(BaseModel):
    case_name: Optional[str] = None
    case_number: Optional[str] = None
    analyst: Optional[str] = None

@app.post("/export-pdf/{job_id}")
def export_pdf(job_id: str, request: PDFExportRequest = None):
    """
    Generiert einen forensischen PDF-Report fuer einen abgeschlossenen Job.
    Synchron (def statt async def) weil ReportLab blockierend ist.
    """
    job_meta = _resolve_job(job_id)
    if job_meta.get("status") != "completed":
        raise HTTPException(status_code=400, detail="Analyse noch nicht abgeschlossen")

    output_path = OUTPUT_DIR / job_id

    # Daten aus Output-Dateien laden
    job_data = {
        "filename": job_meta.get("filename", "Unbekannt"),
        "input_type": job_meta.get("input_type", "Unbekannt"),
        "file_hash": job_meta.get("file_hash", ""),
    }

    # Case-Info aus Request
    if request:
        if request.case_name:
            job_data["case_name"] = request.case_name
        if request.case_number:
            job_data["case_number"] = request.case_number
        if request.analyst:
            job_data["analyst"] = request.analyst

    # Summary laden
    summary_file = output_path / "analysis_summary.json"
    if summary_file.exists():
        job_data["summary"] = json.loads(summary_file.read_text(encoding="utf-8"))

    # Anomalien laden
    anomalies_file = output_path / "anomalies_detected.json"
    if anomalies_file.exists():
        anomalies_data = json.loads(anomalies_file.read_text(encoding="utf-8"))
        job_data["anomalies"] = anomalies_data if isinstance(anomalies_data, list) else anomalies_data.get("anomalies", [])

    # Preprocessed-Daten laden (IOCs)
    preprocessed_file = output_path / "ai_preprocessed.json"
    if preprocessed_file.exists():
        preprocessed = json.loads(preprocessed_file.read_text(encoding="utf-8"))
        job_data["indicators"] = preprocessed.get("indicators", {})

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


## ── Lokale LLM-Analyse (Ollama) ─────────────────────────────────────────────

class LLMAnalyzeRequest(BaseModel):
    anomalies: List[Dict] = []
    indicators: Optional[Dict] = None
    summary: Optional[Dict] = None
    mode: str = "quick"  # "quick" = kurze Analyse, "full" = ausfuehrlicher Report

def _compact_anomaly(a: dict) -> str:
    """Komprimiert eine Anomalie zu einer kurzen Textzeile fuer den LLM-Prompt."""
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
    Lokale LLM-Analyse via Ollama.
    WICHTIG: def statt async def — requests.post() ist synchron und wuerde
    bei async def den gesamten Event-Loop blockieren.
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


## ── Multi-Agent-Analyse (SSE) ────────────────────────────────────────────────

@app.get("/agent-analyze/{job_id}")
def agent_analyze(job_id: str, mode: str = "standard"):
    """
    Multi-Agent forensische Analyse via SSE (Server-Sent Events).
    3 Agenten: Triage (SOC L1) → Analyst (DFIR) → Reporter.

    Query-Parameter:
      mode: 'standard'       → Opfer-Perspektive (Standard)
            'attacker_infra' → Taetersinfrastruktur-Perspektive

    Synchron (def statt async def) weil OllamaClient blockierend ist.
    Gibt StreamingResponse mit text/event-stream zurueck.
    """
    job_meta = _resolve_job(job_id)
    if job_meta.get("status") != "completed":
        raise HTTPException(status_code=400, detail="Analyse noch nicht abgeschlossen")

    output_path = OUTPUT_DIR / job_id

    # Anomalien laden
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

    # Indicators laden
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
        import threading
        import time
        from llm_agent.multi_agent import MultiAgentOrchestrator

        orchestrator = MultiAgentOrchestrator(analysis_mode=analysis_mode)
        events = []
        lock = threading.Lock()
        done = threading.Event()

        def run_agents():
            try:
                for ev in orchestrator.run(anomalies, summary, indicators):
                    with lock:
                        events.append(ev)
            finally:
                done.set()

        thread = threading.Thread(target=run_agents, daemon=True)
        thread.start()

        while not done.is_set():
            # Ausstehende Events senden
            with lock:
                pending = list(events)
                events.clear()
            for ev in pending:
                yield f"data: {json.dumps(ev, ensure_ascii=False)}\n\n"

            # Keepalive senden damit Proxy die Verbindung nicht killt
            if not done.is_set():
                yield f"data: {json.dumps({'type': 'keepalive'})}\n\n"
                done.wait(timeout=15)

        # Restliche Events nach Abschluss senden
        with lock:
            pending = list(events)
            events.clear()
        for ev in pending:
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


## ── Case-Korrelationsanalyse (SSE) ─────────────────────────────────────────

class CaseCorrelateRequest(BaseModel):
    job_ids: List[str]
    case_name: Optional[str] = None
    case_number: Optional[str] = None
    analyst: Optional[str] = None


@app.post("/case-correlate")
def case_correlate(request: CaseCorrelateRequest):
    """
    Case-Korrelationsanalyse via SSE (Server-Sent Events).
    Aggregiert Daten aus mehreren Jobs und identifiziert
    quellenuebergreifende Muster.

    Synchron (def statt async def) weil OllamaClient blockierend ist.
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
        import threading
        from llm_agent.case_correlator import CaseCorrelationAgent

        agent = CaseCorrelationAgent()
        events = []
        lock = threading.Lock()
        done = threading.Event()

        def run_correlation():
            try:
                for ev in agent.run(job_output_paths, case_meta):
                    with lock:
                        events.append(ev)
            finally:
                done.set()

        thread = threading.Thread(target=run_correlation, daemon=True)
        thread.start()

        while not done.is_set():
            with lock:
                pending = list(events)
                events.clear()
            for ev in pending:
                yield f"data: {json.dumps(ev, ensure_ascii=False)}\n\n"

            if not done.is_set():
                yield f"data: {json.dumps({'type': 'keepalive'})}\n\n"
                done.wait(timeout=15)

        with lock:
            pending = list(events)
            events.clear()
        for ev in pending:
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


## ── Case-PDF-Export ────────────────────────────────────────────────────────

class CasePDFExportRequest(BaseModel):
    job_ids: List[str]
    case_name: Optional[str] = None
    case_number: Optional[str] = None
    analyst: Optional[str] = None
    correlation_report: Optional[str] = None
    shared_iocs: Optional[Dict] = None
    metadata: Optional[Dict] = None


@app.post("/export-case-pdf")
def export_case_pdf(request: CasePDFExportRequest):
    """Generiert Fall-Korrelations-PDF-Report."""
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


@app.get("/")
async def root():
    """API-Info."""
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
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)