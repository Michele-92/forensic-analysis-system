from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
import shutil
import uuid
from pipeline import run_pipeline, detect_input_type
import logging
from datetime import datetime

app = FastAPI(title="Forensic Analysis API", version="1.0.0")

# CORS für Frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In Produktion: Nur erlaubte Domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# REPARATUR #28: Besseres Logging-Setup für API
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s.%(msecs)03d | API | %(levelname)-8s | %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

# REPARATUR #29: Zentrale Upload & Output Verzeichnisse (konsistent!)
DATA_DIR = Path("./data")
UPLOAD_DIR = DATA_DIR / "uploads"
OUTPUT_DIR = DATA_DIR / "outputs"

# REPARATUR #30: Erstelle Verzeichnisse falls nicht existent
for directory in [DATA_DIR, UPLOAD_DIR, OUTPUT_DIR]:
    directory.mkdir(exist_ok=True, parents=True)

logger.info(f"UPLOAD_DIR: {UPLOAD_DIR.absolute()}")
logger.info(f"OUTPUT_DIR: {OUTPUT_DIR.absolute()}")

# Job-Tracking (in Produktion: Redis/DB verwenden)
jobs = {}

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
        
        logger.info(f"✓ Datei hochgeladen: {file.filename} ({file_path.stat().st_size} bytes)")
        logger.info(f"  Job-ID: {job_id}")
        
        # REPARATUR #34: Erkenne Input-Typ mit Logging
        input_type = detect_input_type(file_path)
        logger.info(f"✓ Input-Typ erkannt: {input_type}")
        
        # REPARATUR #35: Job-Status mit erweiterten Metadaten initialisieren
        jobs[job_id] = {
            "job_id": job_id,
            "status": "processing",
            "filename": file.filename,
            "input_type": input_type,
            "progress": 0,
            "created_at": datetime.now().isoformat(),
            "file_size": file_path.stat().st_size,
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
        
        # REPARATUR #41: Finalisiere Job-Status
        jobs[job_id]["status"] = "completed"
        jobs[job_id]["progress"] = 100
        jobs[job_id]["output_path"] = str(output_path)
        jobs[job_id]["completed_at"] = datetime.now().isoformat()
        jobs[job_id]["result_files"] = [f.name for f in result_files]
        
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

@app.get("/")
async def root():
    """API-Info."""
    return {
        "name": "Forensic Analysis API",
        "version": "1.0.0",
        "endpoints": {
            "POST /analyze": "Datei hochladen & analysieren",
            "GET /status/{job_id}": "Status prüfen",
            "GET /download/{job_id}/{filename}": "Ergebnis herunterladen"
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)