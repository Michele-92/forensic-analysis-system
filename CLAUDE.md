# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Automated digital forensics analysis system (Bachelor thesis project). Combines traditional forensic tools (Dissect, Sleuth Kit, UAC) with LLM-based analysis (Ollama/Llama 3.1) and ML anomaly detection. The codebase and comments are in German.

## Commands

### Development
```bash
# Start backend with auto-reload (activates venv, starts Ollama, creates dirs)
./scripts/run_dev.sh

# Run API server directly
uvicorn backend.api:app --host 0.0.0.0 --port 8000 --reload

# Run CLI pipeline directly on a file
python backend/pipeline.py /path/to/image.dd --output_dir output
```

### Testing
```bash
# Run all tests with coverage
./scripts/run_tests.sh

# Run tests directly
pytest tests/

# Run a single test file
pytest tests/test_api.py

# Run with coverage report
pytest tests/ --cov=backend --cov-report=html
```

### Code Quality
```bash
black --line-length 100 --target-version py311 backend/
isort --profile black --line-length 100 backend/
flake8 backend/
mypy backend/
```

### Docker
```bash
docker compose -f docker/docker-compose.yml up
```

### Ollama Setup
```bash
./scripts/setup_ollama.sh  # Installs Ollama and pulls llama3.1
```

## Architecture

### 8-Stage Analysis Pipeline (`backend/pipeline.py`)

The core is a sequential pipeline orchestrated via Click CLI (also callable from the API):

1. **File Detection** - Identifies input type (disk_image, logs, uac_dump, ram_dump) via extension, MIME type, and directory structure
2. **UAC Processing** - Runs UAC artifact collector (only for dumps/logs/RAM, not disk images)
3. **Dissect Parsing** - Extracts artifacts (MFT, EventLogs, Registry, Users) from images/logs via `dissect.target`
4. **Sleuth Kit Analysis** - Builds filesystem timeline from disk images via `pytsk3` with recursive directory walking
5. **Data Normalization** (`backend/modules/normalizer.py`) - Standardizes events from all sources into a common schema
6. **Anomaly Detection** (`backend/modules/anomaly_detector.py`) - IsolationForest ML model (4 features: hour, day-of-week, file size log, path depth)
7. **AI Preprocessing** (`backend/modules/ai_preprocessor.py`) - Filters top-1000 suspicious events, extracts key indicators (IPs, domains, users, processes, files)
8. **LLM Agent Analysis** (`backend/llm_agent/agent.py`) - Three LLM calls: anomaly detection, timeline interpretation (with MITRE ATT&CK), and executive report generation

### API Layer (`backend/api.py`)

FastAPI server with background task processing. Job tracking is in-memory (dict-based, not persistent). Endpoints:
- `POST /analyze` - Upload file, returns `job_id` (HTTP 202)
- `GET /status/{job_id}` - Poll job progress (0-100%)
- `GET /results/{job_id}` - List output files
- `GET /download/{job_id}/{filename}` - Download result files

The API imports `run_pipeline` from `pipeline.py` and calls it in a `BackgroundTasks` handler.

### LLM Integration (`backend/llm_agent/`)

- **OllamaClient** - HTTP client for local Ollama API (`/api/generate`)
- **PromptManager** - Loads templates from `prompts/templates/` and system prompts from `prompts/system_prompts/`
- **RAGHandler** - Retrieves context from `rag/knowledge_base/` (IOCs, MITRE techniques, malware signatures)
- **ForensicLLMAgent** - Orchestrates detect_anomalies, interpret_timeline, generate_report with RAG enrichment

### Configuration (`backend/config.py`)

All settings via environment variables with sensible defaults. Key config areas: file limits, tool timeouts, LLM parameters (model, temperature per task type, tokens), RAG settings, API config, feature flags. Copy `.env.example` to `.env` to customize.

### Data Flow

```
Input File → detect_input_type()
  → [UAC / Dissect / SleuthKit] → raw artifacts + timeline
  → DataNormalizer → normalized events (common schema)
  → AnomalyDetector (IsolationForest) → scored events
  → AIPreprocessor → top-1000 filtered + indicators
  → ForensicLLMAgent → anomalies + interpretation + report.md
  → Export → report.md, timeline.csv, anomalies_detected.json, etc.
```

### Output Files (per job in `data/outputs/{job_id}/`)

`report.md`, `timeline.csv`, `anomalies_detected.json`, `preprocessed_for_llm.json`, `normalized_output.json`, `interpretation.json`, `analysis_summary.json`

## Key Design Decisions

- **Pipeline uses relative imports from `backend/` root** - modules are imported as `from modules.normalizer import DataNormalizer` (not `backend.modules...`), but the API imports as `from pipeline import run_pipeline`. Be aware of the working directory assumption.
- **Job storage is in-memory** - the `jobs` dict in `api.py` does not survive restarts. Docker setup includes Redis but it's not wired into job tracking yet.
- **LLM responses are parsed as JSON** - the agent expects structured JSON from Ollama. Falls back to raw text on parse failure.
- **Contamination rate 0.1** - the IsolationForest assumes ~10% of events are anomalous by default.
- **Pydantic models exist** (`backend/models/`) but the pipeline currently uses plain dicts throughout. Models define the target schema (TimelineEvent, Artifact, AnomalyDetectionResponse).

## Code Style

- Python 3.11+, Black formatter (line-length 100), isort (black profile)
- German comments and log messages throughout the codebase
- Logging uses emoji indicators: `✓` success, `✗` error, `⚠` warning, `⊘` skipped
