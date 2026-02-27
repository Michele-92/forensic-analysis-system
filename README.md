# LFX — Forensic Analysis System

Automatisiertes digitales Forensik-Analysesystem mit LLM-Integration. Kombiniert klassische Forensik-Tools (Dissect, Sleuth Kit, UAC) mit KI-basierter Analyse (Ollama/Llama 3.1), ML-Anomalieerkennung (Isolation Forest), MITRE ATT&CK Mapping mit interaktiver Kill Chain Visualisierung, Multi-Agent-System, quellenuebergreifender Fallkorrelation, Threat Intelligence Lookup (lokale KB + AbuseIPDB) und Evidence Integrity (SHA256 Chain of Custody).

---

## Inhaltsverzeichnis

- [Features](#features)
- [Systemvoraussetzungen](#systemvoraussetzungen)
- [Schnellstart](#schnellstart)
- [Manuelle Installation (Schritt fuer Schritt)](#manuelle-installation-schritt-fuer-schritt)
  - [1. Backend einrichten](#1-backend-einrichten)
  - [2. Ollama & LLM-Modell installieren](#2-ollama--llm-modell-installieren)
  - [3. Bun installieren](#3-bun-installieren-frontend-runtime)
  - [4. Frontend einrichten](#4-frontend-einrichten)
  - [5. Alles starten](#5-alles-starten)
- [Docker-Setup (Alternative)](#docker-setup-alternative)
- [Ansible-Setup (Automatisiert)](#ansible-setup-automatisiert)
- [Konfiguration](#konfiguration)
- [Benutzung](#benutzung)
  - [Fallbeispiel 1: Einzelne Log-Datei analysieren](#fallbeispiel-1-einzelne-log-datei-analysieren)
  - [Fallbeispiel 2: Multi-Agent Tiefenanalyse](#fallbeispiel-2-multi-agent-tiefenanalyse)
  - [Fallbeispiel 3: Mehrere Quellen als Fall korrelieren](#fallbeispiel-3-mehrere-quellen-als-fall-korrelieren)
  - [Fallbeispiel 4: PDF-Reports exportieren](#fallbeispiel-4-pdf-reports-exportieren)
  - [Fallbeispiel 5: Evidence Integrity — Beweismittel-Integritaet sichern](#fallbeispiel-5-evidence-integrity--beweismittel-integritaet-sichern)
  - [Fallbeispiel 6: Attack Kill Chain — Angriffsphase visualisieren](#fallbeispiel-6-attack-kill-chain--angriffsphase-visualisieren)
  - [Fallbeispiel 7: Threat Intelligence — IOCs gegen Bedrohungsdatenbanken pruefen](#fallbeispiel-7-threat-intelligence--iocs-gegen-bedrohungsdatenbanken-pruefen)
- [Architektur](#architektur)
  - [Analyse-Pipeline](#analyse-pipeline)
  - [Multi-Agent-System](#multi-agent-system)
  - [Case Correlation Agent](#case-correlation-agent)
- [API-Referenz](#api-referenz)
- [Projektstruktur](#projektstruktur)
- [Fehlerbehebung](#fehlerbehebung)

---

## Features

### Analyse & Erkennung
- **8-stufige Analyse-Pipeline** — Automatische Verarbeitung von Disk-Images, Logs, Memory-Dumps und Netzwerk-Captures
- **ML-Anomalieerkennung** — Isolation Forest mit 8 Features (Uhrzeit, Event-Typ, Keywords, externe IPs, Dateigröße etc.)
- **MITRE ATT&CK Auto-Mapping** — Automatische Zuordnung erkannter Anomalien zu MITRE-Techniken (offline, ohne API)
- **Attack Kill Chain Visualisierung** — Interaktives Diagramm aller 12 MITRE ATT&CK Phasen (Reconnaissance → Impact) mit farbkodierten aktiven Phasen, Anomalie-Zaehlern und aufklappbaren Technik-Details
- **IOC-Extraktion** — Automatische Erkennung von IP-Adressen, Domains, Benutzerkonten, Prozessen und verdaechtigen Dateien
- **Threat Intelligence Lookup** — IOC-Abgleich gegen lokale Knowledge-Base und optional AbuseIPDB (IP-Reputation). Farbige Verdict-Badges (Malicious/Suspicious/Clean/Unknown) mit Detail-Popup pro IOC
- **Evidence Integrity (Chain of Custody)** — SHA256-Hash-Berechnung beim Upload, Verifikations-Endpoint, lueckenloser Audit-Trail (Upload → Analyse → Verifikation). Hash auf PDF-Deckblatt

### KI-Analyse (Ollama, lokal)
- **Quick-Analyse** — Schnelle Bedrohungseinschaetzung der Top-Anomalien (1-2 Min)
- **Multi-Agent-System** — 3 spezialisierte KI-Agenten arbeiten sequentiell:
  - **Triage Agent** (SOC Level 1): Klassifiziert Anomalien als KRITISCH / VERDAECHTIG / FALSE POSITIVE
  - **Analyst Agent** (Senior DFIR): Korreliert Events, erstellt Angriffsketten, mappt MITRE ATT&CK
  - **Reporter Agent** (Forensik-Autor): Erstellt gerichtsverwertbaren Bericht
- **Case Correlation Agent** — Quellenuebergreifende Korrelation: Findet gemeinsame IOCs, zeitliche Muster und Angriffsketten ueber mehrere Dateien

### Fall-Management & UI
- **Case Management** — Dateien in Fall-Ordner gruppieren per Drag & Drop
- **Sidebar Tree-View** — Hierarchische Ansicht: Faelle → Analysen, mit Suche und Inline-Umbenennung
- **Bidirektionales Drag & Drop** — Analysen zwischen Faellen verschieben oder herauslösen
- **3 Analyse-Views** — Overview (Zusammenfassung), Analytics (Charts), Intelligence (KI-Analyse)
- **PDF-Export** — Professionelle forensische Berichte (Einzelanalyse + Fall-Korrelation)
- **Persistenz** — Alle Ergebnisse und Einstellungen bleiben ueber Browser-Sessions erhalten (localStorage)

### Unterstuetzte Dateiformate
| Kategorie | Formate |
|---|---|
| Disk-Images | `.dd`, `.raw`, `.img`, `.e01`, `.ewf`, `.vdi`, `.vmdk` |
| Memory-Dumps | `.mem`, `.dmp`, `.dump` |
| Logs | `.log`, `.txt`, `.syslog`, `.evtx` |
| Netzwerk | `.pcap`, `.pcapng` |
| Archive | `.zip`, `.tar`, `.gz` |

---

## Systemvoraussetzungen

| Komponente | Version | Hinweis |
|---|---|---|
| **Python** | >= 3.11 | Backend + Pipeline |
| **Bun** | >= 1.0 | Frontend (JavaScript Runtime + Package Manager) |
| **Ollama** | latest | Lokale LLM-Inferenz |
| **libmagic** | — | Fuer Dateityp-Erkennung (`python-magic`) |

### Betriebssystem

- **Linux** (empfohlen) — volle Unterstuetzung
- **macOS** — volle Unterstuetzung
- **Windows** — funktioniert ueber WSL2 oder Cygwin (libmagic muss manuell installiert werden)

### Optional

- **Docker + Docker Compose** — fuer containerisiertes Setup
- **NVIDIA GPU** — fuer schnellere LLM-Inferenz via Ollama

---

## Schnellstart

Fuer Ungeduldige — alle Schritte in einem Block:

```bash
# 1. In Projektordner wechseln
cd forensic-analysis-system

# 2. Python Virtual Environment
python3 -m venv venv
source venv/bin/activate          # Linux/macOS
# source venv/Scripts/activate    # Windows (Git Bash / Cygwin)

# 3. Backend-Dependencies installieren
pip install -e .

# 4. Ollama installieren & Modell laden
curl -fsSL https://ollama.ai/install.sh | sh
ollama serve &                     # Ollama-Server starten
ollama pull llama3.1               # LLM-Modell herunterladen (~4.7 GB)

# 5. Verzeichnisse erstellen
mkdir -p data/{uploads,outputs,samples} logs

# 6. Backend starten (Terminal 1)
cd backend && uvicorn api:app --reload --host 0.0.0.0 --port 8000

# 7. Frontend starten (Terminal 2)
cd frontend && bun install && bun dev

# 8. Browser oeffnen
# → http://localhost:5173
```

---

## Manuelle Installation (Schritt fuer Schritt)

### 1. Backend einrichten

```bash
# Virtual Environment erstellen
python3 -m venv venv

# Aktivieren
source venv/bin/activate          # Linux/macOS
source venv/Scripts/activate      # Windows (Git Bash / Cygwin)

# Dependencies installieren
pip install -e .

# (Optional) Entwicklungs-Dependencies
pip install -r requirements-dev.txt
```

#### libmagic installieren (falls nicht vorhanden)

```bash
# Ubuntu / Debian
sudo apt-get install libmagic1

# macOS
brew install libmagic

# Windows (ueber python-magic-bin)
pip install python-magic-bin
```

#### Verzeichnisse erstellen

```bash
mkdir -p data/uploads data/outputs data/samples data/llm_cache logs
```

#### Backend-Konfiguration

```bash
# .env-Datei aus Vorlage erstellen
cp .env.example .env

# Anpassen nach Bedarf
nano .env
```

### 2. Ollama & LLM-Modell installieren

Ollama wird fuer die lokale LLM-Inferenz benoetigt (Llama 3.1).

```bash
# Linux
curl -fsSL https://ollama.ai/install.sh | sh

# macOS
brew install ollama

# Windows
# → Download von https://ollama.com/download
```

```bash
# Ollama-Server starten
ollama serve

# Llama 3.1 Modell herunterladen (8B Parameter, ~4.7 GB)
ollama pull llama3.1

# Ueberpruefen
ollama list
```

> **Hinweis:** Der Ollama-Server muss laufen, bevor das Backend gestartet wird.
> Standard-URL: `http://localhost:11434`

### 3. Bun installieren (Frontend Runtime)

Bun wird als schnelle JavaScript-Runtime und Package-Manager fuer das Frontend verwendet.

```bash
# Linux / macOS
curl -fsSL https://bun.sh/install | bash

# Windows (PowerShell)
powershell -c "irm bun.sh/install.ps1 | iex"

# Alternativ ueber npm (falls Node.js bereits installiert)
npm install -g bun
```

Nach der Installation Terminal neu starten und pruefen:
```bash
bun --version
# → 1.x.x
```

> **Hinweis:** Bun ist ein Drop-in-Replacement fuer Node.js + npm. Es nutzt dieselbe `package.json` und `node_modules`-Struktur, ist aber deutlich schneller bei Installation und Ausfuehrung.

### 4. Frontend einrichten

```bash
cd frontend

# Dependencies installieren
bun install
```

### 5. Alles starten

Du brauchst **drei Terminals**:

**Terminal 1 — Ollama:**
```bash
ollama serve
```

**Terminal 2 — Backend:**
```bash
source venv/bin/activate          # oder: source venv/Scripts/activate
cd backend
uvicorn api:app --reload --host 0.0.0.0 --port 8000
```

**Terminal 3 — Frontend:**
```bash
cd frontend
bun dev
```

#### Zugriff

| Service | URL |
|---|---|
| **Frontend** | http://localhost:5173 |
| **Backend API** | http://localhost:8000 |
| **API Docs (Swagger)** | http://localhost:8000/docs |
| **Ollama** | http://localhost:11434 |

---

## Docker-Setup (Alternative)

Statt manueller Installation kann das gesamte System mit **einem Befehl** ueber Docker gestartet werden. Alle drei Komponenten (Backend, Frontend, Ollama) laufen in separaten Containern und kommunizieren ueber ein internes Netzwerk.

### Voraussetzungen

| Software | Version | Pruefen mit |
|---|---|---|
| **Docker** | >= 24.0 | `docker --version` |
| **Docker Compose** | >= 2.20 (im Docker enthalten) | `docker compose version` |

> **Hinweis:** Auf Windows/macOS installiert [Docker Desktop](https://www.docker.com/products/docker-desktop/) beides zusammen. Auf Linux: [Docker Engine](https://docs.docker.com/engine/install/) installieren.

### Erster Start (Schritt fuer Schritt)

```bash
# 1. In das Projektverzeichnis wechseln
cd forensic-analysis-system

# 2. Alle Container bauen und starten
docker compose -f docker/docker-compose.yml up --build -d

# 3. Warten bis alle Container laufen (ca. 2-3 Minuten beim ersten Mal)
docker compose -f docker/docker-compose.yml ps

# 4. LLM-Modell in den Ollama-Container laden (einmalig, ~4.7 GB Download)
docker exec -it forensic-ollama ollama pull llama3.1

# 5. Browser oeffnen
#    → http://localhost:3000
```

> **Wichtig:** Schritt 4 muss nur beim **allerersten Start** ausgefuehrt werden. Das Modell wird im Docker-Volume `ollama-data` persistent gespeichert und bleibt auch nach `docker compose down` erhalten.

### Services-Uebersicht

| Service | Container | Port | Beschreibung |
|---|---|---|---|
| **Frontend** | `forensic-frontend` | [localhost:3000](http://localhost:3000) | React-Dashboard (nginx) |
| **Backend** | `forensic-backend` | [localhost:8000](http://localhost:8000) | FastAPI + Analyse-Pipeline |
| **Ollama** | `forensic-ollama` | [localhost:11434](http://localhost:11434) | Lokale LLM-Inferenz (Llama 3.1) |

**Architektur:**
```
Browser → :3000 (nginx)
              ├── /       → Statische React-App
              └── /api/*  → Proxy zu Backend (:8000)
                               └── LLM-Calls → Ollama (:11434)
```

Das Frontend (nginx) fungiert als Reverse-Proxy: Alle API-Anfragen (`/api/...`) werden automatisch an den Backend-Container weitergeleitet. SSE-Streams (fuer Multi-Agent-Analyse und Fallkorrelation) werden korrekt durchgereicht.

### Haeufige Befehle

```bash
# Starten (im Hintergrund)
docker compose -f docker/docker-compose.yml up -d

# Starten mit Neu-Build (nach Code-Aenderungen)
docker compose -f docker/docker-compose.yml up --build -d

# Status aller Container pruefen
docker compose -f docker/docker-compose.yml ps

# Logs anzeigen (alle Services)
docker compose -f docker/docker-compose.yml logs -f

# Logs eines einzelnen Services
docker compose -f docker/docker-compose.yml logs -f backend

# Stoppen (Container bleiben erhalten)
docker compose -f docker/docker-compose.yml stop

# Stoppen und Container entfernen
docker compose -f docker/docker-compose.yml down

# Alles entfernen inkl. Volumes (LLM-Modell wird geloescht!)
docker compose -f docker/docker-compose.yml down -v
```

### GPU-Support fuer Ollama (optional)

Wenn eine **NVIDIA GPU** verfuegbar ist, kann Ollama diese fuer deutlich schnellere LLM-Inferenz nutzen.

**Voraussetzung:** [NVIDIA Container Toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/install-guide.html) installieren.

Dann in `docker/docker-compose.yml` den auskommentierten `deploy`-Block beim `ollama`-Service aktivieren:

```yaml
  ollama:
    image: ollama/ollama:latest
    # ... (bestehende Konfiguration)
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: 1
              capabilities: [gpu]
```

Danach neu starten:
```bash
docker compose -f docker/docker-compose.yml up -d ollama
```

### Daten-Persistenz

| Daten | Speicherort | Persistenz |
|---|---|---|
| Hochgeladene Dateien & Ergebnisse | `data/` (Bind-Mount) | Auf dem Host-System, bleibt immer erhalten |
| Log-Dateien | `logs/` (Bind-Mount) | Auf dem Host-System |
| Ollama-Modelle | Docker-Volume `ollama-data` | Ueberlebt `down`, wird nur bei `down -v` geloescht |
| Fall-Management & UI-Einstellungen | Browser localStorage | Im Browser des Nutzers |

---

## Ansible-Setup (Automatisiert)

Das beigelegte Ansible-Playbook installiert **alle Abhängigkeiten automatisch** mit einem einzigen Befehl — Python-Umgebung, Bun, Ollama, LLM-Modell, Verzeichnisse und Konfiguration. Ideal für eine reproduzierbare Erstinstallation auf einem neuen System.

### Voraussetzungen

| Software | Installation |
|---|---|
| **Ansible** | `pip install ansible` oder `brew install ansible` |
| **Python 3** | Muss bereits vorhanden sein |

> **Hinweis:** Ansible läuft nativ auf **Linux und macOS**. Unter Windows wird **WSL2** (Windows Subsystem for Linux) benötigt.

### Schnellstart

```bash
# 1. Ansible installieren (falls noch nicht vorhanden)
pip install ansible

# 2. Playbook ausführen (-K fragt nach dem sudo-Passwort)
ansible-playbook ansible/setup.yml -K
```

Das Playbook führt automatisch folgende Schritte aus:

| Schritt | Beschreibung |
|---|---|
| **System-Pakete** | Python 3.11, libmagic, curl, git (via apt / Homebrew) |
| **Python venv** | Virtual Environment unter `venv/` erstellen |
| **Backend-Deps** | `pip install -e .` (alle Abhängigkeiten aus `pyproject.toml`) |
| **Bun** | JavaScript-Runtime für das Frontend installieren |
| **Frontend-Deps** | `bun install` im `frontend/`-Verzeichnis |
| **Ollama** | Lokale LLM-Infrastruktur installieren |
| **LLM-Modell** | `llama3.1` herunterladen (~4.7 GB, einmalig) |
| **Verzeichnisse** | `data/`, `logs/`, `rag/` Ordnerstruktur anlegen |
| **Konfiguration** | `.env` aus `.env.example` erstellen (ohne Überschreiben) |

### Nach dem Playbook

Nach erfolgreichem Durchlauf drei Terminals öffnen:

```bash
# Terminal 1 — Ollama (falls nicht automatisch gestartet)
ollama serve

# Terminal 2 — Backend
source venv/bin/activate
cd backend && uvicorn api:app --reload --host 0.0.0.0 --port 8000

# Terminal 3 — Frontend
cd frontend && bun dev
```

Browser öffnen: **http://localhost:5173**

### Einzelne Tasks überspringen (Tags)

Das Playbook unterstützt selektive Ausführung über Ansible-Tags:

```bash
# Nur Python-Abhängigkeiten installieren
ansible-playbook ansible/setup.yml -K --tags python

# Nur Ollama + Modell installieren
ansible-playbook ansible/setup.yml -K --tags ollama

# Alles außer dem LLM-Download (spart Zeit bei erneutem Ausführen)
ansible-playbook ansible/setup.yml -K --skip-tags ollama
```

### Unterstützte Systeme

| System | Status | Hinweis |
|---|---|---|
| Ubuntu 22.04 / 24.04 | ✅ Nativ | Vollständig unterstützt |
| Debian 11 / 12 | ✅ Nativ | Vollständig unterstützt |
| macOS (Homebrew) | ✅ Nativ | Vollständig unterstützt |
| Windows (nativ) | ❌ Nicht möglich | Ansible läuft nicht nativ auf Windows |
| Windows (WSL2) | ✅ Über WSL2 | Ubuntu in WSL2 → Playbook funktioniert vollständig |

> **Windows-Nutzer:** Das Playbook erkennt Windows automatisch und gibt eine
> Schritt-für-Schritt-Anleitung für WSL2 aus. Die vollständige Anleitung
> befindet sich in [`ansible/windows_wsl2_setup.md`](ansible/windows_wsl2_setup.md).

---

## Konfiguration

### Backend (.env)

Die Datei `.env` im Projektroot steuert das Backend. Erstelle sie aus `.env.example`:

```bash
cp .env.example .env
```

Wichtigste Einstellungen:

| Variable | Default | Beschreibung |
|---|---|---|
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama-Server URL |
| `DEFAULT_LLM_MODEL` | `llama3.1` | LLM-Modell fuer Analyse |
| `LLM_TIMEOUT` | `120` | Timeout fuer LLM-Anfragen (Sekunden) |
| `LLM_MAX_TOKENS` | `2000` | Max. Tokens pro Antwort |
| `API_PORT` | `8000` | Backend-Port |
| `MAX_FILE_SIZE` | `10737418240` | Max. Upload-Groesse (10 GB) |
| `ANOMALY_CONTAMINATION` | `0.1` | Erwarteter Anomalie-Anteil (10%) |
| `RAG_ENABLED` | `true` | Knowledge Base aktivieren |
| `ABUSEIPDB_API_KEY` | *(leer)* | AbuseIPDB API-Key fuer IP-Reputation (optional) |
| `LOG_LEVEL` | `INFO` | Log-Level (DEBUG/INFO/WARNING/ERROR) |

### Frontend (.env)

Die Datei `frontend/.env` steuert das Frontend:

| Variable | Default | Beschreibung |
|---|---|---|
| `VITE_BACKEND_URL` | `/api` | Backend API URL (Proxy-Pfad) |

---

## Benutzung

### Fallbeispiel 1: Einzelne Log-Datei analysieren

**Szenario:** Du hast eine `auth.log` von einem kompromittierten Server und willst wissen, was passiert ist.

**Schritte:**

1. **Browser oeffnen:** http://localhost:5173
2. **Datei hochladen:** Die `auth.log` in die Upload-Zone (unten links in der Sidebar) per Drag & Drop ziehen
3. **Analyse abwarten:** Der StatusMonitor in der Sidebar zeigt den Fortschritt der 8-stufigen Pipeline:
   - Dateityp-Erkennung → Log-Parsing → Normalisierung → Anomalieerkennung → MITRE-Mapping → KI-Vorverarbeitung → Report
4. **Ergebnisse ansehen:**

   **Overview-Tab:**
   - Executive Summary mit Gesamtrisiko (KRITISCH/HOCH/MITTEL/NIEDRIG)
   - Stat-Cards: Anzahl Events, Anomalien, IOCs
   - Evidence Integrity: SHA256-Hash mit Verifikation und Audit-Trail
   - Key Findings: Die wichtigsten Erkenntnisse
   - IOC-Liste: Erkannte IP-Adressen, Domains, Benutzerkonten — mit optionalem Threat Intelligence Lookup

   **Analytics-Tab:**
   - **Temporal Anomaly Engine:** Zeitlicher Verlauf aller Events (blaue Kurve) mit Anomalie-Markern (farbige Punkte). Linke Y-Achse = Events/Stunde, rechte Y-Achse = Anomaly Score (0-100%)
   - **Artefakt-Taxonomie:** Verteilung der Event-Typen als Donut-Chart
   - **Event-Tabelle:** Durchsuchbare Tabelle aller Events mit Sortierung

   **Intelligence-Tab:**
   - **KI Quick-Analyse:** Klick auf "Analysieren" startet eine schnelle Ollama-Bedrohungsanalyse (1-2 Min)
   - **Attack Kill Chain:** Interaktives Diagramm aller 12 MITRE ATT&CK Phasen — zeigt sofort welche Angriffsphasen betroffen sind
   - **Anomalie-Liste:** Alle erkannten Anomalien mit Scores, Event-Typ und MITRE-Techniken

### Fallbeispiel 2: Multi-Agent Tiefenanalyse

**Szenario:** Die Quick-Analyse zeigt kritische Anomalien. Du willst eine ausfuehrliche, strukturierte Analyse durch spezialisierte KI-Agenten.

**Schritte:**

1. **Intelligence-Tab oeffnen** (nach abgeschlossener Analyse)
2. **"Agenten-Analyse starten" klicken**
3. **3 Agenten arbeiten sequentiell** (Echtzeit-Updates via SSE):

   | Agent | Rolle | Dauer | Ergebnis |
   |---|---|---|---|
   | **Triage** | SOC Level 1 Analyst | ~2 Min | Klassifizierung jeder Anomalie (KRITISCH/VERDAECHTIG/FALSE POSITIVE) |
   | **Analyst** | Senior DFIR (10+ Jahre) | ~3 Min | Angriffskette, MITRE ATT&CK Mapping, korrelierte Findings, IOCs |
   | **Reporter** | Forensik-Autor | ~3 Min | Gerichtsverwertbarer Bericht mit Executive Summary, Empfehlungen |

4. **Ergebnisse lesen:** Jeder Agent hat eine eigene Karte mit aufklappbarem Ergebnis (Markdown-formatiert)
5. **Ergebnisse bleiben gespeichert** — auch nach Seiten-Reload

> **Hinweis:** Die Multi-Agent-Analyse benoetigt ca. 8-10 Minuten (3 sequentielle LLM-Aufrufe). Die Agenten-Karten zeigen den Live-Status waehrend der Analyse.

### Fallbeispiel 3: Mehrere Quellen als Fall korrelieren

**Szenario:** Du hast mehrere Log-Dateien vom selben Vorfall (z.B. `firewall.log`, `auth.log`, `syslog`) und willst quellenuebergreifende Muster erkennen.

**Schritte:**

1. **Alle Dateien hochladen:** Jede Datei einzeln per Drag & Drop hochladen (jede wird unabhaengig analysiert)
2. **Fall-Ordner erstellen:**
   - Klick auf "+" neben "Faelle" in der Sidebar
   - Fallname eingeben (z.B. "Vorfall Server-01")
   - Optional: Aktenzeichen, Analyst
3. **Analysen zuordnen:** Die fertig analysierten Dateien per Drag & Drop in den Fall-Ordner ziehen
4. **Fallkorrelation starten:**
   - Fall-Ordner aufklappen (Klick auf den Pfeil)
   - Der Button "Fallkorrelation" erscheint (ab 2 abgeschlossenen Analysen)
   - Klick auf "Fallkorrelation" → Korrelations-View oeffnet sich
5. **"Korrelation starten" klicken:**
   - **Phase 1:** Geteilte IOCs werden sofort berechnet (Python, kein LLM) und angezeigt
   - **Phase 2:** LLM analysiert quellenuebergreifende Muster (~5 Min)
6. **Ergebnisse:**
   - **Stat-Cards:** Quellen-Anzahl, Events gesamt, Anomalien gesamt, geteilte IOCs
   - **Quellenuebergreifende IOCs:** Welche IPs, Benutzer, Hostnamen in mehreren Dateien auftauchen (mit Quellenangabe Q1, Q2, ...)
   - **Korrelationsbericht:** Executive Summary, Angriffskette ueber alle Quellen, MITRE ATT&CK Matrix, Risikobewertung, Empfehlungen
7. **Fall-PDF exportieren:** Klick auf "Case PDF" fuer einen kombinierten Bericht aller Quellen

> **Tipp:** Du kannst Analysen jederzeit per Drag & Drop zwischen Faellen verschieben oder aus einem Fall herausloesen (in den "Ungroupiert"-Bereich ziehen).

### Fallbeispiel 4: PDF-Reports exportieren

**Einzelanalyse-PDF:**
1. Overview-Tab oeffnen
2. "PDF Export" Button klicken (oben rechts)
3. PDF wird heruntergeladen mit: Deckblatt, Executive Summary, Anomalie-Tabelle, MITRE ATT&CK Mapping, IOC-Liste, Empfehlungen

**Fall-Korrelations-PDF:**
1. Fallkorrelation durchfuehren (siehe Fallbeispiel 3)
2. "Case PDF" Button klicken
3. PDF wird heruntergeladen mit: Fall-Deckblatt, Quellen-Uebersicht, geteilte IOCs, kombinierte MITRE-Tabelle, Korrelationsbericht

> Die PDFs sind im professionellen Forensik-Report-Format gestaltet mit dem Vermerk "VERTRAULICH" und eignen sich fuer die Dokumentation und Weitergabe.

### Fallbeispiel 5: Evidence Integrity — Beweismittel-Integritaet sichern

**Szenario:** Du fuehrst eine forensische Analyse fuer ein laufendes Ermittlungsverfahren durch. Der Staatsanwalt verlangt den Nachweis, dass die analysierte Datei seit dem Upload nicht veraendert wurde — eine lueckenlose Chain of Custody ist erforderlich.

**Wann ist das nuetzlich?**
- **Gerichtsverwertbare Analysen:** Wenn forensische Ergebnisse als Beweismittel vor Gericht verwendet werden sollen, muss die Integritaet der Ursprungsdatei nachweisbar sein
- **Compliance-Anforderungen:** Bei Vorfaellen in regulierten Branchen (Banken, Gesundheitswesen) verlangen Aufsichtsbehoerden den Nachweis, dass Beweismittel nicht manipuliert wurden
- **Mehrere Analysten arbeiten am selben Fall:** Um sicherzustellen, dass alle Analysten mit identischen Quelldateien arbeiten
- **Langzeitarchivierung:** Wenn Analyse-Ergebnisse Monate spaeter erneut geprueft werden und die Dateiintegritaet bestaetigt werden muss

**Schritte:**

1. **Datei hochladen:** Ziehe die Datei in die Upload-Zone. Das System berechnet **automatisch** einen SHA256-Hash und zeigt ihn im Upload-Response
2. **Overview-Tab oeffnen:** Unterhalb der Risiko-Uebersicht erscheint die **"Evidence Integrity"**-Card:
   - **SHA256-Hash** in Monospace-Schrift (klick auf Copy-Icon zum Kopieren)
   - **Status-LED:** Grau = "Nicht geprueft" (Standardzustand nach Upload)
3. **Integritaet verifizieren:** Klick auf **"Verifizieren"**:
   - Das Backend berechnet den SHA256-Hash der gespeicherten Datei erneut
   - Vergleicht mit dem beim Upload berechneten Original-Hash
   - **Gruenes Shield** = Datei unverändert (Hash stimmt ueberein)
   - **Rotes Shield** = Datei wurde nach dem Upload veraendert (ALARM!)
4. **Audit-Trail pruefen:** Nach der Verifikation erscheint eine chronologische Timeline:
   - `Datei hochgeladen` — Zeitstempel + Dateigroesse + Hash
   - `Analyse gestartet` — Zeitstempel + Output-Pfad
   - `Analyse abgeschlossen` — Zeitstempel + erzeugte Dateien
   - `Integritaet geprueft` — Zeitstempel + Ergebnis (OK / FAIL)
5. **PDF-Export:** Der SHA256-Hash erscheint automatisch auf dem **Deckblatt** des PDF-Reports — ideal fuer die Aktenablage

> **Tipp:** Den Hash bei der ersten Analyse notieren und spaeter per "Verifizieren" gegenkontrollieren. So entsteht eine nachvollziehbare Beweiskette, die auch Monate spaeter belastbar ist.

### Fallbeispiel 6: Attack Kill Chain — Angriffsphase visualisieren

**Szenario:** Die Anomalieerkennung hat 25 verdaechtige Events gefunden, jeweils mit MITRE ATT&CK Zuordnungen. Du willst schnell verstehen, in welcher Phase eines Angriffs sich der Vorfall befindet — handelt es sich um Reconnaissance (Aufklaerung) oder hat der Angreifer bereits Daten exfiltriert?

**Wann ist das nuetzlich?**
- **Angriffsphase schnell einschaetzen:** Statt jede Anomalie einzeln durchzugehen, siehst du sofort welche Kill-Chain-Phasen betroffen sind
- **Incident-Response-Priorisierung:** Wenn "Exfiltration" oder "Impact" aktiv sind, ist sofortiges Handeln noetig. Bei "Reconnaissance" bleibt mehr Zeit
- **Berichterstattung an Management:** Die Kill Chain ist ein visuelles Kommunikationsmittel, das auch Nicht-Techniker verstehen
- **Vergleich zwischen Vorfaellen:** Zwei Analysen nebeneinander zeigen, ob der gleiche Angreifer ein aehnliches Muster nutzt
- **Luecken in der Verteidigung erkennen:** Wenn bestimmte Phasen (z.B. "Defense Evasion") besonders viele Treffer zeigen, fehlen dort moeglicherweise Detektionsmechanismen

**Schritte:**

1. **Analyse abschliessen** (Log-Datei hochladen und Pipeline durchlaufen lassen)
2. **Intelligence-Tab oeffnen:** Zwischen der KI Quick-Analyse und der Multi-Agent-Analyse erscheint die **"Attack Kill Chain"**:
   - 12 MITRE ATT&CK Phasen als horizontaler Fluss mit Pfeilen
   - **Aktive Phasen** (mit erkannten Anomalien): Farbig hervorgehoben mit Anomalie-Zaehler als Badge
   - **Inaktive Phasen:** Ausgegraut (keine Anomalien in dieser Phase erkannt)
   - Die Anzeige "X / 12 Phasen aktiv" gibt einen schnellen Ueberblick
3. **Phase anklicken:** Klick auf eine aktive Phase klappt Details auf:
   - Liste aller zugeordneten **MITRE-Techniken** (z.B. T1110 Brute Force)
   - Anzahl der Treffer pro Technik
   - Klick auf eine **Technik-ID** oeffnet die offizielle MITRE ATT&CK Webseite dazu
4. **Farbkodierung interpretieren:**
   - Blau/Violett (fruehe Phasen): Reconnaissance, Initial Access
   - Orange/Rot (spaete Phasen): Command & Control, Exfiltration, Impact
   - Je mehr Anomalien in einer Phase, desto intensiver die Farbe

> **Beispiel-Interpretation:** Wenn die Phasen "Initial Access", "Execution" und "Credential Access" aktiv sind, aber "Exfiltration" nicht, deutet das auf einen laufenden Angriff hin, bei dem der Angreifer noch keine Daten gestohlen hat — sofortiges Eingreifen kann den Schaden begrenzen.

### Fallbeispiel 7: Threat Intelligence — IOCs gegen Bedrohungsdatenbanken pruefen

**Szenario:** Die Analyse hat 15 IP-Adressen, 3 Domains und 8 Prozesse als IOCs (Indicators of Compromise) extrahiert. Du willst wissen, ob diese in bekannten Bedrohungsdatenbanken auftauchen — ist `192.168.1.100` ein bekannter C2-Server oder nur ein interner Server?

**Wann ist das nuetzlich?**
- **Echte Bedrohungen von Fehlalarmen unterscheiden:** Eine IP mit hohem AbuseIPDB-Score ist ein staerkeres Signal als eine unbekannte IP
- **IOC-Priorisierung:** Bei vielen IOCs zuerst die als "Malicious" eingestuften untersuchen
- **Forensischer Bericht anreichern:** "Die IP 45.33.32.156 ist laut AbuseIPDB in 47 Laendern als Angreifer gemeldet (Abuse Score 89%)" ist ueberzeugender als nur "Unbekannte IP erkannt"
- **Bedrohungslage einschaetzen:** Wenn mehrere IOCs mit Tags wie "apt", "ransomware" oder "c2" uebereinstimmen, deutet das auf eine gezielte Attacke hin
- **Interne Wissensbasis aufbauen:** Die lokale Knowledge-Base (`rag/knowledge_base/iocs.json`) waechst mit jedem untersuchten Vorfall

**Schritte:**

1. **Overview-Tab oeffnen** (nach abgeschlossener Analyse)
2. **"TI Lookup" klicken:** Der lila Button rechts neben "Indicators of Compromise"
   - Das System prueft **jeden einzelnen IOC** gegen:
     - **Lokale Knowledge-Base** (`rag/knowledge_base/iocs.json`) — Sofortergebnis, kein Netzwerk noetig
     - **AbuseIPDB** (optional, nur fuer IPs) — Wenn ein API-Key konfiguriert ist
3. **Ergebnisse ablesen:** Jeder IOC bekommt ein farbiges **Verdict-Badge:**
   - 🔴 **Malicious** (rot) — Bekannte Bedrohung mit hoher Konfidenz (z.B. bekannter C2-Server)
   - 🟠 **Suspicious** (orange) — Verdaechtig, aber nicht eindeutig (z.B. mittlere Konfidenz in KB)
   - 🟢 **Clean** (gruen) — Geprueft und als unbedenklich eingestuft
   - ⚪ **Unknown** (grau) — In keiner Datenbank gefunden (nicht zwingend harmlos!)
4. **Details ansehen:** Klick auf ein Badge oeffnet ein **Detail-Popup** mit:
   - Quelle (Lokale KB oder AbuseIPDB)
   - Threat-Beschreibung (z.B. "Known C2 Server", "Phishing Domain")
   - Confidence-Level (high / medium / low)
   - Tags (z.B. `malware`, `apt`, `credential_theft`)
   - Erstmals gesehen (Datum)
   - Bei AbuseIPDB: Abuse-Score, Land, ISP, Anzahl Reports
5. **Ergebnisse bleiben gespeichert:** Die TI-Ergebnisse werden persistent im Job gespeichert — auch nach Browser-Reload verfuegbar

**AbuseIPDB einrichten (optional):**

Fuer IP-Reputation-Abfragen gegen AbuseIPDB (kostenlos bis 1.000 Abfragen/Tag):

1. Account erstellen: https://www.abuseipdb.com/register
2. API-Key generieren: https://www.abuseipdb.com/account/api
3. Beim Backend-Start als Umgebungsvariable setzen:
```bash
export ABUSEIPDB_API_KEY="dein_api_key_hier"
cd backend && uvicorn api:app --port 8000
```

> **Tipp:** Die lokale Knowledge-Base unter `rag/knowledge_base/iocs.json` kann jederzeit mit eigenen IOCs erweitert werden. Format pro Eintrag: `{"value": "1.2.3.4", "type": "ip", "threat": "Known C2 Server", "source": "MISP", "confidence": "high", "tags": ["malware", "c2"]}`.

---

## Architektur

### Analyse-Pipeline

Die Backend-Pipeline verarbeitet jede hochgeladene Datei in 8 Phasen:

```
Datei-Upload + SHA256-Hash (Evidence Integrity)
    ↓
[1] Dateityp-Erkennung        → disk_image / logs / ram_dump / pcap
    ↓
[2] Daten-Extraktion           → Log-Parser / Dissect / Sleuth Kit
    ↓
[3] Normalisierung             → Einheitliches Event-Format
    ↓
[4] Anomalieerkennung (ML)     → Isolation Forest (8 Features, Score 0-1)
    ↓
[5] MITRE ATT&CK Mapping      → Event-Typ → Technik-IDs (offline)
    ↓
[6] KI-Vorverarbeitung         → Top-1000 verdaechtige Events + IOC-Extraktion
    ↓
[7] Report-Generierung         → Markdown-Bericht
    ↓
[8] Export                     → JSON, CSV, Summary (inkl. SHA256-Hash)
```

**Anomalieerkennung — 8 ML-Features:**

| Feature | Beschreibung | Beispiel |
|---|---|---|
| `hour` | Stunde des Events (0-23) | 03:00 → verdaechtig |
| `day_of_week` | Wochentag (0-6) | Sonntag → ungewoehnlich |
| `event_type_score` | Verdaechtigkeits-Score des Event-Typs (1-10) | `auth_failure` → 8 |
| `is_off_hours` | Ausserhalb Geschaeftszeiten (22-06 Uhr) | 1 = ja |
| `suspicious_keyword_count` | Anzahl verdaechtiger Keywords | `sudo`, `wget`, `base64` |
| `has_external_ip` | Oeffentliche IP-Adresse vorhanden | Nicht 10.x, 192.168.x |
| `message_length` | Laenge der Nachricht (normalisiert) | Lange Commands → verdaechtig |
| `file_size_log` | Dateigroesse (log10) | Grosse Dateien → Exfiltration |

### Multi-Agent-System

3 spezialisierte LLM-Agenten arbeiten sequentiell (SSE-Streaming):

```
Anomalien + IOCs
       ↓
┌──────────────────┐
│  TRIAGE AGENT    │  SOC Level 1: Klassifiziert jede Anomalie
│  (Temp: 0.3)     │  → KRITISCH / VERDAECHTIG / FALSE POSITIVE
└────────┬─────────┘
         ↓ Triage-Ergebnisse
┌──────────────────┐
│  ANALYST AGENT   │  Senior DFIR: Korreliert Events, baut
│  (Temp: 0.4)     │  Angriffskette, mappt MITRE ATT&CK
└────────┬─────────┘
         ↓ Analyse-Ergebnisse
┌──────────────────┐
│  REPORTER AGENT  │  Forensik-Autor: Erstellt formalen
│  (Temp: 0.4)     │  gerichtsverwertbaren Bericht
└────────┬─────────┘
         ↓
   Forensischer Bericht
```

### Case Correlation Agent

Fuer Faelle mit mehreren Quellen — ein einzelner Agent mit fokussiertem Korrelations-Prompt:

```
Job 1 (auth.log) ──┐
Job 2 (firewall.log)├─→ [Python: IOC-Matching] → Geteilte IOCs
Job 3 (syslog) ────┘         ↓
                     [LLM: Korrelation] → Quellenuebergreifende Analyse
                              ↓
                     Korrelationsbericht + Fall-PDF
```

**Was der Agent identifiziert:**
- Gemeinsame IP-Adressen, Benutzer, Hostnamen ueber alle Quellen
- Zeitlich zusammenhaengende Events aus verschiedenen Quellen
- MITRE ATT&CK Angriffskette ueber mehrere Systeme
- Gesamtbild des Vorfalls aus allen Perspektiven

---

## API-Referenz

### Kern-Endpoints

| Methode | Endpoint | Beschreibung |
|---|---|---|
| `GET` | `/` | API-Info & verfuegbare Endpoints |
| `POST` | `/analyze` | Datei hochladen & Analyse starten |
| `GET` | `/status/{job_id}` | Analyse-Status & Fortschritt (0-100%) |
| `GET` | `/results/{job_id}` | Liste aller Output-Dateien |
| `GET` | `/download/{job_id}/{filename}` | Einzelne Ergebnis-Datei herunterladen |

### KI-Analyse

| Methode | Endpoint | Beschreibung |
|---|---|---|
| `POST` | `/llm-analyze` | Quick/Full LLM-Analyse (JSON) |
| `GET` | `/agent-analyze/{job_id}` | Multi-Agent-Analyse (SSE-Stream) |
| `POST` | `/case-correlate` | Quellenuebergreifende Fallkorrelation (SSE-Stream) |

### Evidence Integrity & Threat Intelligence

| Methode | Endpoint | Beschreibung |
|---|---|---|
| `POST` | `/verify/{job_id}` | SHA256-Verifikation + Audit-Trail abrufen |
| `POST` | `/threat-intel/lookup` | IOC-Abgleich gegen lokale KB + AbuseIPDB |

### Export

| Methode | Endpoint | Beschreibung |
|---|---|---|
| `POST` | `/export-pdf/{job_id}` | Einzelanalyse als PDF |
| `POST` | `/export-case-pdf` | Fall-Korrelation als PDF |

### Output-Dateien pro Analyse

| Datei | Format | Inhalt |
|---|---|---|
| `analysis_summary.json` | JSON | Metadaten: Events, Anomalien, IOCs, Zeitstempel |
| `anomalies_detected.json` | JSON | Alle Anomalien mit Scores und MITRE-Mapping |
| `normalized_output.json` | JSON | Normalisierte Timeline aller Events |
| `ai_preprocessed.json` | JSON | Gefilterte Events + extrahierte IOCs |
| `timeline.csv` | CSV | Komplette Event-Timeline |
| `report.md` | Markdown | Forensischer Bericht |

### API-Beispiele

```bash
# Datei hochladen & Analyse starten
curl -X POST http://localhost:8000/analyze \
  -F "file=@/pfad/zur/auth.log"
# → {"job_id": "20260218_143000_a1b2c3d4", "status": "processing", "file_hash": "a1b2c3d4..."}

# Status abfragen
curl http://localhost:8000/status/20260218_143000_a1b2c3d4
# → {"status": "processing", "progress": 45}

# Ergebnisse auflisten
curl http://localhost:8000/results/20260218_143000_a1b2c3d4
# → {"output_files": ["report.md", "anomalies_detected.json", ...]}

# Anomalien herunterladen
curl -O http://localhost:8000/download/20260218_143000_a1b2c3d4/anomalies_detected.json

# Quick LLM-Analyse
curl -X POST http://localhost:8000/llm-analyze \
  -H "Content-Type: application/json" \
  -d '{"anomalies": [...], "mode": "quick"}'

# Multi-Agent-Analyse (SSE-Stream)
curl -N http://localhost:8000/agent-analyze/20260218_143000_a1b2c3d4

# Fallkorrelation (SSE-Stream)
curl -N -X POST http://localhost:8000/case-correlate \
  -H "Content-Type: application/json" \
  -d '{"job_ids": ["job_id_1", "job_id_2"], "case_name": "Vorfall-001"}'

# Evidence-Integritaet verifizieren
curl -X POST http://localhost:8000/verify/20260218_143000_a1b2c3d4
# → {"verified": true, "original_hash": "a1b2c3...", "current_hash": "a1b2c3...", "audit_trail": [...]}

# Threat Intelligence Lookup
curl -X POST http://localhost:8000/threat-intel/lookup \
  -H "Content-Type: application/json" \
  -d '{"indicators": {"ips": ["192.168.1.100", "10.0.0.1"], "domains": ["malicious.example.com"]}}'
# → {"results": [{"value": "192.168.1.100", "verdict": "malicious", "confidence": "high", "sources": [...]}]}

# PDF-Export
curl -X POST http://localhost:8000/export-pdf/20260218_143000_a1b2c3d4 \
  -H "Content-Type: application/json" \
  -d '{"case_name": "Test", "analyst": "Max Mustermann"}' \
  -o report.pdf
```

---

## Projektstruktur

```
forensic-analysis-system/
│
├── backend/                        # Python FastAPI Backend
│   ├── api.py                      # REST API (alle Endpoints)
│   ├── pipeline.py                 # 8-stufige Analyse-Pipeline
│   ├── config.py                   # Zentrale Konfiguration
│   ├── llm_agent/                  # LLM-Integration
│   │   ├── agent.py                # ForensicLLMAgent (Basis-Agent)
│   │   ├── multi_agent.py          # Multi-Agent-Orchestrator (Triage → Analyst → Reporter)
│   │   ├── case_correlator.py      # Case Correlation Agent
│   │   ├── ollama_client.py        # Ollama API Client
│   │   ├── prompts.py              # Prompt-Management
│   │   └── rag_handler.py          # RAG Knowledge Base
│   ├── modules/                    # Analyse-Module
│   │   ├── anomaly_detector.py     # ML-Anomalieerkennung (Isolation Forest)
│   │   ├── mitre_mapper.py         # MITRE ATT&CK Auto-Mapping
│   │   ├── ai_preprocessor.py      # Event-Filterung fuer LLM
│   │   ├── pdf_generator.py        # PDF-Report-Generator (Einzel + Fall)
│   │   ├── normalizer.py           # Daten-Normalisierung
│   │   ├── log_parser.py           # Log-Datei Parser
│   │   ├── evidence_tracker.py     # Evidence Integrity (SHA256 + Audit-Trail)
│   │   └── threat_intel.py         # Threat Intelligence Lookup (KB + AbuseIPDB)
│   └── utils/                      # Hilfsfunktionen
│       ├── file_detector.py        # Dateityp-Erkennung (libmagic + Heuristik)
│       └── logger.py               # Logging-Konfiguration
│
├── frontend/                       # React Frontend (LFX Dashboard)
│   ├── .env                        # Frontend-Umgebungsvariablen (VITE_BACKEND_URL)
│   ├── .env.example                # Vorlage fuer .env
│   ├── index.html                  # Vite HTML-Einstiegspunkt
│   ├── package.json                # Dependencies und Scripts
│   ├── bun.lock                    # Bun Lock-Datei (wie package-lock.json)
│   ├── vite.config.js              # Vite Build-Konfiguration
│   ├── tailwind.config.js          # Tailwind CSS Konfiguration
│   ├── postcss.config.js           # PostCSS Konfiguration
│   └── src/
│       ├── main.jsx                # React Einstiegspunkt
│       ├── index.css               # Globale Styles (Tailwind)
│       ├── App.jsx                 # Root Layout + View-Routing
│       ├── api/                    # Backend API Clients
│       │   ├── backend.js          # REST API (Upload, Status, Download, PDF)
│       │   └── llm.js              # LLM API (Quick, Multi-Agent, Korrelation)
│       ├── components/
│       │   ├── Sidebar.jsx         # Case Tree-View, Drag & Drop, Suche
│       │   ├── Header.jsx          # View-Tabs, Status-Anzeige
│       │   ├── UploadZone.jsx      # Datei-Upload per Drag & Drop
│       │   ├── StatusMonitor.jsx   # Analyse-Fortschrittsanzeige
│       │   ├── CaseModal.jsx       # Fall-Erstellungsdialog
│       │   ├── MultiUploadModal.jsx # Multi-Datei-Upload-Dialog
│       │   ├── RiskBadge.jsx       # Risiko-Level Badge
│       │   ├── overview/           # Overview-View
│       │   │   ├── OverviewPanel.jsx    # Hauptpanel (Summary, Stats)
│       │   │   ├── FindingsCards.jsx     # Key Findings Karten
│       │   │   ├── IOCList.jsx          # IOC-Anzeige mit Threat Intelligence Enrichment
│       │   │   ├── EvidenceIntegrity.jsx # Evidence Integrity (Hash, Verify, Audit-Trail)
│       │   │   └── LLMReportView.jsx    # KI-Bericht Darstellung
│       │   ├── analytics/          # Analytics-View
│       │   │   ├── AnalyticsPanel.jsx   # Hauptpanel (Charts + Tabelle)
│       │   │   ├── TimelineChart.jsx    # Temporal Anomaly Engine (Dual-Axis)
│       │   │   ├── ArtifactTaxonomy.jsx # Artefakt-Verteilung (Donut-Chart)
│       │   │   └── EventTable.jsx       # Durchsuchbare Event-Tabelle
│       │   ├── intelligence/       # Intelligence-View
│       │   │   ├── IntelligencePanel.jsx # Hauptpanel (KI-Analyse)
│       │   │   ├── AttackGraph.jsx      # Attack Kill Chain Visualisierung (12 MITRE-Phasen)
│       │   │   ├── AgentAnalysisView.jsx # Multi-Agent-Ergebnisse
│       │   │   └── AnomalyList.jsx      # Anomalie-Liste mit Scores
│       │   └── correlation/        # Korrelations-View
│       │       └── CaseCorrelationPanel.jsx # Fall-Korrelation
│       ├── context/
│       │   └── AppContext.jsx      # Globaler State (Jobs, Cases, Views)
│       ├── hooks/                  # Custom React Hooks
│       │   ├── useJobs.js          # Job-Verwaltung (Upload, Polling)
│       │   ├── useCases.js         # Fall-Verwaltung (CRUD, Drag & Drop)
│       │   └── useLocalStorage.js  # Persistenter State
│       └── utils/                  # Hilfsfunktionen
│           ├── colors.js           # Farbpaletten fuer Charts
│           └── formatters.js       # Datums-/Zahlenformatierung
│
├── docker/                         # Docker-Konfiguration
│   ├── docker-compose.yml          # 3 Services: Backend, Frontend, Ollama
│   ├── Dockerfile.backend          # Python 3.11 + Dependencies
│   ├── Dockerfile.frontend         # Multi-Stage: Node Build → nginx Serve
│   └── nginx.conf                  # Reverse-Proxy (Frontend + API)
│
├── prompts/                        # LLM Prompt-Templates
│   ├── system_prompts/
│   │   └── forensic_expert.txt     # Rollendefinition fuer forensischen Experten
│   ├── templates/                  # Analyse-Templates
│   │   ├── anomaly_detection.txt   # Prompt fuer Anomalieerkennung
│   │   ├── timeline_interpretation.txt  # Prompt fuer Timeline-Interpretation
│   │   └── report_generation.txt   # Prompt fuer Report-Generierung
│   └── examples/                   # Beispiel-Outputs
│       ├── anomaly_example.json    # Beispiel: Anomalie-Erkennung
│       └── report_example.md       # Beispiel: Forensischer Bericht
│
├── scripts/                        # Hilfs-Skripte
│   ├── setup_ollama.sh             # Ollama-Installation + Modell-Download
│   ├── run_dev.sh                  # Development-Umgebung starten
│   ├── run_tests.sh                # Tests ausfuehren
│   └── generate_sample.py          # Test-Daten generieren
│
├── rag/                            # RAG Knowledge Base
│   ├── knowledge_base/
│   │   ├── iocs.json               # Bekannte Bedrohungsindikatoren
│   │   ├── techniques.json         # MITRE ATT&CK Techniken
│   │   └── signatures.json         # Malware-Signaturen
│   ├── embeddings/                 # Generierte Embeddings (Cache)
│   └── vector_store/               # Vektor-Datenbank (Cache)
│
├── data/                           # Daten-Verzeichnis (Git-ignoriert)
│   ├── uploads/                    # Hochgeladene Dateien
│   ├── outputs/                    # Analyse-Ergebnisse (pro Job-ID)
│   ├── samples/                    # Test-/Beispieldaten
│   └── llm_cache/                  # LLM-Response-Cache
│
├── logs/                           # Log-Dateien (Git-ignoriert)
│
├── .env.example                    # Backend-Konfigurationsvorlage
├── .gitignore                      # Git-Ausschluesse
├── .dockerignore                   # Docker Build-Ausschluesse
├── pyproject.toml                  # Python Projekt-Konfiguration + Dependencies
├── requirements-dev.txt            # Entwicklungs-Dependencies (Tests, Linting)
└── README.md                       # Diese Datei
```

---

## Fehlerbehebung

### Backend startet nicht

**`ModuleNotFoundError: No module named 'click'`**
```bash
pip install -e .
```

**`magic.MagicException` oder `libmagic not found`**
```bash
sudo apt-get install libmagic1      # Ubuntu/Debian
brew install libmagic                # macOS
pip install python-magic-bin         # Windows
```

### Ollama-Verbindung schlaegt fehl

```bash
# Pruefen ob Ollama laeuft
curl http://localhost:11434/api/tags

# Falls nicht → starten
ollama serve

# Modell vorhanden?
ollama list
# Falls leer → Modell laden
ollama pull llama3.1
```

### Frontend zeigt "Backend nicht erreichbar"

- Stelle sicher, dass das Backend auf Port 8000 laeuft
- Pruefe `frontend/.env` → `VITE_BACKEND_URL=/api`
- CORS ist standardmaessig auf `*` gesetzt (alle Origins erlaubt)

### LLM-Analyse dauert sehr lange

- Llama 3.1 (8B) braucht ~8 GB RAM
- Standard-Timeout: 120 Sekunden (konfigurierbar ueber `LLM_TIMEOUT`)
- GPU-Beschleunigung pruefen: `ollama ps` zeigt aktive Modelle
- Fuer schnellere Ergebnisse: GPU nutzen oder kleineres Modell (`llama3.2:3b`)

### Multi-Agent-Analyse bricht ab

- Die 3 Agenten benoetigen je 2-5 Minuten (gesamt 8-15 Min)
- Timeout im Backend ist auf 900s (15 Min) pro Agent gesetzt
- Bei Timeout: `LLM_TIMEOUT` in `.env` erhoehen
- Genug RAM sicherstellen (mindestens 8 GB frei fuer Ollama)

### Docker-spezifisch

**Ollama-Modell fehlt im Container:**
```bash
docker exec -it forensic-ollama ollama pull llama3.1
```

**Port bereits belegt:**
```bash
lsof -i :3000              # Linux/macOS
netstat -ano | findstr :3000  # Windows
```

**Ollama out-of-memory:**
- Docker Desktop → Settings → Resources → RAM erhoehen (mind. 8 GB)
- Alternativ kleineres Modell: `ollama pull llama3.2:3b`
