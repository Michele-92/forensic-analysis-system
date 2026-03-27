// ─── Datenfluss-Definitionen ─────────────────────────────────────────────────
// Jeder Flow besteht aus einem Array von "Rows".
// Jede Row hat:
//   nodes:   [{ type, name, sub, file?, icon?, explain? }]
//   arrow:   { label } | null   (null = letzte Row, kein Pfeil darunter)
//
// explain = einfache deutsche Erklärung für nicht-technische Leser

export const FLOWS = [

  // ═══════════════════════════════════════════════════════════════════════════
  // FLOW 1 — Upload & Pipeline-Start
  // ═══════════════════════════════════════════════════════════════════════════
  {
    id: 'upload',
    title: 'Upload & Pipeline-Start',
    emoji: '⬆',
    description: 'Von der Dateiauswahl im Browser bis zum Start der Backend-Pipeline',
    rows: [
      {
        nodes: [{
          type: 'user', name: 'Benutzer (Browser)', sub: 'Drag & Drop · Dateiauswahl',
          explain: 'Der Analyst zieht eine Datei (z.B. eine Log-Datei oder ein Disk-Image) per Drag & Drop in die Oberfläche – oder klickt auf die Upload-Zone. Das ist der Startpunkt der gesamten Analyse.',
        }],
        arrow: { label: 'FileList' },
      },
      {
        nodes: [{
          type: 'frontend', name: 'UploadZone.jsx', sub: 'handleFiles(fileList)  →  handleSingleFile() | setPendingFiles()', file: 'frontend/src/components/UploadZone.jsx',
          explain: 'Die Upload-Komponente entscheidet: Wurde eine einzelne Datei hochgeladen, geht es direkt weiter. Bei mehreren Dateien öffnet sich ein Dialog, in dem man optional einen neuen Fall erstellen kann.',
        }],
        arrow: { label: 'file' },
      },
      {
        nodes: [{
          type: 'hook', name: 'useJobs.js', sub: 'submitFile(file)', file: 'frontend/src/hooks/useJobs.js',
          explain: 'Dieser "Hook" (eine Art Helfer-Funktion) ist zuständig dafür, die Datei ans Backend zu senden und anschließend regelmäßig den Fortschritt abzufragen, bis die Analyse fertig ist.',
        }],
        arrow: { label: 'REST-Aufruf' },
      },
      {
        nodes: [{
          type: 'frontend', name: 'backend.js', sub: 'uploadFile(file)  →  POST /analyze', file: 'frontend/src/api/backend.js',
          explain: 'Hier werden alle Kommunikationsfunktionen mit dem Backend gebündelt. Die Datei wird als HTTP-Anfrage (POST) an den Server geschickt.',
        }],
        arrow: { label: 'HTTP POST /analyze  (multipart)' },
      },
      {
        nodes: [{
          type: 'api', name: 'api.py  ::  analyze_file()', sub: 'Datei speichern  →  job_id generieren  →  job_meta.json schreiben', file: 'backend/api.py',
          explain: 'Der Server empfängt die Datei, speichert sie sicher ab und erstellt eine eindeutige Job-ID (wie eine Auftragsnummer). Diese ID wird sofort ans Frontend zurückgesendet, damit man den Fortschritt verfolgen kann.',
        }],
        arrow: { label: 'parallele Aufrufe' },
      },
      {
        nodes: [
          {
            type: 'module', name: 'evidence_tracker.py', sub: 'compute_hashes()  →  MD5 + SHA256', file: 'backend/modules/evidence_tracker.py',
            explain: 'Für die Beweissicherung (Chain of Custody) werden sofort zwei kryptographische Prüfsummen (MD5 und SHA256) der Originaldatei berechnet. So kann später nachgewiesen werden, dass die Datei nicht verändert wurde.',
          },
          {
            type: 'pipeline', name: 'pipeline.py', sub: 'BackgroundTask  →  run_pipeline(file, job_id, output_dir)', file: 'backend/pipeline.py',
            explain: 'Die eigentliche Analyse-Pipeline wird im Hintergrund gestartet, damit der Browser nicht blockiert wird. Die Pipeline läuft durch alle 11 Stufen und erzeugt am Ende die Ergebnisdateien.',
          },
        ],
        arrow: { label: 'HTTP 202  { job_id, sha256, md5 }' },
      },
      {
        nodes: [{
          type: 'hook', name: 'useJobs.js', sub: 'setJobs(prev → [...prev, newJob])  →  startPolling(job_id)', file: 'frontend/src/hooks/useJobs.js',
          explain: 'Das Frontend speichert den neuen Job und fragt nun alle 2 Sekunden beim Server nach, ob die Analyse schon fertig ist. Der Fortschrittsbalken in der Sidebar zeigt den aktuellen Stand.',
        }],
        arrow: null,
      },
    ],
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // FLOW 2 — 11-Stufen Pipeline
  // ═══════════════════════════════════════════════════════════════════════════
  {
    id: 'pipeline',
    title: '11-Stufen Pipeline',
    emoji: '⚙',
    description: 'Alle Verarbeitungsstufen von der Dateierkennung bis zum Export',
    rows: [
      {
        nodes: [{
          type: 'pipeline', name: 'pipeline.py  ::  run_pipeline()', sub: 'Einstiegspunkt · ProgressTracker initialisieren', file: 'backend/pipeline.py',
          explain: 'Hier beginnt die automatische Analyse. Die Pipeline ist wie ein Fließband: Jede Stufe übernimmt das Ergebnis der vorherigen und verarbeitet es weiter. Ein Fortschritts-Tracker hält den Status aktuell.',
        }],
        arrow: { label: 'Stufe 1' },
      },
      {
        nodes: [{
          type: 'module', name: '[1]  file_detector.py', sub: 'FileDetector.detect_input_type()  →  disk_image | logs | uac_dump', file: 'backend/utils/file_detector.py',
          explain: 'Das System erkennt automatisch, um was für eine Datei es sich handelt – ein Disk-Image (vollständige Festplattenkopie), eine Log-Datei oder ein UAC-Dump (gesammeltes Artefakt-Paket). Dafür werden Dateiendung, MIME-Typ und Magic-Bytes geprüft.',
        }],
        arrow: { label: 'Stufe 2' },
      },
      {
        nodes: [{
          type: 'module', name: '[2]  UAC-Verarbeitung', sub: '[nur logs / uac_dump]  Artefakt-Verzeichnisse einlesen', file: 'backend/pipeline.py',
          explain: 'Falls ein UAC-Dump (ein vorgefertigtes Paket von Systemartefakten) hochgeladen wurde, werden die enthaltenen Verzeichnisse und Dateien eingelesen und für die weiteren Stufen vorbereitet.',
        }],
        arrow: { label: 'Stufe 3' },
      },
      {
        nodes: [{
          type: 'module', name: '[3]  log_parser.py', sub: 'LogParser.parse_file()  →  15 Linux-Formate  →  raw_events[]', file: 'backend/modules/log_parser.py',
          explain: 'Für Log-Dateien stehen 15 spezialisierte Parser bereit – von auth.log über Apache/Nginx bis hin zu MySQL und OpenVPN. Jeder Parser kann sein Format automatisch erkennen und in ein einheitliches Event-Format umwandeln.',
        }],
        arrow: { label: 'Stufe 4' },
      },
      {
        nodes: [{
          type: 'module', name: '[4]  Dissect-Integration', sub: '[nur disk_image]  dissect.target  →  MFT, EventLogs, Registry, Users', file: 'backend/pipeline.py',
          explain: 'Für Disk-Images wird das Tool "Dissect" eingesetzt. Es liest direkt aus dem Image: die Master File Table (Dateisystem-Index), Windows Event Logs, die Registry und Benutzerkonten – ohne das System zu booten.',
        }],
        arrow: { label: 'Stufe 5' },
      },
      {
        nodes: [{
          type: 'module', name: '[5]  Sleuth Kit Timeline', sub: '[nur disk_image]  pytsk3  →  Multi-Partition MBR/GPT  →  timeline[]', file: 'backend/pipeline.py',
          explain: 'Das Sleuth Kit ist ein klassisches Forensik-Werkzeug. Es liest die Partitionstabelle (MBR oder GPT), analysiert jede Partition einzeln und baut daraus eine vollständige Zeitlinie aller Datei-Aktivitäten.',
        }],
        arrow: { label: 'Stufe 6' },
      },
      {
        nodes: [
          {
            type: 'module', name: '[6]  normalizer.py', sub: 'DataNormalizer.normalize()  →  einheitliches Event-Schema', file: 'backend/modules/normalizer.py',
            explain: 'Alle Ereignisse aus den verschiedenen Quellen (Dissect, Sleuth Kit, Log-Parser) haben unterschiedliche Formate. Der Normalizer bringt sie alle in ein einheitliches Schema mit denselben Feldern – damit die weiteren Stufen damit arbeiten können.',
          },
          { type: 'file', name: 'normalized_output.json', sub: 'Alle Events normalisiert' },
        ],
        arrow: { label: 'Stufe 7' },
      },
      {
        nodes: [
          {
            type: 'module', name: '[7]  anomaly_detector.py', sub: 'AnomalyDetector.detect()  →  IsolationForest, 8 Features, Score 0–1', file: 'backend/modules/anomaly_detector.py',
            explain: 'Ein Machine-Learning-Algorithmus (Isolation Forest) analysiert alle Events anhand von 8 Merkmalen: Uhrzeit, Wochentag, verdächtige Keywords, externe IPs, Dateigröße u.a. Jedes Event bekommt einen Anomalie-Score von 0 (normal) bis 1 (sehr verdächtig).',
          },
          { type: 'file', name: 'anomalies_detected.json', sub: 'Anomalien mit Score' },
        ],
        arrow: { label: 'Stufe 8' },
      },
      {
        nodes: [{
          type: 'module', name: '[8]  mitre_mapper.py', sub: 'MitreMapper.map_events()  →  85 Techniken  →  is_attacker_infra Flag', file: 'backend/modules/mitre_mapper.py',
          explain: 'Jedes Event wird automatisch einer oder mehreren MITRE ATT&CK-Techniken zugeordnet. Das ist ein international anerkanntes Framework, das Angriffstechniken klassifiziert (z.B. T1110 = Brute Force, T1059 = Command Execution). 85 Techniken sind abgedeckt.',
        }],
        arrow: { label: 'Stufe 9  (FA-22)' },
      },
      {
        nodes: [
          {
            type: 'module', name: '[9]  system_profiler.py', sub: 'SystemProfiler.build_profile()  →  OS · Kernel · Dienste · Netzwerk-IPs', file: 'backend/modules/system_profiler.py',
            explain: 'Aus den Events wird automatisch ein Profil des analysierten Systems erstellt: Welches Betriebssystem? Welche Kernel-Version? Welche Dienste liefen? Welche Netzwerkadressen waren aktiv? Das gibt wichtigen Kontext für die Bewertung.',
          },
          { type: 'file', name: 'system_profile.json', sub: 'FA-22' },
        ],
        arrow: { label: 'Stufe 10  (FA-23)' },
      },
      {
        nodes: [
          {
            type: 'module', name: '[10]  antiforensics_checker.py', sub: 'AntiForensicsChecker.check()  →  9 Kategorien  →  Risiko-Score 0–100', file: 'backend/modules/antiforensics_checker.py',
            explain: 'Dieser Check sucht nach Hinweisen, dass jemand versucht hat, Spuren zu verwischen: manipulierte Zeitstempel, gelöschte Logs, Wipe-Tools (shred, wipe), Rootkit-Hinweise oder verdächtige Massenlöschungen. Jeder Befund bekommt einen Risiko-Score.',
          },
          { type: 'file', name: 'antiforensics_report.json', sub: 'FA-23' },
        ],
        arrow: { label: 'Stufe 11' },
      },
      {
        nodes: [
          {
            type: 'module', name: '[11]  ai_preprocessor.py', sub: 'AIPreprocessor.preprocess()  →  Top-1000 Events + IOC-Extraktion', file: 'backend/modules/ai_preprocessor.py',
            explain: 'Für die anschließende KI-Analyse werden die 1000 auffälligsten Events ausgewählt und wichtige Indikatoren extrahiert: IP-Adressen, Domains, Benutzerkonten, Prozesse und Dateipfade. Diese werden dem LLM übergeben.',
          },
          { type: 'file', name: 'ai_preprocessed.json', sub: 'Gefilterte Events + IOCs' },
        ],
        arrow: { label: 'Export' },
      },
      {
        nodes: [
          { type: 'file', name: 'report.md' },
          { type: 'file', name: 'timeline.csv' },
          { type: 'file', name: 'analysis_summary.json' },
          { type: 'file', name: 'job_meta.json' },
        ],
        arrow: null,
      },
    ],
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // FLOW 3 — Frontend Polling & Darstellung
  // ═══════════════════════════════════════════════════════════════════════════
  {
    id: 'frontend',
    title: 'Frontend — Ergebnisse laden',
    emoji: '🖥',
    description: 'Polling-Mechanismus, Datei-Download und Rendern im Dashboard',
    rows: [
      {
        nodes: [{
          type: 'hook', name: 'useJobs.js  ::  startPolling(job_id)', sub: 'setInterval alle 2s  →  Status abfragen', file: 'frontend/src/hooks/useJobs.js',
          explain: 'Da die Analyse mehrere Minuten dauern kann, fragt das Frontend alle 2 Sekunden beim Server nach dem aktuellen Status. Dieser Vorgang heißt "Polling". Der Fortschrittsbalken (0–100%) wird dabei laufend aktualisiert.',
        }],
        arrow: { label: 'GET /status/{job_id}' },
      },
      {
        nodes: [{
          type: 'frontend', name: 'backend.js  ::  getStatus(job_id)', sub: 'HTTP GET', file: 'frontend/src/api/backend.js',
          explain: 'Eine einfache HTTP-Anfrage an den Server: "Wie weit ist der Job mit dieser ID?" Der Server antwortet mit Status und Prozentzahl.',
        }],
        arrow: { label: 'HTTP' },
      },
      {
        nodes: [{
          type: 'api', name: 'api.py  →  { status, progress: 0–100 }', sub: 'status: queued | processing | completed | failed', file: 'backend/api.py',
          explain: 'Der Server kennt den aktuellen Stand der Pipeline und gibt ihn zurück. Sobald der Status "completed" lautet, weiß das Frontend, dass alle Ergebnisdateien bereitstehen.',
        }],
        arrow: { label: 'status === "completed"' },
      },
      {
        nodes: [{
          type: 'hook', name: 'useJobs.js  ::  loadResults(job_id)', sub: '6× fetchFileAsJson()  →  alle JSON-Ergebnisse laden', file: 'frontend/src/hooks/useJobs.js',
          explain: 'Wenn die Analyse fertig ist, werden alle 6 Ergebnisdateien automatisch heruntergeladen und im Browser-Speicher abgelegt. Ab jetzt kann der Analyst die Ergebnisse erkunden – ohne weitere Wartezeiten.',
        }],
        arrow: { label: 'Dateien laden via GET /download/...' },
      },
      {
        nodes: [
          { type: 'file', name: 'analysis_summary.json' },
          { type: 'file', name: 'anomalies_detected.json' },
          { type: 'file', name: 'system_profile.json' },
          { type: 'file', name: 'antiforensics_report.json' },
          { type: 'file', name: 'normalized_output.json' },
          { type: 'file', name: 'ai_preprocessed.json' },
        ],
        arrow: { label: 'State-Update' },
      },
      {
        nodes: [{
          type: 'hook', name: 'AppContext.jsx  ::  setJobs(updatedJob)', sub: 'Globaler State  →  alle Views rendern neu', file: 'frontend/src/context/AppContext.jsx',
          explain: 'Der globale Zustandsspeicher wird aktualisiert. React sorgt dafür, dass alle drei Ansichten (Overview, Analytics, Intelligence) sofort neu gezeichnet werden und die Ergebnisse anzeigen.',
        }],
        arrow: { label: 'Props an 3 Views' },
      },
      {
        nodes: [
          { type: 'frontend', name: 'OverviewPanel.jsx', sub: 'SystemProfileCard · EvidenceIntegrity · IOCList · FindingsCards', icon: '📊' },
          { type: 'frontend', name: 'AnalyticsPanel.jsx', sub: 'TimelineChart · ArtifactTaxonomy · EventTable', icon: '📈' },
          { type: 'frontend', name: 'IntelligencePanel.jsx', sub: 'AttackGraph · AnomalyList · AntiForensicsPanel', icon: '🧠' },
        ],
        arrow: null,
      },
    ],
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // FLOW 4 — LLM Multi-Agent-Analyse
  // ═══════════════════════════════════════════════════════════════════════════
  {
    id: 'llm',
    title: 'LLM Multi-Agent-Analyse',
    emoji: '🤖',
    description: 'Drei spezialisierte KI-Agenten arbeiten sequentiell via SSE-Stream',
    rows: [
      {
        nodes: [{
          type: 'frontend', name: 'IntelligencePanel.jsx', sub: '"Agenten-Analyse starten"  →  Modus: standard | attacker_infra', file: 'frontend/src/components/intelligence/IntelligencePanel.jsx',
          explain: 'Der Analyst kann manuell eine tiefergehende KI-Analyse starten. Es gibt zwei Modi: "Standard" analysiert, was dem Opfer passiert ist. "Täterinfrastruktur" analysiert, welche Werkzeuge und Server der Angreifer benutzt hat.',
        }],
        arrow: { label: 'SSE Request' },
      },
      {
        nodes: [{
          type: 'frontend', name: 'llm.js  ::  streamAgentAnalysis(job_id, mode)', sub: 'EventSource  →  Server-Sent Events Verbindung öffnen', file: 'frontend/src/api/llm.js',
          explain: 'Statt auf eine fertige Antwort zu warten, wird eine permanente Verbindung zum Server geöffnet (Server-Sent Events). So können die KI-Ergebnisse live angezeigt werden, während die Agenten noch arbeiten.',
        }],
        arrow: { label: 'GET /agent-analyze/{job_id}?mode=...' },
      },
      {
        nodes: [{
          type: 'api', name: 'api.py  ::  agent_analyze()', sub: 'StreamingResponse  →  SSE-Stream an Client', file: 'backend/api.py',
          explain: 'Der Server hält die Verbindung offen und schickt Ergebnisse in Echtzeit zurück, sobald jeder Agent fertig ist. So sieht der Analyst den Fortschritt live.',
        }],
        arrow: { label: 'run(mode)' },
      },
      {
        nodes: [{
          type: 'llm', name: 'multi_agent.py  ::  MultiAgent.run()', sub: '3 Agenten sequentiell  →  Triage → Analyst → Reporter', file: 'backend/llm_agent/multi_agent.py',
          explain: 'Drei spezialisierte KI-Agenten arbeiten nacheinander. Jeder bekommt das Ergebnis des vorherigen als Kontext – wie ein echtes DFIR-Team, bei dem der Erfahrenste zuletzt den Abschlussbericht schreibt.',
        }],
        arrow: { label: 'Agent 1: Triage' },
      },
      {
        nodes: [
          {
            type: 'llm', name: 'Agent 1 — Triage', sub: 'SOC Level 1  →  KRITISCH / VERDÄCHTIG / FALSE POSITIVE', icon: '🔍',
            explain: 'Der erste Agent übernimmt die Erstsichtung (Triage). Er bewertet jede Anomalie und klassifiziert sie als "Kritisch" (sofort handeln), "Verdächtig" (genauer prüfen) oder "Fehlalarm". Typische Aufgabe eines SOC-Level-1-Analysten.',
          },
          {
            type: 'module', name: 'prompts.py', sub: 'format_triage_prompt()  →  Prompt-Template laden', file: 'backend/llm_agent/prompts.py',
            explain: 'Jeder Agent bekommt einen speziell zugeschnittenen Prompt (Aufgabenstellung). Die Templates liegen in Dateien und werden mit den konkreten Analysedaten befüllt.',
          },
          {
            type: 'module', name: 'rag_handler.py', sub: 'retrieve_context()  →  knowledge_base/*.json', file: 'backend/llm_agent/rag_handler.py',
            explain: 'RAG (Retrieval-Augmented Generation): Bevor der Agent antwortet, werden relevante Informationen aus einer lokalen Wissensdatenbank geladen (bekannte IOCs, MITRE-Techniken, Malware-Signaturen). So "weiß" das LLM mehr als durch sein Training allein.',
          },
        ],
        arrow: { label: 'Agent 2: Analyst' },
      },
      {
        nodes: [
          {
            type: 'llm', name: 'Agent 2 — Analyst', sub: 'Senior DFIR  →  Angriffskette + MITRE ATT&CK Mapping', icon: '🕵',
            explain: 'Der zweite Agent denkt wie ein erfahrener DFIR-Analyst (Digital Forensics & Incident Response). Er korreliert die Anomalien, rekonstruiert die Angriffskette und ordnet sie MITRE ATT&CK-Techniken zu.',
          },
          {
            type: 'llm', name: 'ollama_client.py', sub: 'generate()  →  POST http://localhost:11434/api/generate', file: 'backend/llm_agent/ollama_client.py',
            explain: 'Alle drei Agenten nutzen Ollama – ein lokal laufendes LLM (Llama 3.1, 8B Parameter). Keine Daten verlassen den eigenen Server. Alles läuft offline und datenschutzkonform.',
          },
        ],
        arrow: { label: 'Agent 3: Reporter' },
      },
      {
        nodes: [{
          type: 'llm', name: 'Agent 3 — Reporter', sub: 'Forensik-Autor  →  gerichtsverwertbarer Bericht mit Executive Summary', icon: '📋',
          explain: 'Der dritte Agent ist spezialisiert auf die Berichterstellung. Er fasst alle Erkenntnisse in einem strukturierten, gerichtsverwertbaren Bericht zusammen: Executive Summary, Befunde, Empfehlungen. Das Ergebnis kann direkt als Grundlage für Ermittlungen dienen.',
        }],
        arrow: { label: 'SSE Events zurück an Client' },
      },
      {
        nodes: [{
          type: 'frontend', name: 'AgentAnalysisView.jsx', sub: 'SSE-Stream empfangen  →  Live-Darstellung der 3 Agenten-Ergebnisse', file: 'frontend/src/components/intelligence/AgentAnalysisView.jsx',
          explain: 'Die Ergebnisse aller drei Agenten werden live in der Oberfläche angezeigt – mit Markdown-Formatierung, aufklappbaren Bereichen und einem klaren Status für jeden Agenten.',
        }],
        arrow: null,
      },
    ],
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // FLOW 5 — Fall-Management & On-Demand-Funktionen
  // ═══════════════════════════════════════════════════════════════════════════
  {
    id: 'cases',
    title: 'Fall-Management & On-Demand',
    emoji: '📁',
    description: 'Cases, Threat Intelligence, Evidence Integrity, PDF-Export, Fallkorrelation',
    rows: [
      {
        nodes: [
          {
            type: 'frontend', name: 'Sidebar.jsx  /  CaseModal.jsx', sub: 'Fall anlegen · umbenennen · löschen · Drag & Drop', icon: '🗂',
            explain: 'In der Sidebar können Fälle angelegt werden. Mehrere Analysen lassen sich per Drag & Drop einem Fall zuordnen. So können z.B. alle Log-Dateien eines Vorfalls gemeinsam verwaltet werden.',
          },
          {
            type: 'frontend', name: 'UploadZone.jsx  /  MultiUploadModal.jsx', sub: 'Mehrfach-Upload  →  Fall direkt beim Upload erstellen', icon: '⬆',
            explain: 'Werden mehrere Dateien gleichzeitig hochgeladen, öffnet sich ein Dialog. Darin kann man optional direkt einen neuen Fall erstellen und alle hochgeladenen Dateien diesem Fall zuordnen.',
          },
        ],
        arrow: { label: 'async/await' },
      },
      {
        nodes: [{
          type: 'hook', name: 'useCases.js', sub: 'createCase() · updateCase() · deleteCase() · addJobToCase() · removeJobFromCase()', file: 'frontend/src/hooks/useCases.js',
          explain: 'Alle Fall-Operationen sind asynchron – das bedeutet, das Frontend wartet auf die Bestätigung des Servers, bevor es die Anzeige aktualisiert. So sind Frontend und Backend immer synchron.',
        }],
        arrow: { label: 'REST-Aufrufe' },
      },
      {
        nodes: [{
          type: 'frontend', name: 'backend.js', sub: 'createCaseOnServer() · updateCaseOnServer() · addJobToCaseOnServer() · …', file: 'frontend/src/api/backend.js',
          explain: 'Jede Fall-Operation hat eine eigene API-Funktion. Die Normalisierungsfunktion _normalizeCase() sorgt dafür, dass die Backend-Felder (name) in Frontend-Felder (case_name) übersetzt werden.',
        }],
        arrow: { label: 'HTTP' },
      },
      {
        nodes: [
          { type: 'api', name: 'POST /cases', sub: 'Fall erstellen', icon: '➕' },
          { type: 'api', name: 'PUT /cases/{id}', sub: 'Fall updaten', icon: '✏' },
          { type: 'api', name: 'DELETE /cases/{id}', sub: 'Fall löschen', icon: '🗑' },
          { type: 'api', name: 'POST /cases/{id}/jobs', sub: 'Job zuordnen', icon: '🔗' },
        ],
        arrow: { label: 'persistiert als JSON' },
      },
      {
        nodes: [{
          type: 'file', name: 'data/cases/{case_id}.json', sub: 'Backend-persistent  →  überlebt Browser-Reload & Backend-Neustart', icon: '💾',
          explain: 'Fälle werden als JSON-Dateien auf dem Server gespeichert – nicht mehr nur im Browser. Das bedeutet: Selbst wenn der Browser neu gestartet oder ein anderes Gerät verwendet wird, bleiben alle Fälle erhalten.',
        }],
        arrow: { label: 'On-Demand Features' },
      },
      {
        nodes: [
          {
            type: 'module', name: 'threat_intel.py', sub: 'POST /threat-intel/lookup  →  KB + AbuseIPDB  →  Verdict-Badges', icon: '🛡',
            explain: 'Erkannte IP-Adressen und Domains können gegen eine lokale Bedrohungsdatenbank und optional gegen AbuseIPDB (öffentliche IP-Reputationsdatenbank) geprüft werden. Das Ergebnis: farbige Badges (Malicious / Suspicious / Clean).',
          },
          {
            type: 'module', name: 'evidence_tracker.py', sub: 'POST /verify/{job_id}  →  MD5+SHA256 Verifikation  →  Audit-Trail', icon: '🔒',
            explain: 'Die Beweissicherung kann jederzeit verifiziert werden: Das System berechnet die Hashes der gespeicherten Datei neu und vergleicht sie mit den ursprünglichen Werten. Ein vollständiger Audit-Trail dokumentiert alle Schritte.',
          },
          {
            type: 'module', name: 'pdf_generator.py', sub: 'POST /export-pdf/{job_id}  →  Forensischer PDF-Report', icon: '📑',
            explain: 'Aus den Analyseergebnissen wird ein professioneller PDF-Report erstellt: mit Deckblatt, Executive Summary, Anomalie-Tabelle, MITRE ATT&CK-Mapping, IOC-Liste und den MD5/SHA256-Hashes für die Aktenablage.',
          },
          {
            type: 'llm', name: 'case_correlator.py', sub: 'POST /case-correlate  →  IOC-Matching + LLM  →  SSE-Stream', icon: '🔍',
            explain: 'Bei Fällen mit mehreren Quellen sucht der Korrelationsagent nach gemeinsamen IOCs (gleiche IPs, Benutzer, Hostnamen über mehrere Dateien) und lässt dann das LLM eine quellenübergreifende Analyse erstellen.',
          },
        ],
        arrow: null,
      },
    ],
  },
]
