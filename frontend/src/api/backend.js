/**
 * ============================================================================
 * BACKEND API CLIENT — REST-Schnittstelle zum FastAPI-Backend
 * ============================================================================
 * Kapselt alle HTTP-Aufrufe zum Python-Backend (FastAPI, Port 8000).
 * Im Dev-Modus laufen alle Requests über den Vite-Proxy (/api → localhost:8000),
 * in Produktion wird VITE_BACKEND_URL direkt verwendet.
 *
 * Exportierte Funktionen:
 *   Kern-API:
 *   - apiFetch()                 → Zentraler HTTP-Wrapper mit Fehlerbehandlung
 *   - uploadFile()               → Forensische Datei hochladen, Analyse-Job starten
 *   - pollStatus()               → Analyse-Fortschritt abfragen (0–100 %)
 *   - fetchResults()             → Ergebnis-Dateiliste nach Job-Abschluss laden
 *   - downloadFile()             → Einzelne Ergebnisdatei als Response-Objekt
 *   - fetchFileAsText()          → Ergebnisdatei als Rohtext laden (z. B. report.md)
 *   - fetchFileAsJson()          → Ergebnisdatei als geparsten JSON-Wert laden
 *
 *   PDF-Export:
 *   - exportCasePdf()            → Gesamt-Case-PDF mit Korrelationsdaten exportieren
 *   - exportPdf()                → Einzel-Job-PDF-Report exportieren
 *   - exportFullPdf()            → Vollständigen Report mit Multi-Agent-Analyse exportieren
 *
 *   Threat Intelligence & Verifikation:
 *   - lookupThreatIntel()        → Indikatoren gegen Threat-Intel-Datenbank prüfen
 *   - verifyEvidence()           → Beweismittel-Integrität eines Jobs verifizieren
 *
 *   Case Management (Backend-persistent, FA-20):
 *   - fetchCasesFromServer()     → Alle Cases vom Backend laden
 *   - createCaseOnServer()       → Neuen Case anlegen
 *   - updateCaseOnServer()       → Case-Metadaten aktualisieren
 *   - deleteCaseOnServer()       → Case löschen
 *   - addJobToCaseOnServer()     → Job einem Case zuordnen
 *   - removeJobFromCaseOnServer()→ Job aus einem Case entfernen
 *
 *   System-Analyse:
 *   - fetchSystemProfile()       → OS/Kernel/Benutzer-Profil eines Jobs laden (FA-22)
 *   - fetchAntiForensics()       → Anti-Forensics-Befunde eines Jobs laden (FA-23)
 *
 * Abhängigkeiten:
 *   Kein externes Package — nur nativer fetch() Browser-API
 *
 * @module api/backend
 */

// ── Basis-URL-Konfiguration ───────────────────────────────────────────────────

/**
 * Ermittelt die Basis-URL für alle Backend-Anfragen.
 *
 * Logik:
 *   1. Ist VITE_BACKEND_URL eine vollständige URL (beginnt mit "http"), wird sie direkt genutzt.
 *   2. Ist VITE_BACKEND_URL ein relativer Pfad (z. B. "/api"), wird er als Proxy-Pfad verwendet.
 *   3. Ohne Konfiguration wird "/api" als Standard-Vite-Proxy-Pfad zurückgegeben.
 *
 * @returns {string} Basis-URL, z. B. "/api" oder "http://localhost:8000"
 */
function getBaseUrl() {
  const envUrl = import.meta.env.VITE_BACKEND_URL
  // Wenn eine volle URL gesetzt ist (http://...), verwende sie direkt
  if (envUrl && envUrl.startsWith('http')) return envUrl
  // Sonst: Nutze den Vite-Proxy-Pfad (default: /api)
  return envUrl || '/api'
}

const BASE_URL = getBaseUrl()

// ── Zentraler HTTP-Wrapper ────────────────────────────────────────────────────

/**
 * Zentraler HTTP-Wrapper für alle Backend-Anfragen.
 *
 * Fügt automatisch die Basis-URL hinzu, prüft den HTTP-Statuscode und
 * gibt bei Fehlern eine aussagekräftige Fehlermeldung aus.
 * Netzwerkfehler (Backend nicht erreichbar) werden gesondert behandelt.
 *
 * @param {string} path - API-Pfad relativ zur Basis-URL, z. B. "/analyze"
 * @param {RequestInit} [options={}] - Optionale fetch()-Optionen (method, headers, body, …)
 * @returns {Promise<Response>} Das rohe Response-Objekt (noch nicht geparst)
 * @throws {Error} Bei HTTP-Fehler (4xx/5xx) oder Netzwerkproblem
 */
export async function apiFetch(path, options = {}) {
  const url = `${BASE_URL}${path}`

  try {
    const res = await fetch(url, options)

    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }))
      throw new Error(err.detail || `HTTP ${res.status}: ${res.statusText}`)
    }

    return res
  } catch (err) {
    // Netzwerk-Fehler mit hilfreicher Meldung
    if (err.message === 'Failed to fetch') {
      throw new Error(
        `Backend nicht erreichbar (${url}). ` +
        'Stelle sicher, dass das Backend auf Port 8000 läuft: ' +
        'cd backend && uvicorn api:app --host 127.0.0.1 --port 8000'
      )
    }
    throw err
  }
}

// ── Analyse-Pipeline ──────────────────────────────────────────────────────────

/**
 * Lädt eine forensische Datei hoch und startet die 8-stufige Analyse-Pipeline.
 *
 * Die Datei wird als multipart/form-data übertragen. Das Backend gibt sofort
 * eine Job-ID zurück (HTTP 202 Accepted), bevor die Analyse abgeschlossen ist.
 *
 * @param {File} file - Die hochzuladende Datei (Disk-Image .dd/.E01, Logs, UAC-Dump, RAM-Dump)
 * @returns {Promise<{job_id: string, filename: string, input_type: string, created_at: string, file_hash: string|null, sha256_hash: string|null, md5_hash: string|null}>} Job-Metadaten
 * @throws {Error} Bei HTTP-Fehler oder Netzwerkproblem
 */
export async function uploadFile(file) {
  const formData = new FormData()
  formData.append('file', file)

  const res = await apiFetch('/analyze', {
    method: 'POST',
    body: formData,
  })

  return res.json()
}

/**
 * Fragt den aktuellen Status eines laufenden Analyse-Jobs ab.
 *
 * Wird vom Polling-Mechanismus in useJobs alle 2 Sekunden aufgerufen,
 * bis der Job den Status "completed" oder "failed" erreicht.
 *
 * @param {string} jobId - Die Job-ID (aus uploadFile() erhalten)
 * @returns {Promise<{status: string, progress: number, message?: string}>} Aktueller Job-Status
 * @throws {Error} Bei HTTP-Fehler
 */
export async function pollStatus(jobId) {
  const res = await apiFetch(`/status/${jobId}`)
  return res.json()
}

/**
 * Lädt die Liste der generierten Ausgabedateien eines abgeschlossenen Jobs.
 *
 * Wird aufgerufen, sobald pollStatus() "completed" zurückgibt.
 * Die Dateinamen dienen als Grundlage für fetchFileAsText/Json.
 *
 * @param {string} jobId - Die Job-ID
 * @returns {Promise<{output_files: string[]}>} Liste der verfügbaren Dateinamen
 * @throws {Error} Bei HTTP-Fehler
 */
export async function fetchResults(jobId) {
  const res = await apiFetch(`/results/${jobId}`)
  return res.json()
}

// ── Datei-Download ────────────────────────────────────────────────────────────

/**
 * Lädt eine einzelne Ausgabedatei eines Jobs herunter.
 *
 * Gibt das rohe Response-Objekt zurück; für geparste Inhalte
 * fetchFileAsText() oder fetchFileAsJson() verwenden.
 *
 * @param {string} jobId - Die Job-ID
 * @param {string} filename - Dateiname, z. B. "report.md" oder "anomalies_detected.json"
 * @returns {Promise<Response>} Rohes Response-Objekt
 * @throws {Error} Bei HTTP-Fehler
 */
export async function downloadFile(jobId, filename) {
  return apiFetch(`/download/${jobId}/${filename}`)
}

/**
 * Lädt eine Ausgabedatei und gibt ihren Inhalt als Rohtext zurück.
 *
 * Typisch für Markdown-Reports (report.md).
 *
 * @param {string} jobId - Die Job-ID
 * @param {string} filename - Dateiname
 * @returns {Promise<string>} Dateiinhalt als UTF-8-String
 * @throws {Error} Bei HTTP-Fehler
 */
export async function fetchFileAsText(jobId, filename) {
  const res = await downloadFile(jobId, filename)
  return res.text()
}

/**
 * Lädt eine Ausgabedatei und parst sie als JSON.
 *
 * Typisch für strukturierte Analyse-Ergebnisse
 * (analysis_summary.json, anomalies_detected.json, etc.).
 *
 * @param {string} jobId - Die Job-ID
 * @param {string} filename - Dateiname
 * @returns {Promise<object>} Geparster JSON-Inhalt
 * @throws {Error} Bei HTTP-Fehler oder ungültigem JSON
 */
export async function fetchFileAsJson(jobId, filename) {
  const res = await downloadFile(jobId, filename)
  return res.json()
}

// ── PDF-Export ────────────────────────────────────────────────────────────────

/**
 * Generiert einen Case-übergreifenden PDF-Report und löst den Browser-Download aus.
 *
 * Sendet alle Job-IDs des Cases sowie optionale Korrelationsdaten an das Backend,
 * das einen konsolidierten PDF-Report mit forensischer Zusammenfassung erstellt.
 * Der Download wird programmatisch über einen temporären <a>-Link ausgelöst.
 *
 * @param {string[]} jobIds - Liste der Job-IDs, die in den Report einfließen
 * @param {object} [caseInfo={}] - Case-Metadaten für den Berichtsheader
 * @param {string} [caseInfo.case_name] - Name des Falls
 * @param {string} [caseInfo.case_number] - Aktenzeichen
 * @param {string} [caseInfo.analyst] - Name des Analysten
 * @param {object} [correlationData={}] - Ergebnisse der Multi-Job-Korrelationsanalyse
 * @param {string} [correlationData.correlation_report] - Korrelationsbericht als Text
 * @param {object} [correlationData.shared_iocs] - Gemeinsame Indicators of Compromise
 * @param {object} [correlationData.metadata] - Zusätzliche Metadaten
 * @returns {Promise<void>}
 * @throws {Error} Bei HTTP-Fehler
 */
export async function exportCasePdf(jobIds, caseInfo = {}, correlationData = {}) {
  const res = await apiFetch('/export-case-pdf', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      job_ids: jobIds,
      case_name: caseInfo.case_name || '',
      case_number: caseInfo.case_number || '',
      analyst: caseInfo.analyst || '',
      correlation_report: correlationData.correlation_report || '',
      shared_iocs: correlationData.shared_iocs || {},
      metadata: correlationData.metadata || {},
    }),
  })

  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  const safeName = (caseInfo.case_name || 'case').replace(/[^a-zA-Z0-9_-]/g, '_')
  a.download = `case_report_${safeName}.pdf`
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

/**
 * Generiert einen einfachen PDF-Report für einen einzelnen Job und löst den Download aus.
 *
 * @param {string} jobId - Die Job-ID
 * @param {object} [caseInfo={}] - Optionale Case-Metadaten für den Berichtsheader
 * @returns {Promise<void>}
 * @throws {Error} Bei HTTP-Fehler
 */
export async function exportPdf(jobId, caseInfo = {}) {
  const res = await apiFetch(`/export-pdf/${jobId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(caseInfo),
  })

  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `forensic_report_${jobId}.pdf`
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

/**
 * Generiert einen vollständigen PDF-Report inklusive Multi-Agent-LLM-Analyse und löst den Download aus.
 *
 * Im Unterschied zu exportPdf() führt das Backend zusätzlich eine
 * mehrstufige KI-Analyse (Triage → Analyst → Reporter) durch,
 * bevor das PDF erzeugt wird. Kann dadurch deutlich länger dauern.
 *
 * @param {string} jobId - Die Job-ID
 * @param {object} [caseInfo={}] - Optionale Case-Metadaten für den Berichtsheader
 * @returns {Promise<void>}
 * @throws {Error} Bei HTTP-Fehler
 */
export async function exportFullPdf(jobId, caseInfo = {}) {
  const res = await apiFetch(`/export-full-pdf/${jobId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(caseInfo),
  })

  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `forensic_full_report_${jobId}.pdf`
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

// ── Threat Intelligence & Verifikation ───────────────────────────────────────

/**
 * Prüft eine Liste von Indikatoren (IPs, Domains, Hashes) gegen die Backend-Threat-Intel-Datenbank.
 *
 * @param {string[]} indicators - Liste der zu prüfenden Indikatoren (z. B. ["192.168.1.1", "evil.com"])
 * @returns {Promise<object>} Threat-Intel-Ergebnisse pro Indikator
 * @throws {Error} Bei HTTP-Fehler
 */
export async function lookupThreatIntel(indicators) {
  const res = await apiFetch('/threat-intel/lookup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ indicators }),
  })
  return res.json()
}

/**
 * Verifiziert die kryptografische Integrität der Beweismittel eines Jobs.
 *
 * Das Backend berechnet Hashwerte der Eingabedatei neu und vergleicht sie
 * mit den beim Upload gespeicherten Werten, um Manipulationen auszuschließen.
 *
 * @param {string} jobId - Die Job-ID
 * @returns {Promise<{verified: boolean, hashes: object, details: string}>} Verifikationsergebnis
 * @throws {Error} Bei HTTP-Fehler
 */
export async function verifyEvidence(jobId) {
  const res = await apiFetch(`/verify/${jobId}`, { method: 'POST' })
  return res.json()
}

// ── Case Management (Backend-persistent) ─────────────────────────────────────

/**
 * Normalisiert ein Backend-Case-Objekt auf die Frontend-Konvention.
 *
 * Das Backend kann "name" oder "case_name" liefern; diese Funktion
 * stellt sicher, dass immer "case_name" vorhanden ist.
 *
 * @param {object} c - Rohes Case-Objekt vom Backend
 * @returns {object} Normalisiertes Case-Objekt mit garantiertem "case_name"-Feld
 * @private
 */
function _normalizeCase(c) {
  return { ...c, case_name: c.case_name || c.name || '' }
}

/**
 * Lädt alle Cases vom Backend (FA-20).
 *
 * Wird beim App-Start im AppContext.useEffect aufgerufen,
 * um den lokalen State mit dem persistenten Backend-State zu synchronisieren.
 *
 * @returns {Promise<object[]>} Liste aller normalisierten Case-Objekte
 * @throws {Error} Bei HTTP-Fehler
 */
export async function fetchCasesFromServer() {
  const res = await apiFetch('/cases')
  const data = await res.json()
  return (data.cases || []).map(_normalizeCase)
}

/**
 * Legt einen neuen Case auf dem Backend an.
 *
 * @param {object} caseData - Case-Daten
 * @param {string} caseData.case_name - Name des Falls
 * @param {string} [caseData.case_number] - Aktenzeichen
 * @param {string} [caseData.description] - Beschreibung des Falls
 * @param {string} [caseData.analyst] - Zuständiger Analyst
 * @returns {Promise<object>} Das neu erstellte, normalisierte Case-Objekt (inkl. case_id)
 * @throws {Error} Bei HTTP-Fehler
 */
export async function createCaseOnServer(caseData) {
  const res = await apiFetch('/cases', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      name:        caseData.case_name || caseData.name || '',
      case_number: caseData.case_number || '',
      description: caseData.description || '',
      analyst:     caseData.analyst || '',
    }),
  })
  const data = await res.json()
  return _normalizeCase(data)
}

/**
 * Aktualisiert die Metadaten eines bestehenden Cases.
 *
 * @param {string} caseId - Die ID des zu aktualisierenden Cases
 * @param {object} updates - Zu aktualisierende Felder (Teilmenge der Case-Daten)
 * @param {string} [updates.case_name] - Neuer Name des Falls
 * @param {string} [updates.case_number] - Neues Aktenzeichen
 * @param {string} [updates.description] - Neue Beschreibung
 * @param {string} [updates.analyst] - Neuer Analyst
 * @returns {Promise<object>} Das aktualisierte, normalisierte Case-Objekt
 * @throws {Error} Bei HTTP-Fehler
 */
export async function updateCaseOnServer(caseId, updates) {
  const res = await apiFetch(`/cases/${caseId}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      name:        updates.case_name || updates.name,
      case_number: updates.case_number,
      description: updates.description,
      analyst:     updates.analyst,
    }),
  })
  const data = await res.json()
  return _normalizeCase(data)
}

/**
 * Löscht einen Case auf dem Backend (inkl. aller Zuordnungen zu Jobs).
 *
 * Die Jobs selbst werden dabei nicht gelöscht, nur die Case-Zuordnung.
 *
 * @param {string} caseId - Die ID des zu löschenden Cases
 * @returns {Promise<void>}
 * @throws {Error} Bei HTTP-Fehler
 */
export async function deleteCaseOnServer(caseId) {
  await apiFetch(`/cases/${caseId}`, { method: 'DELETE' })
}

/**
 * Ordnet einen bestehenden Analyse-Job einem Case zu.
 *
 * @param {string} caseId - Die ID des Ziel-Cases
 * @param {string} jobId - Die ID des hinzuzufügenden Jobs
 * @returns {Promise<object>} Das aktualisierte, normalisierte Case-Objekt
 * @throws {Error} Bei HTTP-Fehler
 */
export async function addJobToCaseOnServer(caseId, jobId) {
  const res = await apiFetch(`/cases/${caseId}/jobs/${jobId}`, { method: 'POST' })
  const data = await res.json()
  return _normalizeCase(data)
}

/**
 * Entfernt die Zuordnung eines Jobs aus einem Case.
 *
 * @param {string} caseId - Die ID des Cases
 * @param {string} jobId - Die ID des zu entfernenden Jobs
 * @returns {Promise<object>} Das aktualisierte, normalisierte Case-Objekt
 * @throws {Error} Bei HTTP-Fehler
 */
export async function removeJobFromCaseOnServer(caseId, jobId) {
  const res = await apiFetch(`/cases/${caseId}/jobs/${jobId}`, { method: 'DELETE' })
  const data = await res.json()
  return _normalizeCase(data)
}

// ── System-Profil ─────────────────────────────────────────────────────────────

/**
 * Lädt das System-Profil eines analysierten Beweismittels (FA-22).
 *
 * Enthält Informationen wie Betriebssystem, Kernel-Version, Hostname,
 * lokale Benutzerkonten und laufende Dienste zum Analysezeitpunkt.
 *
 * @param {string} jobId - Die Job-ID
 * @returns {Promise<object>} System-Profil-Objekt (leer wenn nicht vorhanden)
 * @throws {Error} Bei HTTP-Fehler
 */
export async function fetchSystemProfile(jobId) {
  const res = await apiFetch(`/system-profile/${jobId}`)
  const data = await res.json()
  return data.system_profile || {}
}

// ── Anti-Forensics ────────────────────────────────────────────────────────────

/**
 * Lädt die Anti-Forensics-Analyse-Ergebnisse eines Jobs (FA-23).
 *
 * Erkennt Spuren von Verschleierungsmaßnahmen wie Timestomping,
 * Log-Lücken, Wipe-Tools oder verschlüsselte Dateisysteme.
 *
 * @param {string} jobId - Die Job-ID
 * @returns {Promise<object>} Anti-Forensics-Befunde (leer wenn nicht vorhanden)
 * @throws {Error} Bei HTTP-Fehler
 */
export async function fetchAntiForensics(jobId) {
  const res = await apiFetch(`/antiforensics/${jobId}`)
  const data = await res.json()
  return data.antiforensics || {}
}
