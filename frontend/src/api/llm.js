/**
 * ============================================================================
 * LLM API CLIENT — Lokale KI-Analyse via Backend (Ollama/Llama 3.1)
 * ============================================================================
 * Kapselt alle Anfragen an die KI-Analyse-Endpunkte des Backends.
 * Läuft vollständig offline über das lokale Ollama-Modell (kein API-Key,
 * kein Quota, keine Cloud-Abhängigkeit).
 *
 * Zwei Kommunikations-Modi:
 *   1. Request/Response  → Einfache Analyse, wartet auf vollständige Antwort
 *   2. Server-Sent Events (SSE) → Streaming für lange Multi-Agenten-Analysen;
 *      Zwischenergebnisse werden per Callback in Echtzeit geliefert
 *
 * Exportierte Funktionen:
 *   - analyzeAnomaliesLocal()  → Schnelle Anomalie-Einschätzung (mode: "quick")
 *   - generateLocalReport()    → Vollständiger KI-Report (mode: "full")
 *   - runAgentAnalysis()       → Multi-Agent-Streaming: Triage → Analyst → Reporter
 *   - runCaseCorrelation()     → Case-übergreifende Korrelations-Analyse via SSE
 *
 * Abhängigkeiten:
 *   - api/backend.js  → apiFetch() für Request/Response-Aufrufe
 *   - Nativer fetch() → für SSE-Streaming (ReadableStream)
 *
 * @module api/llm
 */

import { apiFetch } from './backend'

// ── SSE-Hilfsfunktion ─────────────────────────────────────────────────────────

/**
 * Verarbeitet einen ReadableStream als Server-Sent Events (SSE).
 *
 * Liest den Byte-Stream stückweise, dekodiert ihn als UTF-8, puffert
 * unvollständige Events und parst jedes vollständige "data: {...}\n\n"-Segment
 * als JSON. Für jedes erfolgreich geparste Event wird der onEvent-Callback
 * aufgerufen. Parse-Fehler werden als Warnung geloggt und übersprungen.
 *
 * @param {ReadableStream} stream - Der Response-Body des SSE-Endpunkts
 * @param {function(object): void} onEvent - Callback für jedes empfangene SSE-Event
 * @returns {Promise<void>} Resolved wenn der Stream vollständig gelesen wurde
 * @private
 */
async function _consumeSseStream(stream, onEvent) {
  const reader = stream.getReader()
  const decoder = new TextDecoder()
  let buffer = ''

  while (true) {
    const { done, value } = await reader.read()
    if (done) break

    buffer += decoder.decode(value, { stream: true })

    // Parse SSE: jedes Event ist "data: {...}\n\n"
    const parts = buffer.split('\n\n')
    buffer = parts.pop() || ''

    for (const part of parts) {
      const trimmed = part.trim()
      if (!trimmed || !trimmed.startsWith('data: ')) continue
      try {
        const data = JSON.parse(trimmed.slice(6))
        onEvent(data)
      } catch (e) {
        console.warn('SSE parse error:', e, trimmed)
      }
    }
  }

  // Restlichen Buffer verarbeiten — tritt auf wenn der Stream ohne abschließendes \n\n endet
  if (buffer.trim() && buffer.trim().startsWith('data: ')) {
    try {
      const data = JSON.parse(buffer.trim().slice(6))
      onEvent(data)
    } catch (e) {
      // ignorieren
    }
  }
}

// ── Request/Response-Analyse ──────────────────────────────────────────────────

/**
 * Führt eine schnelle KI-Einschätzung der erkannten Anomalien durch.
 *
 * Sendet die Anomalie-Liste an den Backend-Endpunkt /llm-analyze im
 * Modus "quick". Das Modell liefert eine kompakte Priorisierung und
 * erste Einschätzung der kritischsten Befunde.
 *
 * @param {object[]} anomalies - Liste der erkannten Anomalie-Objekte aus anomalies_detected.json
 * @returns {Promise<string>} KI-generierter Analysetext
 * @throws {Error} Bei HTTP-Fehler oder Backend-Timeout
 */
export async function analyzeAnomaliesLocal(anomalies) {
  const res = await apiFetch('/llm-analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      anomalies: anomalies || [],
      mode: 'quick'
    })
  })
  const data = await res.json()
  return data.result
}

/**
 * Generiert einen vollständigen KI-Forensikbericht auf Basis aller verfügbaren Daten.
 *
 * Sendet Anomalien, extrahierte Indikatoren und die Pipeline-Zusammenfassung
 * an /llm-analyze im Modus "full". Das Modell erstellt einen strukturierten
 * Bericht mit Hypothesen, MITRE-ATT&CK-Mapping und Handlungsempfehlungen.
 *
 * @param {object} params - Eingabedaten für den Report
 * @param {object[]} params.anomalies - Erkannte Anomalien
 * @param {object|null} [params.indicators] - Extrahierte Indikatoren (IPs, Domains, Hashes)
 * @param {object|null} [params.summary] - Pipeline-Zusammenfassung aus analysis_summary.json
 * @returns {Promise<string>} KI-generierter Vollbericht als Text
 * @throws {Error} Bei HTTP-Fehler oder Backend-Timeout
 */
export async function generateLocalReport({ anomalies, indicators, summary }) {
  const res = await apiFetch('/llm-analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      anomalies: anomalies || [],
      indicators: indicators || null,
      summary: summary || null,
      mode: 'full'
    })
  })
  const data = await res.json()
  return data.result
}

// ── SSE-Streaming-Analyse ─────────────────────────────────────────────────────

/**
 * Führt eine mehrstufige Multi-Agent-Analyse eines Jobs via SSE durch.
 *
 * Das Backend startet drei spezialisierte LLM-Agenten sequenziell:
 *   1. Triage-Agent    → Erste Einschätzung und Priorisierung
 *   2. Analyst-Agent   → Tiefenanalyse mit MITRE-ATT&CK-Mapping
 *   3. Reporter-Agent  → Formuliert den finalen Forensikbericht
 *
 * Jede Agenten-Ausgabe wird als separates SSE-Event gestreamt, sodass die
 * UI Fortschritt und Zwischenergebnisse in Echtzeit anzeigen kann.
 *
 * SSE-Event-Struktur (Beispiel):
 *   { agent: "analyst", status: "running", content: "..." }
 *   { agent: "reporter", status: "done", result: "..." }
 *
 * @param {string} jobId - Die Job-ID des zu analysierenden Jobs
 * @param {function(object): void} onEvent - Callback für jedes SSE-Event
 * @returns {Promise<void>} Resolved wenn alle Agenten abgeschlossen sind
 * @throws {Error} Bei HTTP-Fehler oder Verbindungsabbruch
 */
export async function runAgentAnalysis(jobId, onEvent) {
  const baseUrl = import.meta.env.VITE_BACKEND_URL || '/api'
  const url = `${baseUrl}/agent-analyze/${jobId}`

  const response = await fetch(url)

  if (!response.ok) {
    const err = await response.json().catch(() => ({ detail: response.statusText }))
    throw new Error(err.detail || `HTTP ${response.status}`)
  }

  await _consumeSseStream(response.body, onEvent)
}

/**
 * Analysiert Case-übergreifende Muster über mehrere Jobs via SSE (FA-20 Korrelation).
 *
 * Das Backend lädt alle angegebenen Jobs und sucht nach gemeinsamen Indikatoren
 * (geteilte IPs, Domains, Malware-Signaturen), zeitlichen Überschneidungen und
 * kampagnentypischen Mustern. Die Ergebnisse werden als SSE-Stream geliefert.
 *
 * SSE-Event-Struktur (Beispiel):
 *   { type: "progress", message: "Lade Job-Daten..." }
 *   { type: "result", shared_iocs: {...}, correlation_report: "..." }
 *   { type: "done" }
 *
 * @param {string[]} jobIds - Liste der Job-IDs, deren Daten korreliert werden sollen
 * @param {object} caseMeta - Metadaten des Cases für den Bericht
 * @param {string} [caseMeta.case_name] - Name des Falls
 * @param {string} [caseMeta.case_number] - Aktenzeichen
 * @param {string} [caseMeta.analyst] - Zuständiger Analyst
 * @param {function(object): void} onEvent - Callback für jedes SSE-Event
 * @returns {Promise<void>} Resolved wenn die Korrelationsanalyse abgeschlossen ist
 * @throws {Error} Bei HTTP-Fehler oder Verbindungsabbruch
 */
export async function runCaseCorrelation(jobIds, caseMeta, onEvent) {
  const baseUrl = import.meta.env.VITE_BACKEND_URL || '/api'
  const url = `${baseUrl}/case-correlate`

  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      job_ids: jobIds,
      case_name: caseMeta?.case_name || '',
      case_number: caseMeta?.case_number || '',
      analyst: caseMeta?.analyst || '',
    }),
  })

  if (!response.ok) {
    const err = await response.json().catch(() => ({ detail: response.statusText }))
    throw new Error(err.detail || `HTTP ${response.status}`)
  }

  await _consumeSseStream(response.body, onEvent)
}
