/**
 * ============================================================================
 * useJobs — Job-Lebenszyklus-Hook (Upload → Polling → Ergebnisse)
 * ============================================================================
 * Verwaltet den vollständigen Analyse-Job-Lebenszyklus:
 *   1. Datei-Upload an das Backend (startet die 8-stufige Pipeline)
 *   2. Automatisches Status-Polling alle 2 Sekunden bis zur Fertigstellung
 *   3. Laden aller Ergebnisdateien nach erfolgreichem Abschluss
 *
 * Dieser Hook wird ausschließlich vom AppContext instanziiert und
 * teilt dessen jobs/setJobs-State. Er ist kein eigenständiger Kontext.
 *
 * Polling-Strategie:
 *   - Intervall: 2000 ms
 *   - Fehlertoleranz: bis zu 5 aufeinanderfolgende Fehler, dann Abbruch mit status="failed"
 *   - Mehrfach-Polling wird verhindert (pollIntervals.current als Guard)
 *
 * Geladene Ergebnisdateien (sofern vorhanden):
 *   report.md, analysis_summary.json, anomalies_detected.json,
 *   preprocessed_for_llm.json, normalized_output.json, interpretation.json,
 *   system_profile.json (FA-22), antiforensics_report.json (FA-23)
 *
 * Exportierte Actions:
 *   - submitFile(file)         → Datei hochladen, Job anlegen, Polling starten
 *   - startPolling(jobId)      → Polling manuell starten (z. B. nach App-Neustart)
 *   - retryLoadResults(jobId)  → Ergebnisse erneut laden (bei Ladefehler)
 *
 * @module hooks/useJobs
 */

import { useCallback, useRef } from 'react'
import { uploadFile, pollStatus, fetchResults, fetchFileAsText, fetchFileAsJson } from '../api/backend'

// ── Hook-Definition ───────────────────────────────────────────────────────────

/**
 * Verwaltet den vollständigen Job-Lebenszyklus: Upload → Polling → Ergebnisse.
 *
 * Wird im AppContext instanziiert; jobs/setJobs/setActiveJobId kommen
 * von dort und werden per Parameter übergeben, damit dieser Hook
 * denselben State-Slot wie der localStorage-persistierte AppContext nutzt.
 *
 * @param {object[]} jobs - Aktuelle Job-Liste aus dem AppContext-State
 * @param {function} setJobs - State-Setter für die Job-Liste
 * @param {function} setActiveJobId - State-Setter für den aktiven Job
 * @returns {{ submitFile: function, startPolling: function, retryLoadResults: function }}
 */
export function useJobs(jobs, setJobs, setActiveJobId) {
  // Speichert aktive setInterval-IDs, um Mehrfach-Polling zu verhindern.
  // useRef statt useState, da Änderungen keinen Re-Render auslösen sollen.
  const pollIntervals = useRef({})

  // ── Interne Hilfsfunktion ─────────────────────────────────────────────────

  /**
   * Aktualisiert einzelne Felder eines bestehenden Jobs in der State-Liste.
   *
   * Alle anderen Jobs bleiben unverändert (immutable Update via map).
   *
   * @param {string} jobId - ID des zu aktualisierenden Jobs
   * @param {object} updates - Zu aktualisierende Felder (Teilmenge des Job-Objekts)
   */
  const updateJob = useCallback((jobId, updates) => {
    setJobs(prev => prev.map(j => j.job_id === jobId ? { ...j, ...updates } : j))
  }, [setJobs])

  // ── Polling ───────────────────────────────────────────────────────────────

  /**
   * Startet das regelmäßige Status-Polling für einen Job (alle 2 Sekunden).
   *
   * Sicherheitsmechanismen:
   *   - Guard: Ist bereits ein Intervall für diese jobId aktiv, wird kein zweites gestartet.
   *   - Fehlertoleranz: Nach 5 aufeinanderfolgenden Fehlern wird das Polling gestoppt
   *     und der Job auf status="failed" gesetzt (Backend nicht erreichbar).
   *   - Cleanup: Bei "completed" oder "failed" wird das Intervall automatisch gelöscht.
   *
   * @param {string} jobId - Die zu pollende Job-ID
   */
  const startPolling = useCallback((jobId) => {
    if (pollIntervals.current[jobId]) return

    let failCount = 0
    pollIntervals.current[jobId] = setInterval(async () => {
      try {
        const status = await pollStatus(jobId)
        failCount = 0 // Reset bei Erfolg
        updateJob(jobId, {
          status: status.status,
          progress: status.progress,
        })

        if (status.status === 'completed' || status.status === 'failed') {
          clearInterval(pollIntervals.current[jobId])
          delete pollIntervals.current[jobId]

          if (status.status === 'completed') {
            await loadJobResults(jobId)
          }
        }
      } catch (err) {
        failCount++
        console.warn(`Polling fehlgeschlagen für ${jobId} (${failCount}x): ${err.message}`)
        // Nach 5 Fehlversuchen aufhören (Backend vermutlich nicht erreichbar oder Job nicht vorhanden)
        if (failCount >= 5) {
          clearInterval(pollIntervals.current[jobId])
          delete pollIntervals.current[jobId]
          updateJob(jobId, { status: 'failed', error: 'Backend nicht erreichbar' })
        }
      }
    }, 2000)
  }, [updateJob])

  // ── Ergebnisse laden ──────────────────────────────────────────────────────

  /**
   * Lädt alle verfügbaren Ergebnisdateien eines abgeschlossenen Jobs.
   *
   * Ablauf:
   *   1. Dateiliste vom Backend holen (fetchResults)
   *   2. Nur tatsächlich vorhandene Dateien laden (filter auf outputFiles)
   *   3. Alle Dateien parallel laden (Promise.all) für minimale Wartezeit
   *   4. Ergebnisse im Job-State unter job.data ablegen
   *
   * Geladene Dateien und ihre State-Keys:
   *   report.md               → data.report         (Rohtext)
   *   analysis_summary.json   → data.summary         (JSON)
   *   anomalies_detected.json → data.anomalies        (JSON)
   *   preprocessed_for_llm.json → data.preprocessed  (JSON)
   *   normalized_output.json  → data.normalized       (JSON)
   *   interpretation.json     → data.interpretation   (JSON)
   *   system_profile.json     → data.systemProfile    (JSON, FA-22)
   *   antiforensics_report.json → data.antiforensics  (JSON, FA-23)
   *
   * @param {string} jobId - Die Job-ID, deren Ergebnisse geladen werden sollen
   * @returns {Promise<void>}
   */
  const loadJobResults = useCallback(async (jobId) => {
    try {
      const results = await fetchResults(jobId)

      const data = { outputFiles: results.output_files || [] }

      // Load each result file
      const fileLoaders = [
        { name: 'report.md',                  key: 'report',         loader: fetchFileAsText },
        { name: 'analysis_summary.json',       key: 'summary',        loader: fetchFileAsJson },
        { name: 'anomalies_detected.json',     key: 'anomalies',      loader: fetchFileAsJson },
        { name: 'preprocessed_for_llm.json',   key: 'preprocessed',   loader: fetchFileAsJson },
        { name: 'normalized_output.json',      key: 'normalized',     loader: fetchFileAsJson },
        { name: 'interpretation.json',         key: 'interpretation', loader: fetchFileAsJson },
        // FA-22: System-Profil (OS, Kernel, Hostname, Benutzer, Dienste)
        { name: 'system_profile.json',         key: 'systemProfile',  loader: fetchFileAsJson },
        // FA-23: Anti-Forensics-Report (Timestomping, Log-Lücken, Wipe-Tools, ...)
        { name: 'antiforensics_report.json',   key: 'antiforensics',  loader: fetchFileAsJson },
      ]

      await Promise.all(
        fileLoaders
          .filter(f => data.outputFiles.includes(f.name))
          .map(async ({ name, key, loader }) => {
            try {
              data[key] = await loader(jobId, name)
            } catch {
              // File not available
            }
          })
      )

      updateJob(jobId, { data, status: 'completed', progress: 100 })
    } catch (err) {
      console.error('Failed to load results:', err)
    }
  }, [updateJob])

  // ── Upload ────────────────────────────────────────────────────────────────

  /**
   * Lädt eine forensische Datei hoch, legt einen Job-Eintrag im State an
   * und startet sofort das Status-Polling.
   *
   * Der neue Job wird an den Anfang der Liste gesetzt (neueste zuerst)
   * und als aktiver Job markiert.
   *
   * @param {File} file - Die hochzuladende Datei
   * @returns {Promise<object>} Das neu erstellte Job-Objekt
   * @throws {Error} Bei Upload-Fehler (wird an den Aufrufer weitergereicht)
   */
  const submitFile = useCallback(async (file) => {
    try {
      const result = await uploadFile(file)
      const job = {
        job_id: result.job_id,
        filename: result.filename || file.name,
        input_type: result.input_type,
        status: 'processing',
        progress: 0,
        created_at: result.created_at || new Date().toISOString(),
        file_hash:   result.file_hash   || null,
        sha256_hash: result.sha256_hash || null,
        md5_hash:    result.md5_hash    || null,
        data: null,
      }

      setJobs(prev => [job, ...prev])
      setActiveJobId(result.job_id)
      startPolling(result.job_id)

      return job
    } catch (err) {
      throw err
    }
  }, [setJobs, setActiveJobId, startPolling])

  // ── Retry ─────────────────────────────────────────────────────────────────

  /**
   * Lädt die Ergebnisse eines abgeschlossenen Jobs erneut.
   *
   * Nützlich wenn das erste Laden der Ergebnisse fehlgeschlagen ist
   * (z. B. kurzzeitiger Netzwerkfehler) oder die UI-Daten veraltet sind.
   *
   * @param {string} jobId - Die Job-ID, deren Ergebnisse neu geladen werden sollen
   * @returns {Promise<void>}
   */
  const retryLoadResults = useCallback(async (jobId) => {
    await loadJobResults(jobId)
  }, [loadJobResults])

  return { submitFile, startPolling, retryLoadResults }
}
