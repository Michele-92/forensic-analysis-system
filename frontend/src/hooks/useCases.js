/**
 * ============================================================================
 * useCases — Case-Management-Hook (Backend-persistent, FA-20)
 * ============================================================================
 * Verwaltet CRUD-Operationen für forensische Cases (Fallakten).
 * Ein "Case" gruppiert mehrere Analyse-Jobs unter einem Aktenzeichen
 * und ermöglicht Case-übergreifende Korrelationsanalysen.
 *
 * Datenhaltungs-Strategie:
 *   - SCHREIBEN: Alle Mutationen gehen zuerst an das Backend (REST API),
 *     bei Erfolg wird der lokale React-State aktualisiert (optimistic update).
 *   - LESEN: Das initiale Laden erfolgt im AppContext beim Mount via
 *     fetchCasesFromServer(). Dieser Hook liest nur aus dem übergebenen
 *     cases-Array.
 *   - Fehlerverhalten: Bei Backend-Fehler wird die Exception weitergereicht,
 *     der lokale State bleibt unverändert (kein korrupter Zwischenstand).
 *
 * Ausnahme — Korrelationsdaten:
 *   setCaseCorrelationData() speichert nur lokal (kein eigener Backend-Endpunkt),
 *   da Korrelationsergebnisse transient sind und bei Bedarf neu berechnet werden.
 *
 * Exportierte Actions:
 *   - createCase(caseData)              → Neuen Case anlegen
 *   - updateCase(caseId, updates)       → Case-Metadaten ändern
 *   - deleteCase(caseId)                → Case löschen
 *   - addJobToCase(caseId, jobId)       → Job einem Case zuordnen
 *   - removeJobFromCase(caseId, jobId)  → Job aus Case entfernen
 *   - getCaseForJob(jobId)              → Case zu einem Job finden
 *   - setCaseCorrelationData(caseId, data) → Korrelationsdaten lokal setzen
 *
 * @module hooks/useCases
 */

import { useCallback } from 'react'
import {
  createCaseOnServer,
  updateCaseOnServer,
  deleteCaseOnServer,
  addJobToCaseOnServer,
  removeJobFromCaseOnServer,
} from '../api/backend'

// ── Hook-Definition ───────────────────────────────────────────────────────────

/**
 * Case-Management-Hook — Backend-persistent (FA-20).
 *
 * Alle Mutationen gehen zuerst an das Backend (REST API), dann wird der
 * lokale State aktualisiert. Bei Backend-Fehler wird eine Exception geworfen,
 * damit die aufrufende Komponente den Fehler anzeigen kann.
 *
 * Lesen (fetchCasesFromServer) erfolgt im AppContext beim Mount.
 *
 * @param {object[]} cases - Aktuelle Case-Liste aus dem AppContext-State
 * @param {function} setCases - State-Setter für die Case-Liste
 * @returns {{
 *   createCase: function,
 *   updateCase: function,
 *   deleteCase: function,
 *   addJobToCase: function,
 *   removeJobFromCase: function,
 *   getCaseForJob: function,
 *   setCaseCorrelationData: function
 * }}
 */
export function useCases(cases, setCases) {

  // ── CRUD-Operationen ──────────────────────────────────────────────────────

  /**
   * Legt einen neuen forensischen Case auf dem Backend an und fügt ihn dem lokalen State hinzu.
   *
   * Der neue Case wird an den Anfang der Liste gesetzt (neueste zuerst).
   *
   * @param {object} caseData - Daten für den neuen Case
   * @param {string} caseData.case_name - Name des Falls (Pflichtfeld)
   * @param {string} [caseData.case_number] - Aktenzeichen
   * @param {string} [caseData.description] - Beschreibung des Falls
   * @param {string} [caseData.analyst] - Zuständiger Analyst
   * @returns {Promise<object>} Das erstellte Case-Objekt (inkl. vom Backend vergebener case_id)
   * @throws {Error} Bei Backend-Fehler
   */
  const createCase = useCallback(async (caseData) => {
    const created = await createCaseOnServer(caseData)
    setCases(prev => [created, ...prev])
    return created
  }, [setCases])

  /**
   * Aktualisiert die Metadaten eines bestehenden Cases.
   *
   * Ersetzt das Case-Objekt in der lokalen Liste durch die vom Backend
   * zurückgegebene aktualisierte Version.
   *
   * @param {string} caseId - ID des zu aktualisierenden Cases
   * @param {object} updates - Zu ändernde Felder (Teilmenge der Case-Daten)
   * @returns {Promise<object>} Das aktualisierte Case-Objekt
   * @throws {Error} Bei Backend-Fehler
   */
  const updateCase = useCallback(async (caseId, updates) => {
    const updated = await updateCaseOnServer(caseId, updates)
    setCases(prev => prev.map(c => c.case_id === caseId ? updated : c))
    return updated
  }, [setCases])

  /**
   * Löscht einen Case auf dem Backend und entfernt ihn aus dem lokalen State.
   *
   * Verknüpfte Jobs werden nicht gelöscht; sie verlieren lediglich ihre Case-Zuordnung.
   *
   * @param {string} caseId - ID des zu löschenden Cases
   * @returns {Promise<void>}
   * @throws {Error} Bei Backend-Fehler
   */
  const deleteCase = useCallback(async (caseId) => {
    await deleteCaseOnServer(caseId)
    setCases(prev => prev.filter(c => c.case_id !== caseId))
  }, [setCases])

  // ── Job-Zuordnung ─────────────────────────────────────────────────────────

  /**
   * Ordnet einen bestehenden Analyse-Job einem Case zu.
   *
   * Das Backend aktualisiert die job_ids-Liste des Cases.
   * Gibt den aktualisierten Case zurück, der den State ersetzt.
   *
   * @param {string} caseId - ID des Ziel-Cases
   * @param {string} jobId - ID des hinzuzufügenden Jobs
   * @returns {Promise<object>} Aktualisiertes Case-Objekt mit erweiterter job_ids-Liste
   * @throws {Error} Bei Backend-Fehler
   */
  const addJobToCase = useCallback(async (caseId, jobId) => {
    const updated = await addJobToCaseOnServer(caseId, jobId)
    setCases(prev => prev.map(c => c.case_id === caseId ? updated : c))
    return updated
  }, [setCases])

  /**
   * Entfernt die Zuordnung eines Jobs aus einem Case.
   *
   * @param {string} caseId - ID des Cases
   * @param {string} jobId - ID des zu entfernenden Jobs
   * @returns {Promise<object>} Aktualisiertes Case-Objekt mit reduzierter job_ids-Liste
   * @throws {Error} Bei Backend-Fehler
   */
  const removeJobFromCase = useCallback(async (caseId, jobId) => {
    const updated = await removeJobFromCaseOnServer(caseId, jobId)
    setCases(prev => prev.map(c => c.case_id === caseId ? updated : c))
    return updated
  }, [setCases])

  // ── Lookup-Helfer ─────────────────────────────────────────────────────────

  /**
   * Sucht den Case, dem ein bestimmter Job zugeordnet ist.
   *
   * Durchsucht die lokale Case-Liste nach einem Case, dessen job_ids-Array
   * die gegebene jobId enthält. Reine Lese-Operation, kein Backend-Aufruf.
   *
   * @param {string} jobId - ID des gesuchten Jobs
   * @returns {object|null} Das zugehörige Case-Objekt oder null wenn kein Case zugeordnet
   */
  const getCaseForJob = useCallback((jobId) => {
    return cases.find(c => c.job_ids?.includes(jobId)) || null
  }, [cases])

  // ── Korrelationsdaten (nur lokal) ─────────────────────────────────────────

  /**
   * Speichert die Ergebnisse einer Korrelationsanalyse lokal im Case-State.
   *
   * Korrelationsdaten sind transient (werden bei Bedarf neu berechnet) und
   * haben keinen eigenen Backend-Endpunkt. Sie werden beim App-Neustart
   * nicht wiederhergestellt.
   *
   * @param {string} caseId - ID des Cases, dem die Daten zugeordnet werden
   * @param {object} data - Korrelationsergebnisse aus runCaseCorrelation()
   * @param {string} [data.correlation_report] - Textbericht
   * @param {object} [data.shared_iocs] - Gemeinsame Indicators of Compromise
   * @param {object} [data.metadata] - Statistische Metadaten
   */
  const setCaseCorrelationData = useCallback((caseId, data) => {
    // Korrelationsdaten bleiben lokal (kein eigener Backend-Endpoint)
    setCases(prev => prev.map(c =>
      c.case_id === caseId
        ? { ...c, correlationData: data, updated_at: new Date().toISOString() }
        : c
    ))
  }, [setCases])

  return {
    createCase,
    updateCase,
    deleteCase,
    addJobToCase,
    removeJobFromCase,
    getCaseForJob,
    setCaseCorrelationData,
  }
}
