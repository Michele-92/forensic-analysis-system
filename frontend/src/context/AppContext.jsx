/**
 * ============================================================================
 * APP CONTEXT — Globaler Anwendungs-State (React Context)
 * ============================================================================
 * Zentraler State-Container der gesamten Anwendung. Stellt alle globalen
 * Daten und Aktionen über den useApp()-Hook bereit, sodass keine Props
 * durch den Komponenten-Baum weitergegeben werden müssen (Prop-Drilling).
 *
 * Verwalteter State:
 *   - jobs            → Liste aller Analyse-Jobs (localStorage-persistent)
 *   - activeJobId     → Aktuell ausgewählter Job (localStorage-persistent)
 *   - activeView      → Aktive Tab-Ansicht: 'overview'|'analytics'|'intelligence'
 *   - cases           → Forensische Fallakten (vom Backend geladen, FA-20)
 *   - activeCaseId    → Aktuell ausgewählter Fall (localStorage-persistent)
 *   - caseCorrelationView → Korrelationsergebnis für Fall-Ansicht
 *
 * Bereitgestellte Aktionen:
 *   - submitFile()         → Datei hochladen, Job starten (via useJobs)
 *   - startPolling()       → Job-Polling manuell starten (nach Neustart)
 *   - retryLoadResults()   → Ergebnisse eines Jobs neu laden
 *   - deleteJob()          → Job aus der Liste entfernen
 *   - updateJobData()      → Job-Daten partiell aktualisieren
 *   - createCase() / updateCase() / deleteCase()  → Fall-CRUD (via useCases)
 *   - addJobToCase() / removeJobFromCase()        → Job-Fall-Zuordnung
 *   - getCaseForJob()      → Fall zu einem Job finden
 *   - setCaseCorrelationData() → Korrelationsdaten lokal speichern
 *
 * Initialisierung (useEffect beim Mount):
 *   - Laufende Jobs (status='processing') werden automatisch weiter gepollt
 *   - Alle Cases werden vom Backend neu geladen (FA-20)
 *
 * Verwendung:
 *   import { useApp } from '../context/AppContext'
 *   const { activeJob, submitFile, setActiveView } = useApp()
 *
 * @module context/AppContext
 */
import React, { createContext, useContext, useEffect, useState } from 'react'
import { useLocalStorage } from '../hooks/useLocalStorage'
import { useJobs } from '../hooks/useJobs'
import { useCases } from '../hooks/useCases'
import { fetchCasesFromServer } from '../api/backend'

const AppContext = createContext(null)

export function AppProvider({ children }) {
  const [jobs, setJobs] = useLocalStorage('lfx-jobs', [])
  const [activeJobId, setActiveJobId] = useLocalStorage('lfx-active-job', null)
  const [activeView, setActiveView] = useLocalStorage('lfx-active-view', 'overview')

  // Case Management — Daten kommen vom Backend (FA-20), nur activeCaseId im localStorage
  const [cases, setCases] = useState([])
  const [activeCaseId, setActiveCaseId] = useLocalStorage('lfx-active-case', null)

  const { submitFile, startPolling, retryLoadResults } = useJobs(jobs, setJobs, setActiveJobId)
  const [caseCorrelationView, setCaseCorrelationView] = useLocalStorage('lfx-correlation-view', null)

  const {
    createCase, updateCase, deleteCase,
    addJobToCase, removeJobFromCase, getCaseForJob, setCaseCorrelationData,
  } = useCases(cases, setCases)

  // Beim Mount: laufende Jobs weiter pollen + Cases vom Backend laden
  useEffect(() => {
    jobs.forEach(job => {
      if (job.status === 'processing') {
        startPolling(job.job_id)
      }
    })

    // Cases vom Backend laden (FA-20)
    fetchCasesFromServer()
      .then(setCases)
      .catch(err => console.warn('Cases vom Backend konnten nicht geladen werden:', err.message))
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const activeJob = jobs.find(j => j.job_id === activeJobId) || null
  const activeCase = cases.find(c => c.case_id === activeCaseId) || null

  // Gefilterte Jobs: wenn ein Case aktiv ist, nur dessen Jobs zeigen
  const filteredJobs = activeCaseId && activeCase
    ? jobs.filter(j => activeCase.job_ids?.includes(j.job_id))
    : jobs

  const deleteJob = (jobId) => {
    setJobs(prev => prev.filter(j => j.job_id !== jobId))
    if (activeJobId === jobId) {
      const remaining = jobs.filter(j => j.job_id !== jobId)
      setActiveJobId(remaining[0]?.job_id || null)
    }
  }

  const updateJobData = (jobId, dataUpdates) => {
    setJobs(prev => prev.map(j => {
      if (j.job_id !== jobId) return j
      return { ...j, data: { ...j.data, ...dataUpdates } }
    }))
  }

  const value = {
    jobs,
    filteredJobs,
    activeJob,
    activeJobId,
    setActiveJobId,
    activeView,
    setActiveView,
    submitFile,
    deleteJob,
    retryLoadResults,
    updateJobData,
    // Case Management
    cases,
    activeCase,
    activeCaseId,
    setActiveCaseId,
    createCase,
    updateCase,
    deleteCase,
    addJobToCase,
    removeJobFromCase,
    getCaseForJob,
    setCaseCorrelationData,
    // Correlation View
    caseCorrelationView,
    setCaseCorrelationView,
  }

  return <AppContext.Provider value={value}>{children}</AppContext.Provider>
}

export function useApp() {
  const ctx = useContext(AppContext)
  if (!ctx) throw new Error('useApp must be used within AppProvider')
  return ctx
}
