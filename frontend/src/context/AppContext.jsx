import React, { createContext, useContext, useEffect } from 'react'
import { useLocalStorage } from '../hooks/useLocalStorage'
import { useJobs } from '../hooks/useJobs'
import { useCases } from '../hooks/useCases'

const AppContext = createContext(null)

export function AppProvider({ children }) {
  const [jobs, setJobs] = useLocalStorage('lfx-jobs', [])
  const [activeJobId, setActiveJobId] = useLocalStorage('lfx-active-job', null)
  const [activeView, setActiveView] = useLocalStorage('lfx-active-view', 'overview')

  // Case Management
  const [cases, setCases] = useLocalStorage('lfx-cases', [])
  const [activeCaseId, setActiveCaseId] = useLocalStorage('lfx-active-case', null)

  const { submitFile, startPolling, retryLoadResults } = useJobs(jobs, setJobs, setActiveJobId)
  const [caseCorrelationView, setCaseCorrelationView] = useLocalStorage('lfx-correlation-view', null)

  const {
    createCase, updateCase, deleteCase,
    addJobToCase, removeJobFromCase, getCaseForJob, setCaseCorrelationData,
  } = useCases(cases, setCases)

  // Resume polling for in-progress jobs on mount
  useEffect(() => {
    jobs.forEach(job => {
      if (job.status === 'processing') {
        startPolling(job.job_id)
      }
    })
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const activeJob = jobs.find(j => j.job_id === activeJobId) || null
  const activeCase = cases.find(c => c.case_id === activeCaseId) || null

  // Gefilterte Jobs: wenn ein Case aktiv ist, nur dessen Jobs zeigen
  const filteredJobs = activeCaseId && activeCase
    ? jobs.filter(j => activeCase.job_ids.includes(j.job_id))
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
    deleteCase: deleteCase,
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
