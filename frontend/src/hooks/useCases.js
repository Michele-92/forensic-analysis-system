import { useCallback } from 'react'

export function useCases(cases, setCases) {

  const createCase = useCallback((caseData) => {
    const newCase = {
      case_id: 'case_' + Date.now().toString(36) + Math.random().toString(36).substr(2, 5),
      case_name: caseData.case_name,
      case_number: caseData.case_number || '',
      description: caseData.description || '',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      job_ids: [],
      tags: caseData.tags || [],
      status: 'offen',
      analyst: caseData.analyst || '',
    }
    setCases(prev => [newCase, ...prev])
    return newCase
  }, [setCases])

  const updateCase = useCallback((caseId, updates) => {
    setCases(prev => prev.map(c =>
      c.case_id === caseId
        ? { ...c, ...updates, updated_at: new Date().toISOString() }
        : c
    ))
  }, [setCases])

  const deleteCase = useCallback((caseId) => {
    setCases(prev => prev.filter(c => c.case_id !== caseId))
  }, [setCases])

  const addJobToCase = useCallback((caseId, jobId) => {
    setCases(prev => prev.map(c =>
      c.case_id === caseId
        ? { ...c, job_ids: [...new Set([...c.job_ids, jobId])], updated_at: new Date().toISOString() }
        : c
    ))
  }, [setCases])

  const removeJobFromCase = useCallback((caseId, jobId) => {
    setCases(prev => prev.map(c =>
      c.case_id === caseId
        ? { ...c, job_ids: c.job_ids.filter(id => id !== jobId), updated_at: new Date().toISOString() }
        : c
    ))
  }, [setCases])

  const getCaseForJob = useCallback((jobId) => {
    return cases.find(c => c.job_ids.includes(jobId)) || null
  }, [cases])

  const setCaseCorrelationData = useCallback((caseId, data) => {
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
