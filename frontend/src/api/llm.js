/**
 * Lokale LLM-Analyse via Backend (Ollama).
 * Ersetzt Gemini — kein API-Key, kein Quota, komplett offline.
 */
import { apiFetch } from './backend'

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

/**
 * Multi-Agent-Analyse via SSE (Server-Sent Events).
 * 3 Agenten: Triage → Analyst → Reporter.
 *
 * @param {string} jobId - Die Job-ID
 * @param {function} onEvent - Callback fuer jedes SSE-Event: (data: object) => void
 * @returns {Promise<void>} - Resolved wenn Stream endet
 */
export async function runAgentAnalysis(jobId, onEvent) {
  const baseUrl = import.meta.env.VITE_BACKEND_URL || '/api'
  const url = `${baseUrl}/agent-analyze/${jobId}`

  const response = await fetch(url)

  if (!response.ok) {
    const err = await response.json().catch(() => ({ detail: response.statusText }))
    throw new Error(err.detail || `HTTP ${response.status}`)
  }

  const reader = response.body.getReader()
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

  // Restlichen Buffer verarbeiten
  if (buffer.trim() && buffer.trim().startsWith('data: ')) {
    try {
      const data = JSON.parse(buffer.trim().slice(6))
      onEvent(data)
    } catch (e) {
      // ignorieren
    }
  }
}

/**
 * Case-Korrelation via SSE (Server-Sent Events).
 * Analysiert quellenuebergreifende Muster ueber mehrere Jobs.
 *
 * @param {string[]} jobIds - Liste der Job-IDs
 * @param {object} caseMeta - {case_name?, case_number?, analyst?}
 * @param {function} onEvent - Callback fuer jedes SSE-Event
 * @returns {Promise<void>}
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

  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''

  while (true) {
    const { done, value } = await reader.read()
    if (done) break

    buffer += decoder.decode(value, { stream: true })

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

  if (buffer.trim() && buffer.trim().startsWith('data: ')) {
    try {
      const data = JSON.parse(buffer.trim().slice(6))
      onEvent(data)
    } catch (e) {
      // ignorieren
    }
  }
}
