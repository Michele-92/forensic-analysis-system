/**
 * Backend API Client
 *
 * Im Dev-Modus (Vite): Requests gehen über den Vite-Proxy (/api -> localhost:8000)
 * In Produktion: VITE_BACKEND_URL wird direkt verwendet
 */
function getBaseUrl() {
  const envUrl = import.meta.env.VITE_BACKEND_URL
  // Wenn eine volle URL gesetzt ist (http://...), verwende sie direkt
  if (envUrl && envUrl.startsWith('http')) return envUrl
  // Sonst: Nutze den Vite-Proxy-Pfad (default: /api)
  return envUrl || '/api'
}

const BASE_URL = getBaseUrl()

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

export async function uploadFile(file) {
  const formData = new FormData()
  formData.append('file', file)

  const res = await apiFetch('/analyze', {
    method: 'POST',
    body: formData,
  })

  return res.json()
}

export async function pollStatus(jobId) {
  const res = await apiFetch(`/status/${jobId}`)
  return res.json()
}

export async function fetchResults(jobId) {
  const res = await apiFetch(`/results/${jobId}`)
  return res.json()
}

export async function downloadFile(jobId, filename) {
  return apiFetch(`/download/${jobId}/${filename}`)
}

export async function fetchFileAsText(jobId, filename) {
  const res = await downloadFile(jobId, filename)
  return res.text()
}

export async function fetchFileAsJson(jobId, filename) {
  const res = await downloadFile(jobId, filename)
  return res.json()
}

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

export async function lookupThreatIntel(indicators) {
  const res = await apiFetch('/threat-intel/lookup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ indicators }),
  })
  return res.json()
}

export async function verifyEvidence(jobId) {
  const res = await apiFetch(`/verify/${jobId}`, { method: 'POST' })
  return res.json()
}

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
