import { useCallback, useRef } from 'react'
import { uploadFile, pollStatus, fetchResults, fetchFileAsText, fetchFileAsJson } from '../api/backend'

export function useJobs(jobs, setJobs, setActiveJobId) {
  const pollIntervals = useRef({})

  const updateJob = useCallback((jobId, updates) => {
    setJobs(prev => prev.map(j => j.job_id === jobId ? { ...j, ...updates } : j))
  }, [setJobs])

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

  const loadJobResults = useCallback(async (jobId) => {
    try {
      const results = await fetchResults(jobId)

      const data = { outputFiles: results.output_files || [] }

      // Load each result file
      const fileLoaders = [
        { name: 'report.md', key: 'report', loader: fetchFileAsText },
        { name: 'analysis_summary.json', key: 'summary', loader: fetchFileAsJson },
        { name: 'anomalies_detected.json', key: 'anomalies', loader: fetchFileAsJson },
        { name: 'preprocessed_for_llm.json', key: 'preprocessed', loader: fetchFileAsJson },
        { name: 'normalized_output.json', key: 'normalized', loader: fetchFileAsJson },
        { name: 'interpretation.json', key: 'interpretation', loader: fetchFileAsJson },
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
        file_hash: result.file_hash || null,
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

  const retryLoadResults = useCallback(async (jobId) => {
    await loadJobResults(jobId)
  }, [loadJobResults])

  return { submitFile, startPolling, retryLoadResults }
}
