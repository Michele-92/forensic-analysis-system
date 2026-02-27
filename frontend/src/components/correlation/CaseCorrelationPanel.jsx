import React, { useState, useEffect } from 'react'
import { useApp } from '../../context/AppContext'
import { runCaseCorrelation } from '../../api/llm'
import { exportCasePdf } from '../../api/backend'
import { marked } from 'marked'
import DOMPurify from 'dompurify'
import {
  GitCompareArrows, X, Play, FileDown, Loader2,
  Database, AlertTriangle, Network, Shield, Check,
} from 'lucide-react'

export default function CaseCorrelationPanel() {
  const {
    cases, jobs, caseCorrelationView, setCaseCorrelationView,
    setCaseCorrelationData,
  } = useApp()

  const [running, setRunning] = useState(false)
  const [phase, setPhase] = useState('')
  const [error, setError] = useState(null)
  const [pdfLoading, setPdfLoading] = useState(false)

  const caseObj = cases.find(c => c.case_id === caseCorrelationView)
  if (!caseObj) return null

  const caseJobs = jobs.filter(j => caseObj.job_ids.includes(j.job_id))
  const completedJobs = caseJobs.filter(j => j.status === 'completed')

  // Gespeicherte Korrelationsdaten aus dem Case laden
  const saved = caseObj.correlationData || null
  const correlationReport = saved?.correlation_report || null
  const sharedIocs = saved?.shared_iocs || null
  const metadata = saved?.metadata || null

  const handleClose = () => {
    setCaseCorrelationView(null)
  }

  const handleRun = async () => {
    setRunning(true)
    setPhase('Starte Korrelation...')
    setError(null)

    const jobIds = completedJobs.map(j => j.job_id)
    const caseMeta = {
      case_name: caseObj.case_name,
      case_number: caseObj.case_number,
      analyst: caseObj.analyst,
    }

    try {
      await runCaseCorrelation(jobIds, caseMeta, (event) => {
        // Phase-Updates
        if (event.message) setPhase(event.message)

        // Pre-analysis done — shared IOCs sofort speichern
        if (event.status === 'pre_analysis_done') {
          setCaseCorrelationData(caseObj.case_id, {
            shared_iocs: event.shared_iocs,
            metadata: event.metadata,
            correlation_report: saved?.correlation_report || null,
          })
        }

        // LLM fertig
        if (event.status === 'done' && event.result) {
          setCaseCorrelationData(caseObj.case_id, {
            shared_iocs: saved?.shared_iocs || event.shared_iocs,
            metadata: saved?.metadata || event.metadata,
            correlation_report: event.result,
          })
        }

        // Komplett
        if (event.status === 'complete') {
          setCaseCorrelationData(caseObj.case_id, {
            correlation_report: event.correlation_report,
            shared_iocs: event.shared_iocs,
            metadata: event.metadata,
          })
        }

        // Fehler
        if (event.status === 'error') {
          setError(event.error || 'Unbekannter Fehler')
        }
      })
    } catch (err) {
      setError(err.message)
    } finally {
      setRunning(false)
      setPhase('')
    }
  }

  const handleExportPdf = async () => {
    setPdfLoading(true)
    try {
      const jobIds = completedJobs.map(j => j.job_id)
      await exportCasePdf(
        jobIds,
        { case_name: caseObj.case_name, case_number: caseObj.case_number, analyst: caseObj.analyst },
        { correlation_report: correlationReport, shared_iocs: sharedIocs, metadata: metadata }
      )
    } catch (err) {
      setError(`PDF-Export fehlgeschlagen: ${err.message}`)
    } finally {
      setPdfLoading(false)
    }
  }

  // IOC-Kategorien fuer Anzeige
  const iocLabels = {
    ips: 'IP-Adressen',
    users: 'Benutzer',
    hostnames: 'Hostnamen',
    domains: 'Domains',
    processes: 'Prozesse',
    files: 'Dateien',
  }

  const totalSharedIocs = sharedIocs
    ? Object.values(sharedIocs).reduce((sum, vals) => sum + Object.keys(vals).length, 0)
    : 0

  return (
    <div className="space-y-6">
      {/* Header Bar */}
      <div className="glass-card">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-cyan-500/10 flex items-center justify-center">
              <GitCompareArrows size={20} className="text-cyan-400" />
            </div>
            <div>
              <h2 className="text-base font-semibold text-white/90">Fallkorrelation</h2>
              <p className="text-xs text-white/40">
                {caseObj.case_name}
                {caseObj.case_number && <span className="ml-2 font-mono">({caseObj.case_number})</span>}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {/* Run Button */}
            <button
              onClick={handleRun}
              disabled={running || completedJobs.length < 2}
              className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-medium bg-cyan-500/10 text-cyan-400 hover:bg-cyan-500/20 transition-all disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {running ? (
                <Loader2 size={14} className="animate-spin" />
              ) : correlationReport ? (
                <Check size={14} />
              ) : (
                <Play size={14} />
              )}
              {correlationReport ? 'Neu analysieren' : 'Korrelation starten'}
            </button>

            {/* PDF Export */}
            {correlationReport && (
              <button
                onClick={handleExportPdf}
                disabled={pdfLoading}
                className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium bg-white/[0.06] text-white/60 hover:bg-white/[0.1] transition-all disabled:opacity-40"
              >
                {pdfLoading ? <Loader2 size={14} className="animate-spin" /> : <FileDown size={14} />}
                Case PDF
              </button>
            )}

            {/* Close */}
            <button
              onClick={handleClose}
              className="p-2 rounded-lg text-white/30 hover:text-white/60 hover:bg-white/[0.06] transition-all"
            >
              <X size={16} />
            </button>
          </div>
        </div>

        {completedJobs.length < 2 && (
          <p className="text-xs text-yellow-400/60 mt-3">
            Mindestens 2 abgeschlossene Analysen im Fall erforderlich.
          </p>
        )}
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-4 gap-3">
        <StatCard
          icon={Database}
          label="Quellen"
          value={completedJobs.length}
          color="text-cyan-400"
          bgColor="bg-cyan-500/10"
        />
        <StatCard
          icon={Shield}
          label="Events gesamt"
          value={metadata?.total_events ?? '—'}
          color="text-blue-400"
          bgColor="bg-blue-500/10"
        />
        <StatCard
          icon={AlertTriangle}
          label="Anomalien gesamt"
          value={metadata?.total_anomalies ?? '—'}
          color="text-amber-400"
          bgColor="bg-amber-500/10"
        />
        <StatCard
          icon={Network}
          label="Geteilte IOCs"
          value={totalSharedIocs || '—'}
          color="text-purple-400"
          bgColor="bg-purple-500/10"
        />
      </div>

      {/* Error */}
      {error && (
        <div className="glass-card border border-red-500/20 bg-red-500/5">
          <p className="text-sm text-red-400">{error}</p>
        </div>
      )}

      {/* Progress */}
      {running && (
        <div className="glass-card">
          <div className="flex items-center gap-3">
            <div className="w-6 h-6 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
            <span className="text-sm text-white/50">{phase}</span>
          </div>
        </div>
      )}

      {/* Shared IOCs (erscheint VOR dem LLM-Bericht) */}
      {sharedIocs && totalSharedIocs > 0 && (
        <div className="glass-card">
          <h3 className="text-sm font-medium text-white/60 mb-3 flex items-center gap-2">
            <Network size={14} className="text-cyan-400" />
            Quellenuebergreifende IOCs
          </h3>
          <div className="space-y-3">
            {Object.entries(sharedIocs).map(([category, vals]) => {
              const entries = Object.entries(vals)
              if (entries.length === 0) return null
              return (
                <div key={category}>
                  <h4 className="text-xs font-medium text-white/40 mb-1.5">
                    {iocLabels[category] || category}
                  </h4>
                  <div className="space-y-1">
                    {entries.map(([value, sources]) => (
                      <div
                        key={value}
                        className="flex items-center justify-between px-3 py-1.5 rounded-lg bg-white/[0.03]"
                      >
                        <span className="text-xs text-white/70 font-mono">{value}</span>
                        <div className="flex items-center gap-1.5">
                          {sources.map((srcIdx) => {
                            const srcJob = completedJobs[srcIdx]
                            return (
                              <span
                                key={srcIdx}
                                className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400"
                                title={srcJob?.filename}
                              >
                                Q{srcIdx + 1}
                              </span>
                            )
                          })}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Korrelationsbericht */}
      {correlationReport && (
        <div className="glass-card">
          <h3 className="text-sm font-medium text-white/60 mb-3 flex items-center gap-2">
            <GitCompareArrows size={14} className="text-cyan-400" />
            Korrelationsanalyse
          </h3>
          <div
            className="report-content text-sm"
            dangerouslySetInnerHTML={{
              __html: DOMPurify.sanitize(marked.parse(correlationReport))
            }}
          />
        </div>
      )}

      {/* Quellen-Uebersicht */}
      {completedJobs.length > 0 && (
        <div className="glass-card">
          <h3 className="text-sm font-medium text-white/60 mb-3">Analysierte Quellen</h3>
          <div className="space-y-1.5">
            {completedJobs.map((job, idx) => (
              <div
                key={job.job_id}
                className="flex items-center justify-between px-3 py-2 rounded-lg bg-white/[0.03]"
              >
                <div className="flex items-center gap-2.5">
                  <span className="text-[10px] font-bold text-cyan-400 bg-cyan-500/10 px-1.5 py-0.5 rounded">
                    Q{idx + 1}
                  </span>
                  <span className="text-xs text-white/70">{job.filename}</span>
                </div>
                <div className="flex items-center gap-3 text-[10px] text-white/30">
                  <span>{job.data?.anomalies?.length || 0} Anomalien</span>
                  <span className="font-mono">{job.job_id.slice(0, 8)}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function StatCard({ icon: Icon, label, value, color, bgColor }) {
  return (
    <div className="glass-card flex items-center gap-3 py-3">
      <div className={`w-8 h-8 rounded-lg ${bgColor} flex items-center justify-center flex-shrink-0`}>
        <Icon size={16} className={color} />
      </div>
      <div>
        <p className="text-lg font-semibold text-white/80">{value}</p>
        <p className="text-[10px] text-white/30">{label}</p>
      </div>
    </div>
  )
}
