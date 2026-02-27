import React, { useState } from 'react'
import { useApp } from '../../context/AppContext'
import { exportPdf } from '../../api/backend'
import LLMReportView from './LLMReportView'
import FindingsCards from './FindingsCards'
import IOCList from './IOCList'
import EvidenceIntegrity from './EvidenceIntegrity'
import RiskBadge from '../RiskBadge'
import { formatTimestamp } from '../../utils/formatters'
import { FileText, AlertTriangle, Activity, Clock, Download, Loader2 } from 'lucide-react'

export default function OverviewPanel() {
  const { activeJob, getCaseForJob } = useApp()
  const [reportOpen, setReportOpen] = useState(false)
  const [pdfLoading, setPdfLoading] = useState(false)
  const [pdfError, setPdfError] = useState(null)

  const data = activeJob?.data
  if (!data) return null

  const summary = data.summary || {}
  const anomalies = data.anomalies || []
  const preprocessed = data.preprocessed || {}
  const indicators = preprocessed.indicators || {}

  const overallRisk = anomalies.length > 0
    ? (Math.max(...anomalies.map(a => a.anomaly_score || 0)) >= 0.8 ? 'critical'
      : Math.max(...anomalies.map(a => a.anomaly_score || 0)) >= 0.6 ? 'high'
      : Math.max(...anomalies.map(a => a.anomaly_score || 0)) >= 0.4 ? 'medium' : 'low')
    : 'info'

  return (
    <div className="space-y-6">
      {/* Top Stats */}
      <div className="grid grid-cols-4 gap-4">
        <StatCard
          icon={<Activity size={18} className="text-accent-blue" />}
          label="Total Events"
          value={summary.total_events || '—'}
        />
        <StatCard
          icon={<AlertTriangle size={18} className="text-risk-high" />}
          label="Anomalien"
          value={summary.anomalies_found || anomalies.length}
        />
        <StatCard
          icon={<Activity size={18} className="text-accent-cyan" />}
          label="IOCs"
          value={summary.iocs_identified || (indicators.ips?.length || 0) + (indicators.domains?.length || 0)}
        />
        <StatCard
          icon={<Clock size={18} className="text-white/40" />}
          label="Analysiert"
          value={formatTimestamp(summary.analysis_timestamp)}
          small
        />
      </div>

      {/* Risk Overview + Report Button */}
      <div className="glass-card flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div>
            <span className="text-xs text-white/40 block mb-1">Gesamtrisiko</span>
            <RiskBadge level={overallRisk} size="md" />
          </div>
          <div className="h-8 w-px bg-white/[0.06]" />
          <div>
            <span className="text-xs text-white/40 block mb-1">Input</span>
            <span className="text-sm font-mono text-white/70">{activeJob.filename}</span>
          </div>
          <div className="h-8 w-px bg-white/[0.06]" />
          <div>
            <span className="text-xs text-white/40 block mb-1">Typ</span>
            <span className="text-sm text-white/70">{activeJob.input_type}</span>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={async () => {
              setPdfLoading(true)
              setPdfError(null)
              try {
                const jobCase = getCaseForJob(activeJob.job_id)
                const caseInfo = jobCase ? {
                  case_name: jobCase.case_name,
                  case_number: jobCase.case_number,
                  analyst: jobCase.analyst,
                } : {}
                await exportPdf(activeJob.job_id, caseInfo)
              } catch (err) {
                setPdfError(err.message)
              } finally {
                setPdfLoading(false)
              }
            }}
            disabled={pdfLoading}
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-accent-purple/10 text-accent-purple hover:bg-accent-purple/20 transition-all text-sm font-medium disabled:opacity-50"
          >
            {pdfLoading ? <Loader2 size={16} className="animate-spin" /> : <Download size={16} />}
            PDF Export
          </button>
          <button
            onClick={() => setReportOpen(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-accent-blue/10 text-accent-blue hover:bg-accent-blue/20 transition-all text-sm font-medium"
          >
            <FileText size={16} />
            Vollständiger Report
          </button>
        </div>
      </div>
      {pdfError && (
        <div className="glass-card border border-risk-critical/20 text-risk-critical text-xs py-2">
          PDF-Fehler: {pdfError}
        </div>
      )}

      {/* Evidence Integrity */}
      <EvidenceIntegrity fileHash={activeJob.file_hash} jobId={activeJob.job_id} />

      {/* Key Findings */}
      {anomalies.length > 0 && (
        <div>
          <h3 className="text-sm font-medium text-white/50 mb-3 flex items-center gap-2">
            <AlertTriangle size={14} />
            Key Findings
          </h3>
          <FindingsCards anomalies={anomalies} />
        </div>
      )}

      {/* IOCs */}
      {Object.values(indicators).some(arr => arr?.length > 0) && (
        <div>
          <IOCList indicators={indicators} />
        </div>
      )}

      {/* Report Modal */}
      {reportOpen && (
        <LLMReportView
          report={data.report}
          anomalies={anomalies}
          indicators={indicators}
          summary={summary}
          onClose={() => setReportOpen(false)}
        />
      )}
    </div>
  )
}

function StatCard({ icon, label, value, small }) {
  return (
    <div className="glass-card flex items-center gap-3">
      <div className="w-10 h-10 rounded-xl bg-white/[0.03] flex items-center justify-center flex-shrink-0">
        {icon}
      </div>
      <div>
        <span className="text-[10px] text-white/30 uppercase tracking-wider block">{label}</span>
        <span className={`font-semibold text-white/80 ${small ? 'text-xs font-mono' : 'text-lg'}`}>
          {value}
        </span>
      </div>
    </div>
  )
}
