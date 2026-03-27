/**
 * ============================================================================
 * OVERVIEW PANEL — Executive Summary des Forensik-Reports
 * ============================================================================
 * Hauptansicht nach Abschluss einer Analyse. Zeigt alle wichtigen Kennzahlen
 * auf einen Blick: Gesamtrisiko, erkannte Anomalien, IOCs und Zeitstempel.
 *
 * Enthaltene Sektionen (von oben nach unten):
 *   - Top Stats:          4 Kennzahl-Karten (Events, Anomalien, IOCs, Zeitstempel)
 *   - Risk Overview:      Gesamtrisiko-Badge + Dateiinfo + Export-Buttons
 *   - Evidence Integrity: Hash-Verifizierung der Beweis-Datei (Chain of Custody)
 *   - System Profile:     Profil des analysierten Systems (optional, aus FA-22)
 *   - Key Findings:       Karten der Top-6 Anomalie-Befunde
 *   - IOC List:           Indicators of Compromise mit Threat-Intel-Lookup
 *
 * Modals (werden über lokalen State gesteuert):
 *   - LLMReportView:      Markdown-Report des Backends + optionaler Ollama-Report
 *   - PdfExportModal:     Standard-PDF-Export mit Gutachter-Angaben
 *   - FullReportModal:    Vollständiger Report inkl. Multi-Agent KI-Analyse
 *
 * Props: keine — liest `activeJob` und `getCaseForJob` aus AppContext
 *
 * Abhängigkeiten:
 *   AppContext, PdfExportModal, FullReportModal, LLMReportView,
 *   FindingsCards, IOCList, EvidenceIntegrity, SystemProfileCard,
 *   RiskBadge, formatters, lucide-react
 *
 * @component
 */
import React, { useState } from 'react'
import { useApp } from '../../context/AppContext'
import PdfExportModal from '../PdfExportModal'
import FullReportModal from '../FullReportModal'
import LLMReportView from './LLMReportView'
import FindingsCards from './FindingsCards'
import IOCList from './IOCList'
import EvidenceIntegrity from './EvidenceIntegrity'
import SystemProfileCard from './SystemProfileCard'
import RiskBadge from '../RiskBadge'
import { formatTimestamp } from '../../utils/formatters'
import { FileText, AlertTriangle, Activity, Clock, Download, FileDown } from 'lucide-react'

// ── Hauptkomponente ───────────────────────────────────────────────────────────

/**
 * Executive-Summary-Ansicht für den aktiven Analyse-Job.
 * Rendert nichts, solange kein aktiver Job mit Daten vorhanden ist.
 */
export default function OverviewPanel() {
  const { activeJob, getCaseForJob } = useApp()
  const [reportOpen, setReportOpen] = useState(false)
  const [pdfModalOpen, setPdfModalOpen] = useState(false)
  const [fullReportOpen, setFullReportOpen] = useState(false)

  const data = activeJob?.data
  if (!data) return null

  // Optionale Multi-Agent-Analyse (aus IntelligencePanel befüllt)
  const agentAnalysis = data.agentAnalysis || null

  const summary      = data.summary      || {}
  const anomalies    = data.anomalies    || []
  const preprocessed = data.preprocessed || {}
  const indicators   = preprocessed.indicators || {}

  // Gesamtrisiko aus dem höchsten Anomalie-Score ableiten:
  // >= 0.8 → critical, >= 0.6 → high, >= 0.4 → medium, sonst low / info
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

        {/* Export- und Report-Buttons */}
        <div className="flex items-center gap-2">
          <button
            onClick={() => setPdfModalOpen(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-accent-purple/10 text-accent-purple hover:bg-accent-purple/20 transition-all text-sm font-medium"
          >
            <Download size={16} />
            PDF Export
          </button>
          <button
            onClick={() => setFullReportOpen(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-accent-cyan/10 text-accent-cyan hover:bg-accent-cyan/20 transition-all text-sm font-medium"
          >
            <FileDown size={16} />
            Vollständiger Report
            {/* Grüner Indikator-Punkt wenn Multi-Agent-Analyse vorhanden */}
            {agentAnalysis && (
              <span className="w-1.5 h-1.5 rounded-full bg-accent-green" />
            )}
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

      {/* Evidence Integrity */}
      <EvidenceIntegrity fileHash={activeJob.file_hash} jobId={activeJob.job_id} />

      {/* System-Profil (FA-22) */}
      {data.systemProfile && <SystemProfileCard profile={data.systemProfile} />}

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

      {/* PDF Export Modal */}
      {pdfModalOpen && (
        <PdfExportModal
          jobCase={getCaseForJob(activeJob.job_id)}
          jobId={activeJob.job_id}
          onClose={() => setPdfModalOpen(false)}
        />
      )}

      {/* Vollständiger Report Modal */}
      {fullReportOpen && (
        <FullReportModal
          jobCase={getCaseForJob(activeJob.job_id)}
          jobId={activeJob.job_id}
          agentAnalysis={agentAnalysis}
          onClose={() => setFullReportOpen(false)}
        />
      )}
    </div>
  )
}

// ── Hilfskomponenten ──────────────────────────────────────────────────────────

/**
 * Einzelne Statistik-Karte in der Top-Stats-Leiste.
 * Zeigt ein Icon, eine Beschriftung und eine Kennzahl.
 *
 * @param {React.ReactNode} icon  - Lucide-Icon (bereits als JSX übergeben)
 * @param {string}          label - Beschriftung unter der Kennzahl (z.B. "Total Events")
 * @param {string|number}   value - Anzuzeigende Kennzahl
 * @param {boolean}         [small] - Kleinere Monospace-Schrift für lange Werte (z.B. Zeitstempel)
 */
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
