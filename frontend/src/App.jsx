import React from 'react'
import { useApp } from './context/AppContext'
import Sidebar from './components/Sidebar'
import Header from './components/Header'
import OverviewPanel from './components/overview/OverviewPanel'
import AnalyticsPanel from './components/analytics/AnalyticsPanel'
import IntelligencePanel from './components/intelligence/IntelligencePanel'
import CaseCorrelationPanel from './components/correlation/CaseCorrelationPanel'
import { Shield, Upload } from 'lucide-react'

function EmptyState() {
  return (
    <div className="flex-1 flex flex-col items-center justify-center gap-4">
      <div className="w-16 h-16 rounded-2xl glass flex items-center justify-center">
        <Shield size={28} className="text-white/20" />
      </div>
      <div className="text-center">
        <h2 className="text-lg font-medium text-white/40">LFX Forensic Analysis</h2>
        <p className="text-sm text-white/20 mt-1">Lade ein forensisches Image hoch um zu beginnen</p>
      </div>
      <div className="flex items-center gap-2 text-xs text-white/15 mt-2">
        <Upload size={14} />
        <span>Drag &amp; Drop in die Sidebar oder klicke auf die Upload-Zone</span>
      </div>
    </div>
  )
}

function ProcessingState({ job }) {
  return (
    <div className="flex-1 flex flex-col items-center justify-center gap-6">
      <div className="relative">
        <div className="w-20 h-20 rounded-2xl glass flex items-center justify-center">
          <div className="w-8 h-8 border-2 border-accent-blue border-t-transparent rounded-full animate-spin" />
        </div>
        <div className="absolute -bottom-1 -right-1 w-6 h-6 rounded-full bg-accent-blue/20 flex items-center justify-center">
          <span className="text-[10px] font-mono text-accent-blue">{job.progress}%</span>
        </div>
      </div>
      <div className="text-center">
        <h2 className="text-lg font-medium text-white/60">Analyse läuft...</h2>
        <p className="text-sm text-white/30 mt-1 font-mono">{job.filename}</p>
      </div>
    </div>
  )
}

function MainContent() {
  const { activeJob, activeView, caseCorrelationView } = useApp()

  // Case Correlation View hat Vorrang
  if (caseCorrelationView) return <CaseCorrelationPanel />

  if (!activeJob) return <EmptyState />
  if (activeJob.status === 'processing') return <ProcessingState job={activeJob} />

  if (activeJob.status === 'failed') {
    return (
      <div className="flex-1 flex flex-col items-center justify-center gap-4">
        <div className="w-16 h-16 rounded-2xl bg-risk-critical/10 flex items-center justify-center">
          <span className="text-2xl">!</span>
        </div>
        <div className="text-center">
          <h2 className="text-lg font-medium text-risk-critical">Analyse fehlgeschlagen</h2>
          <p className="text-sm text-white/30 mt-1">{activeJob.error || 'Unbekannter Fehler'}</p>
        </div>
      </div>
    )
  }

  switch (activeView) {
    case 'analytics':
      return <AnalyticsPanel />
    case 'intelligence':
      return <IntelligencePanel />
    default:
      return <OverviewPanel />
  }
}

export default function App() {
  return (
    <div className="flex h-screen overflow-hidden bg-black">
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <Header />
        <main className="flex-1 overflow-y-auto p-6">
          <MainContent />
        </main>
      </div>
    </div>
  )
}
