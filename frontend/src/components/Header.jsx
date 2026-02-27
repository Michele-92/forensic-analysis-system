import React from 'react'
import { useApp } from '../context/AppContext'
import { LayoutDashboard, BarChart3, Brain, GitCompareArrows } from 'lucide-react'

const views = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'analytics', label: 'Analytics', icon: BarChart3 },
  { id: 'intelligence', label: 'Intelligence', icon: Brain },
]

export default function Header() {
  const { activeView, setActiveView, activeJob, caseCorrelationView, setCaseCorrelationView, cases } = useApp()

  const correlationCase = caseCorrelationView
    ? cases.find(c => c.case_id === caseCorrelationView)
    : null

  const handleTabClick = (id) => {
    if (caseCorrelationView) setCaseCorrelationView(null)
    setActiveView(id)
  }

  return (
    <header className="h-14 flex items-center justify-between px-6 border-b border-white/[0.06] bg-black/50 backdrop-blur-xl">
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-1">
          {views.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => handleTabClick(id)}
              className={`
                flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200
                ${activeView === id && !caseCorrelationView
                  ? 'bg-white/[0.08] text-white'
                  : 'text-white/40 hover:text-white/70 hover:bg-white/[0.03]'
                }
              `}
            >
              <Icon size={16} />
              {label}
            </button>
          ))}
        </div>

        {correlationCase && (
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-cyan-500/10 text-cyan-400 text-sm font-medium border border-cyan-500/20">
            <GitCompareArrows size={14} />
            <span>Fallkorrelation</span>
            <span className="text-white/30 mx-0.5">|</span>
            <span className="text-white/70 text-xs">{correlationCase.case_name}</span>
          </div>
        )}
      </div>

      {activeJob && !caseCorrelationView && (
        <div className="flex items-center gap-3 text-sm">
          <span className="text-white/30 font-mono text-xs">
            {activeJob.job_id}
          </span>
          {activeJob.status === 'processing' && (
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-accent-blue animate-pulse" />
              <span className="text-accent-blue">{activeJob.progress}%</span>
            </div>
          )}
          {activeJob.status === 'completed' && (
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-accent-green" />
              <span className="text-accent-green">Abgeschlossen</span>
            </div>
          )}
          {activeJob.status === 'failed' && (
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-risk-critical" />
              <span className="text-risk-critical">Fehlgeschlagen</span>
            </div>
          )}
        </div>
      )}
    </header>
  )
}
