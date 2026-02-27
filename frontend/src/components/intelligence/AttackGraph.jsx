import React, { useState, useMemo } from 'react'
import { Shield, ChevronDown, ChevronRight, Crosshair } from 'lucide-react'

/**
 * Kanonische MITRE ATT&CK Kill Chain Phasen-Reihenfolge.
 */
const KILL_CHAIN = [
  { tactic: 'Reconnaissance',       short: 'RECON',   color: '#64748b' },
  { tactic: 'Initial Access',       short: 'ACCESS',  color: '#6366f1' },
  { tactic: 'Execution',            short: 'EXEC',    color: '#8b5cf6' },
  { tactic: 'Persistence',          short: 'PERSIST', color: '#a855f7' },
  { tactic: 'Privilege Escalation', short: 'PRIVESC', color: '#d946ef' },
  { tactic: 'Defense Evasion',      short: 'EVASION', color: '#ec4899' },
  { tactic: 'Credential Access',    short: 'CREDS',   color: '#f43f5e' },
  { tactic: 'Discovery',            short: 'DISC',    color: '#f97316' },
  { tactic: 'Lateral Movement',     short: 'LATERAL', color: '#eab308' },
  { tactic: 'Command and Control',  short: 'C2',      color: '#ef4444' },
  { tactic: 'Exfiltration',         short: 'EXFIL',   color: '#dc2626' },
  { tactic: 'Impact',               short: 'IMPACT',  color: '#b91c1c' },
]

export default function AttackGraph({ anomalies }) {
  const [expandedPhase, setExpandedPhase] = useState(null)

  // Anomalien pro Taktik aggregieren
  const phaseData = useMemo(() => {
    const map = {}
    KILL_CHAIN.forEach(phase => {
      map[phase.tactic] = { techniques: {}, anomalyCount: 0, anomalies: [] }
    })

    for (const anomaly of (anomalies || [])) {
      for (const tech of (anomaly.mitre_techniques || [])) {
        const tactic = tech.tactic
        if (!map[tactic]) continue
        map[tactic].anomalyCount++
        map[tactic].anomalies.push(anomaly)
        if (!map[tactic].techniques[tech.id]) {
          map[tactic].techniques[tech.id] = { ...tech, count: 0 }
        }
        map[tactic].techniques[tech.id].count++
      }
    }
    return map
  }, [anomalies])

  const activePhases = KILL_CHAIN.filter(p => phaseData[p.tactic].anomalyCount > 0)
  const maxCount = Math.max(1, ...activePhases.map(p => phaseData[p.tactic].anomalyCount))

  if (activePhases.length === 0) {
    return (
      <div className="glass-card flex items-center justify-center h-24">
        <span className="text-sm text-white/20">Keine MITRE ATT&CK Daten vorhanden</span>
      </div>
    )
  }

  return (
    <div className="glass-card">
      <h3 className="text-sm font-medium text-white/50 mb-4 flex items-center gap-2">
        <Crosshair size={14} className="text-risk-high" />
        Attack Kill Chain
        <span className="text-[10px] bg-white/[0.05] px-1.5 py-0.5 rounded-full text-white/30">
          {activePhases.length} / {KILL_CHAIN.length} Phasen aktiv
        </span>
      </h3>

      {/* Kill Chain Flow */}
      <div className="flex flex-wrap gap-1 mb-3">
        {KILL_CHAIN.map((phase, i) => {
          const data = phaseData[phase.tactic]
          const isActive = data.anomalyCount > 0
          const isExpanded = expandedPhase === phase.tactic
          const intensity = isActive ? Math.max(0.3, data.anomalyCount / maxCount) : 0
          const techCount = Object.keys(data.techniques).length

          return (
            <div key={phase.tactic} className="flex items-center">
              {/* Phase Box */}
              <button
                onClick={() => isActive && setExpandedPhase(isExpanded ? null : phase.tactic)}
                className={`relative flex flex-col items-center px-2 py-2 rounded-lg border transition-all min-w-[72px] ${
                  isActive
                    ? 'border-white/[0.1] cursor-pointer hover:border-white/[0.2]'
                    : 'border-white/[0.03] opacity-30 cursor-default'
                } ${isExpanded ? 'ring-1 ring-white/20' : ''}`}
                style={isActive ? {
                  backgroundColor: `${phase.color}${Math.round(intensity * 30).toString(16).padStart(2, '0')}`,
                } : {}}
                disabled={!isActive}
              >
                {/* Anomaly count badge */}
                {isActive && (
                  <div
                    className="absolute -top-1.5 -right-1.5 w-4 h-4 rounded-full flex items-center justify-center text-[8px] font-bold text-white"
                    style={{ backgroundColor: phase.color }}
                  >
                    {data.anomalyCount}
                  </div>
                )}

                <span
                  className="text-[8px] font-bold tracking-wider"
                  style={{ color: isActive ? phase.color : 'rgba(255,255,255,0.2)' }}
                >
                  {phase.short}
                </span>
                <span className="text-[9px] text-white/40 mt-0.5 leading-tight text-center">
                  {phase.tactic}
                </span>
                {isActive && (
                  <span className="text-[8px] text-white/25 mt-0.5">
                    {techCount} {techCount === 1 ? 'Technik' : 'Techniken'}
                  </span>
                )}
              </button>

              {/* Arrow connector */}
              {i < KILL_CHAIN.length - 1 && (
                <div className="flex items-center mx-0.5">
                  <div className={`w-3 h-px ${
                    isActive && phaseData[KILL_CHAIN[i + 1].tactic].anomalyCount > 0
                      ? 'bg-white/20'
                      : 'bg-white/[0.05]'
                  }`} />
                  <div className={`w-0 h-0 border-t-[3px] border-t-transparent border-b-[3px] border-b-transparent border-l-[4px] ${
                    isActive && phaseData[KILL_CHAIN[i + 1].tactic].anomalyCount > 0
                      ? 'border-l-white/20'
                      : 'border-l-white/[0.05]'
                  }`} />
                </div>
              )}
            </div>
          )
        })}
      </div>

      {/* Expanded Phase Details */}
      {expandedPhase && phaseData[expandedPhase] && (
        <ExpandedPhase
          tactic={expandedPhase}
          data={phaseData[expandedPhase]}
          phase={KILL_CHAIN.find(p => p.tactic === expandedPhase)}
          onClose={() => setExpandedPhase(null)}
        />
      )}
    </div>
  )
}

function ExpandedPhase({ tactic, data, phase, onClose }) {
  const techniques = Object.values(data.techniques).sort((a, b) => b.count - a.count)

  return (
    <div
      className="mt-2 p-3 rounded-lg border border-white/[0.06]"
      style={{ backgroundColor: `${phase.color}08` }}
    >
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <Shield size={12} style={{ color: phase.color }} />
          <span className="text-xs font-medium text-white/70">{tactic}</span>
          <span className="text-[10px] text-white/30">
            {data.anomalyCount} Anomalien, {techniques.length} Techniken
          </span>
        </div>
        <button
          onClick={onClose}
          className="text-white/20 hover:text-white/50 transition-colors"
        >
          <ChevronDown size={14} />
        </button>
      </div>

      <div className="space-y-1">
        {techniques.map(tech => (
          <div key={tech.id} className="flex items-center gap-2 px-2 py-1 rounded hover:bg-white/[0.03] transition-colors">
            <a
              href={`https://attack.mitre.org/techniques/${tech.id.replace('.', '/')}/`}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded font-mono hover:bg-white/[0.05] transition-colors"
              style={{ color: phase.color }}
              onClick={e => e.stopPropagation()}
            >
              <Shield size={8} />
              {tech.id}
            </a>
            <span className="text-xs text-white/50 flex-1">{tech.name}</span>
            <span className="text-[10px] text-white/25 px-1.5 py-0.5 rounded-full bg-white/[0.04]">
              {tech.count}x
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}
