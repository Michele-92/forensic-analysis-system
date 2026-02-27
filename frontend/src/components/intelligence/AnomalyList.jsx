import React, { useState } from 'react'
import RiskBadge from '../RiskBadge'
import { formatScore, formatTimestamp } from '../../utils/formatters'
import { getScoreColor } from '../../utils/colors'
import { ChevronDown, ChevronRight, Shield } from 'lucide-react'

export default function AnomalyList({ anomalies, filterTactics }) {
  if (!anomalies?.length) {
    return (
      <div className="glass-card flex items-center justify-center h-40">
        <span className="text-sm text-white/20">Keine Anomalien erkannt</span>
      </div>
    )
  }

  // Optional: Nur Anomalien mit bestimmten MITRE-Taktiken anzeigen
  const filtered = filterTactics
    ? anomalies.filter(a =>
        (a.mitre_techniques || []).some(t => filterTactics.has(t.tactic))
      )
    : anomalies

  if (filterTactics && filtered.length === 0) return null

  const sorted = [...filtered].sort((a, b) => (b.anomaly_score || 0) - (a.anomaly_score || 0))

  return (
    <div className="glass-card p-0">
      <div className="p-4 border-b border-white/[0.04]">
        <h3 className="text-sm font-medium text-white/50">
          Anomalien ({filtered.length}{filterTactics ? ` / ${anomalies.length} gefiltert` : ''})
        </h3>
      </div>
      <div className="divide-y divide-white/[0.03]">
        {sorted.map((anomaly, i) => (
          <AnomalyItem key={anomaly.event_id || i} anomaly={anomaly} />
        ))}
      </div>
    </div>
  )
}

function AnomalyItem({ anomaly }) {
  const [expanded, setExpanded] = useState(false)
  const scoreColor = getScoreColor(anomaly.anomaly_score)
  const scorePercent = Math.round((anomaly.anomaly_score || 0) * 100)

  return (
    <div
      className="px-4 py-3 hover:bg-white/[0.02] transition-colors cursor-pointer"
      onClick={() => setExpanded(!expanded)}
    >
      {/* Main Row */}
      <div className="flex items-center gap-3">
        <div className="flex-shrink-0 text-white/20">
          {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        </div>

        {/* Score bar */}
        <div className="w-10 flex-shrink-0">
          <div className="h-1.5 bg-white/[0.04] rounded-full overflow-hidden">
            <div
              className="h-full rounded-full transition-all"
              style={{ width: `${scorePercent}%`, backgroundColor: scoreColor.hex }}
            />
          </div>
          <span className="text-[10px] font-mono block text-center mt-0.5" style={{ color: scoreColor.hex }}>
            {formatScore(anomaly.anomaly_score)}
          </span>
        </div>

        {/* Risk badge */}
        <RiskBadge level={anomaly.risk_level} size="xs" />

        {/* Event */}
        <span className="flex-1 text-xs text-white/70 truncate">{anomaly.event}</span>

        {/* Timestamp */}
        <span className="text-[10px] text-white/25 font-mono flex-shrink-0">
          {formatTimestamp(anomaly.timestamp)}
        </span>
      </div>

      {/* Expanded Details */}
      {expanded && (
        <div className="mt-3 ml-8 space-y-3">
          {/* Explanation */}
          {anomaly.explanation && (
            <p className="text-xs text-white/40 leading-relaxed">{anomaly.explanation}</p>
          )}

          {/* Indicators */}
          {anomaly.indicators?.length > 0 && (
            <div>
              <span className="text-[10px] text-white/25 uppercase tracking-wider block mb-1">Indikatoren</span>
              <div className="flex flex-wrap gap-1">
                {anomaly.indicators.map((ind, j) => (
                  <span key={j} className="text-[10px] px-2 py-0.5 rounded-full bg-white/[0.04] text-white/50 font-mono">
                    {ind}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* MITRE ATT&CK */}
          {anomaly.mitre_techniques?.length > 0 && (
            <div>
              <span className="text-[10px] text-white/25 uppercase tracking-wider block mb-1">MITRE ATT&CK</span>
              <div className="flex flex-wrap gap-1">
                {anomaly.mitre_techniques.map((tech, j) => (
                  <a
                    key={j}
                    href={`https://attack.mitre.org/techniques/${tech.id.replace('.', '/')}/`}
                    target="_blank"
                    rel="noopener noreferrer"
                    onClick={(e) => e.stopPropagation()}
                    className="inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded bg-accent-purple/10 text-accent-purple font-mono hover:bg-accent-purple/20 transition-colors"
                    title={`${tech.name} (${tech.tactic})`}
                  >
                    <Shield size={8} />
                    {tech.id}
                  </a>
                ))}
              </div>
            </div>
          )}

          {/* Recommended Actions */}
          {anomaly.recommended_actions?.length > 0 && (
            <div>
              <span className="text-[10px] text-white/25 uppercase tracking-wider block mb-1">Empfohlene Aktionen</span>
              <ul className="space-y-1">
                {anomaly.recommended_actions.map((action, j) => (
                  <li key={j} className="flex items-start gap-2 text-xs text-white/40">
                    <span className="text-accent-green mt-0.5">›</span>
                    {action}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Event ID */}
          <div className="flex items-center gap-2">
            <span className="text-[10px] text-white/20">Event ID:</span>
            <code className="text-[10px] font-mono text-white/30">{anomaly.event_id}</code>
            {anomaly.confidence && (
              <>
                <span className="text-[10px] text-white/20 ml-2">Confidence:</span>
                <span className="text-[10px] text-white/30">{anomaly.confidence}</span>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
