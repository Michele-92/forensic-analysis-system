import React from 'react'
import RiskBadge from '../RiskBadge'
import { formatScore, formatTimestamp } from '../../utils/formatters'
import { getRiskColor, getScoreColor } from '../../utils/colors'

export default function FindingsCards({ anomalies }) {
  const sorted = [...anomalies].sort((a, b) => (b.anomaly_score || 0) - (a.anomaly_score || 0))
  const top = sorted.slice(0, 6)

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
      {top.map((anomaly, i) => {
        const scoreColor = getScoreColor(anomaly.anomaly_score)
        return (
          <div key={anomaly.event_id || i} className="glass-card group">
            {/* Header */}
            <div className="flex items-start justify-between mb-3">
              <RiskBadge level={anomaly.risk_level || 'medium'} size="xs" />
              <span className="text-xs font-mono" style={{ color: scoreColor.hex }}>
                {formatScore(anomaly.anomaly_score)}
              </span>
            </div>

            {/* Event */}
            <p className="text-sm text-white/80 font-medium mb-2 leading-snug">
              {anomaly.event}
            </p>

            {/* Explanation */}
            {anomaly.explanation && (
              <p className="text-xs text-white/40 mb-3 leading-relaxed">
                {anomaly.explanation}
              </p>
            )}

            {/* Indicators */}
            {anomaly.indicators?.length > 0 && (
              <div className="flex flex-wrap gap-1 mb-3">
                {anomaly.indicators.map((ind, j) => (
                  <span key={j} className="text-[10px] px-1.5 py-0.5 rounded bg-white/[0.05] text-white/40 font-mono">
                    {ind}
                  </span>
                ))}
              </div>
            )}

            {/* MITRE ATT&CK */}
            {anomaly.mitre_techniques?.length > 0 && (
              <div className="flex flex-wrap gap-1 mb-3">
                {anomaly.mitre_techniques.slice(0, 3).map((tech, j) => (
                  <span
                    key={j}
                    className="inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded bg-accent-purple/10 text-accent-purple font-mono"
                    title={`${tech.name} (${tech.tactic})`}
                  >
                    {tech.id}
                  </span>
                ))}
              </div>
            )}

            {/* Footer */}
            <div className="flex items-center justify-between pt-2 border-t border-white/[0.04]">
              <span className="text-[10px] text-white/25 font-mono">
                {anomaly.event_id}
              </span>
              <span className="text-[10px] text-white/25 font-mono">
                {formatTimestamp(anomaly.timestamp)}
              </span>
            </div>
          </div>
        )
      })}
    </div>
  )
}
