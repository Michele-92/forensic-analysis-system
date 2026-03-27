/**
 * ============================================================================
 * FINDINGS CARDS — Karten-Ansicht der wichtigsten Anomalie-Befunde
 * ============================================================================
 * Zeigt die Top-6 Anomalien (nach Anomalie-Score absteigend sortiert) als
 * Grid-Karten an. Jede Karte enthält:
 *   - Risk-Level Badge (critical / high / medium / low)
 *   - Anomalie-Score (farbcodiert via getScoreColor)
 *   - Event-Beschreibung
 *   - Optionale Erklärung (LLM-generiert)
 *   - Indicator-Tags (verdächtige Artefakte)
 *   - MITRE ATT&CK Technik-IDs (max. 3)
 *   - Footer: Event-ID + Zeitstempel
 *
 * Props:
 *   anomalies — Array aller Anomalie-Objekte aus data.anomalies
 *
 * Abhängigkeiten:
 *   RiskBadge, formatters (formatScore, formatTimestamp), colors (getRiskColor, getScoreColor)
 *
 * @component
 */
import React from 'react'
import RiskBadge from '../RiskBadge'
import { formatScore, formatTimestamp } from '../../utils/formatters'
import { getRiskColor, getScoreColor } from '../../utils/colors'

// ── Hauptkomponente ───────────────────────────────────────────────────────────

/**
 * Rendert ein responsives Grid mit den Top-6 Anomalie-Befundkarten.
 * Die Sortierung nach `anomaly_score` (absteigend) stellt sicher, dass die
 * kritischsten Befunde zuerst angezeigt werden.
 *
 * @param {Object[]} anomalies - Array der Anomalie-Objekte vom Backend
 * @param {string}   anomalies[].event_id          - Eindeutige ID des Events
 * @param {number}   anomalies[].anomaly_score      - Score 0.0–1.0 (höher = kritischer)
 * @param {string}   anomalies[].risk_level         - "critical" | "high" | "medium" | "low"
 * @param {string}   anomalies[].event              - Kurzbeschreibung des Events
 * @param {string}   [anomalies[].explanation]      - LLM-generierte Erklärung (optional)
 * @param {string[]} [anomalies[].indicators]       - Liste auffälliger Artefakte (optional)
 * @param {Object[]} [anomalies[].mitre_techniques] - MITRE ATT&CK Techniken (optional)
 * @param {string}   anomalies[].timestamp          - ISO-Zeitstempel des Events
 */
export default function FindingsCards({ anomalies }) {
  // Absteigende Sortierung nach Score, dann auf Top-6 beschränken
  const sorted = [...anomalies].sort((a, b) => (b.anomaly_score || 0) - (a.anomaly_score || 0))
  const top = sorted.slice(0, 6)

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
      {top.map((anomaly, i) => {
        // Farbe des Scores dynamisch ermitteln (rot bei hohem Score)
        const scoreColor = getScoreColor(anomaly.anomaly_score)
        return (
          <div key={anomaly.event_id || i} className="glass-card group">
            {/* Header: Risk-Badge links, Score rechts */}
            <div className="flex items-start justify-between mb-3">
              <RiskBadge level={anomaly.risk_level || 'medium'} size="xs" />
              <span className="text-xs font-mono" style={{ color: scoreColor.hex }}>
                {formatScore(anomaly.anomaly_score)}
              </span>
            </div>

            {/* Event-Beschreibung */}
            <p className="text-sm text-white/80 font-medium mb-2 leading-snug">
              {anomaly.event}
            </p>

            {/* LLM-generierte Erklärung (optional) */}
            {anomaly.explanation && (
              <p className="text-xs text-white/40 mb-3 leading-relaxed">
                {anomaly.explanation}
              </p>
            )}

            {/* Indicator-Tags: verdächtige Artefakte als Mono-Chips */}
            {anomaly.indicators?.length > 0 && (
              <div className="flex flex-wrap gap-1 mb-3">
                {anomaly.indicators.map((ind, j) => (
                  <span key={j} className="text-[10px] px-1.5 py-0.5 rounded bg-white/[0.05] text-white/40 font-mono">
                    {ind}
                  </span>
                ))}
              </div>
            )}

            {/* MITRE ATT&CK Technik-IDs (max. 3, Tooltip zeigt Name + Taktik) */}
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

            {/* Footer: Event-ID und Zeitstempel */}
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
