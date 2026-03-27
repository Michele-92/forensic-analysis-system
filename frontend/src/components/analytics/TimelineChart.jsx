/**
 * ============================================================================
 * TIMELINE CHART — Temporal Anomaly Engine
 * ============================================================================
 * Visualisiert forensische Events und Anomalien auf einer gemeinsamen
 * Zeitachse mittels eines Recharts ComposedChart:
 *
 *   - Area-Chart (linke Y-Achse): Stündlich aggregierte Event-Dichte
 *     (Events pro Stunde). Gibt einen schnellen Überblick über Aktivitäts-
 *     peaks im Untersuchungszeitraum.
 *
 *   - Scatter-Chart (rechte Y-Achse): Anomalie-Punkte mit Anomaly-Score
 *     (0–100%). Jeder Punkt ist farbkodiert nach Schweregrad:
 *       · Rot    ≥ 80% — Kritisch
 *       · Orange ≥ 60% — Hoch
 *       · Gelb   ≥ 40% — Mittel
 *       · Blau   < 40% — Niedrig
 *
 * Props:
 * @param {Object[]} timeline  - Normalisierte Event-Liste (aus DataNormalizer)
 * @param {Object[]} anomalies - Anomalien mit anomaly_score und timestamp
 *
 * Abhängigkeiten:
 *   - recharts (ComposedChart, Area, Scatter, …)
 *   - utils/colors (chartColors)
 *   - utils/formatters (formatTime)
 *
 * @component
 */
import React, { useMemo } from 'react'
import {
  ComposedChart, Area, Scatter, XAxis, YAxis, Tooltip,
  CartesianGrid, ResponsiveContainer, Cell
} from 'recharts'
import { chartColors } from '../../utils/colors'
import { formatTime } from '../../utils/formatters'

// ── Hauptkomponente ────────────────────────────────────────────────────────────

/**
 * Kombinierter Chart: Area (Event-Dichte) + Scatter (Anomalie-Scores).
 *
 * @param {Object[]} timeline  - Vollständige normalisierte Event-Liste
 * @param {Object[]} anomalies - Gefilterte Anomalie-Liste mit Scores
 */
export default function TimelineChart({ timeline, anomalies }) {

  // ── Datenaggregation ──────────────────────────────────────────────────────

  /**
   * Aggregiert alle Timeline-Events in Stunden-Buckets (YYYY-MM-DDTHH).
   * Jeder Bucket enthält `count` (Gesamt-Events) und `anomalyCount`
   * (Events die als Anomalie markiert sind, via `is_anomaly` Flag).
   * Das Ergebnis ist nach Zeitstempel aufsteigend sortiert.
   */
  const hourlyData = useMemo(() => {
    if (!timeline?.length) return []

    const buckets = {}
    timeline.forEach(event => {
      const ts = event.timestamp || event.mtime
      if (!ts) return
      const d = new Date(ts)
      if (isNaN(d.getTime())) return
      // ISO-String auf Stunden-Granularität kürzen: "2024-03-15T14"
      const key = d.toISOString().slice(0, 13) // YYYY-MM-DDTHH
      if (!buckets[key]) {
        buckets[key] = { time: key, count: 0, anomalyCount: 0 }
      }
      buckets[key].count++
      if (event.is_anomaly) buckets[key].anomalyCount++
    })

    return Object.values(buckets).sort((a, b) => a.time.localeCompare(b.time))
  }, [timeline])

  /**
   * Bereitet Anomalien als Scatter-Datenpunkte auf.
   * Jeder Punkt wird dem entsprechenden Stunden-Bucket zugeordnet,
   * damit er auf der X-Achse korrekt positioniert wird.
   * Der `y`-Wert (rechte Achse) ist der skalierte Anomaly-Score (0–100).
   */
  const scatterData = useMemo(() => {
    if (!anomalies?.length) return []
    return anomalies.map((a, i) => {
      const ts = a.timestamp
      const d = ts ? new Date(ts) : null
      const hourKey = d && !isNaN(d.getTime()) ? d.toISOString().slice(0, 13) : null
      // Zugehörigen Stunden-Bucket suchen, um y-Koordinate zu ermitteln
      const hourBucket = hourlyData.find(h => h.time === hourKey)
      return {
        time: hourKey || `unknown_${i}`,
        score: (a.anomaly_score || 0) * 100,
        risk_level: a.risk_level || 'medium',
        event: a.event,
        // y-Wert: Scatter-Punkt liegt auf der rechten Achse (Score 0–100)
        y: hourBucket ? hourBucket.count : 0,
      }
    }).filter(d => d.time)
  }, [anomalies, hourlyData])

  // ── Empty State ───────────────────────────────────────────────────────────

  if (hourlyData.length === 0) {
    return (
      <div className="glass-card h-80 flex items-center justify-center">
        <span className="text-sm text-white/20">Keine Timeline-Daten verfügbar</span>
      </div>
    )
  }

  // ── Hilfsfunktionen ───────────────────────────────────────────────────────

  /**
   * Mappt einen numerischen Anomaly-Score (0–100) auf eine Hex-Farbe.
   * Schwellenwerte orientieren sich an den vier Risikostufen des Systems.
   *
   * @param {number} score - Anomaly-Score in Prozent (0–100)
   * @returns {string} CSS-Farbe aus chartColors
   */
  const scoreToColor = (score) => {
    if (score >= 80) return chartColors.scatter.critical   // Rot
    if (score >= 60) return chartColors.scatter.high        // Orange
    if (score >= 40) return chartColors.scatter.medium      // Gelb
    return chartColors.scatter.low                          // Blau
  }

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="glass-card">
      <h3 className="text-sm font-medium text-white/50 mb-4">Temporal Anomaly Engine</h3>
      <ResponsiveContainer width="100%" height={320}>
        <ComposedChart data={hourlyData} margin={{ top: 10, right: 40, bottom: 0, left: 10 }}>
          {/* SVG-Gradient für den Area-Fill (transparent nach unten) */}
          <defs>
            <linearGradient id="areaGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={chartColors.area} stopOpacity={0.3} />
              <stop offset="100%" stopColor={chartColors.area} stopOpacity={0} />
            </linearGradient>
          </defs>

          <CartesianGrid strokeDasharray="3 3" stroke={chartColors.grid} />

          {/* X-Achse: Stunden-Timestamps, nur HH:MM angezeigt */}
          <XAxis
            dataKey="time"
            tick={{ fill: chartColors.axis, fontSize: 10 }}
            tickFormatter={(v) => v ? v.slice(11, 16) : ''}
            stroke={chartColors.grid}
          />

          {/* Linke Y-Achse: absolute Event-Anzahl pro Stunde */}
          <YAxis
            yAxisId="left"
            tick={{ fill: chartColors.axis, fontSize: 10 }}
            stroke={chartColors.grid}
            label={{ value: 'Events/h', angle: -90, position: 'insideLeft', fill: 'rgba(255,255,255,0.25)', fontSize: 10, dx: -5 }}
          />

          {/* Rechte Y-Achse: Anomaly-Score in Prozent (0–100%) */}
          <YAxis
            yAxisId="right"
            orientation="right"
            domain={[0, 100]}
            tick={{ fill: chartColors.axis, fontSize: 10 }}
            stroke={chartColors.grid}
            tickFormatter={(v) => `${v}%`}
            label={{ value: 'Anomaly Score', angle: 90, position: 'insideRight', fill: 'rgba(255,255,255,0.25)', fontSize: 10, dx: 5 }}
          />

          {/* Tooltip: formatiert Timestamp als "YYYY-MM-DD HH:MM Uhr" */}
          <Tooltip
            contentStyle={{
              backgroundColor: chartColors.tooltip,
              border: '1px solid rgba(255,255,255,0.1)',
              borderRadius: '12px',
              padding: '8px 12px',
              backdropFilter: 'blur(20px)',
            }}
            labelStyle={{ color: 'rgba(255,255,255,0.6)', fontSize: 11 }}
            itemStyle={{ color: 'rgba(255,255,255,0.8)', fontSize: 11 }}
            labelFormatter={(v) => v ? `${v.slice(0, 10)} ${v.slice(11, 16)} Uhr` : ''}
          />

          {/* Area: Event-Dichte mit Glow-Effekt via drop-shadow */}
          <Area
            yAxisId="left"
            type="monotone"
            dataKey="count"
            stroke={chartColors.area}
            strokeWidth={2}
            fill="url(#areaGradient)"
            name="Events"
            style={{ filter: 'drop-shadow(0 0 6px rgba(59, 130, 246, 0.3))' }}
          />

          {/* Scatter: Anomalie-Punkte, individuell eingefärbt nach Score */}
          <Scatter yAxisId="right" data={scatterData} dataKey="score" name="Anomalien">
            {scatterData.map((entry, i) => (
              <Cell
                key={i}
                fill={scoreToColor(entry.score)}
                style={{ filter: `drop-shadow(0 0 8px ${scoreToColor(entry.score)})` }}
              />
            ))}
          </Scatter>
        </ComposedChart>
      </ResponsiveContainer>
    </div>
  )
}
