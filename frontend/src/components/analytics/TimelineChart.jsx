import React, { useMemo } from 'react'
import {
  ComposedChart, Area, Scatter, XAxis, YAxis, Tooltip,
  CartesianGrid, ResponsiveContainer, Cell
} from 'recharts'
import { chartColors } from '../../utils/colors'
import { formatTime } from '../../utils/formatters'

export default function TimelineChart({ timeline, anomalies }) {
  // Aggregate events by hour for area chart
  const hourlyData = useMemo(() => {
    if (!timeline?.length) return []

    const buckets = {}
    timeline.forEach(event => {
      const ts = event.timestamp || event.mtime
      if (!ts) return
      const d = new Date(ts)
      if (isNaN(d.getTime())) return
      const key = d.toISOString().slice(0, 13) // YYYY-MM-DDTHH
      if (!buckets[key]) {
        buckets[key] = { time: key, count: 0, anomalyCount: 0 }
      }
      buckets[key].count++
      if (event.is_anomaly) buckets[key].anomalyCount++
    })

    return Object.values(buckets).sort((a, b) => a.time.localeCompare(b.time))
  }, [timeline])

  // Anomaly scatter points
  const scatterData = useMemo(() => {
    if (!anomalies?.length) return []
    return anomalies.map((a, i) => {
      const ts = a.timestamp
      const d = ts ? new Date(ts) : null
      const hourKey = d && !isNaN(d.getTime()) ? d.toISOString().slice(0, 13) : null
      const hourBucket = hourlyData.find(h => h.time === hourKey)
      return {
        time: hourKey || `unknown_${i}`,
        score: (a.anomaly_score || 0) * 100,
        risk_level: a.risk_level || 'medium',
        event: a.event,
        y: hourBucket ? hourBucket.count : 0,
      }
    }).filter(d => d.time)
  }, [anomalies, hourlyData])

  if (hourlyData.length === 0) {
    return (
      <div className="glass-card h-80 flex items-center justify-center">
        <span className="text-sm text-white/20">Keine Timeline-Daten verfügbar</span>
      </div>
    )
  }

  // Farbe direkt aus dem Score ableiten (0-100%)
  const scoreToColor = (score) => {
    if (score >= 80) return chartColors.scatter.critical   // Rot
    if (score >= 60) return chartColors.scatter.high        // Orange
    if (score >= 40) return chartColors.scatter.medium      // Gelb
    return chartColors.scatter.low                          // Blau
  }

  return (
    <div className="glass-card">
      <h3 className="text-sm font-medium text-white/50 mb-4">Temporal Anomaly Engine</h3>
      <ResponsiveContainer width="100%" height={320}>
        <ComposedChart data={hourlyData} margin={{ top: 10, right: 40, bottom: 0, left: 10 }}>
          <defs>
            <linearGradient id="areaGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={chartColors.area} stopOpacity={0.3} />
              <stop offset="100%" stopColor={chartColors.area} stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke={chartColors.grid} />
          <XAxis
            dataKey="time"
            tick={{ fill: chartColors.axis, fontSize: 10 }}
            tickFormatter={(v) => v ? v.slice(11, 16) : ''}
            stroke={chartColors.grid}
          />
          <YAxis
            yAxisId="left"
            tick={{ fill: chartColors.axis, fontSize: 10 }}
            stroke={chartColors.grid}
            label={{ value: 'Events/h', angle: -90, position: 'insideLeft', fill: 'rgba(255,255,255,0.25)', fontSize: 10, dx: -5 }}
          />
          <YAxis
            yAxisId="right"
            orientation="right"
            domain={[0, 100]}
            tick={{ fill: chartColors.axis, fontSize: 10 }}
            stroke={chartColors.grid}
            tickFormatter={(v) => `${v}%`}
            label={{ value: 'Anomaly Score', angle: 90, position: 'insideRight', fill: 'rgba(255,255,255,0.25)', fontSize: 10, dx: 5 }}
          />
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
