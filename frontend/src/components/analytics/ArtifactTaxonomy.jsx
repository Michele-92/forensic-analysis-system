import React, { useMemo } from 'react'
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts'
import { eventTypeColors } from '../../utils/colors'

export default function ArtifactTaxonomy({ timeline }) {
  const typeData = useMemo(() => {
    if (!timeline?.length) return []

    const counts = {}
    timeline.forEach(event => {
      const type = event.event_type || event.type || 'unknown'
      counts[type] = (counts[type] || 0) + 1
    })

    return Object.entries(counts)
      .map(([name, value]) => ({ name, value, color: eventTypeColors[name] || '#4b5563' }))
      .sort((a, b) => b.value - a.value)
  }, [timeline])

  if (typeData.length === 0) {
    return (
      <div className="glass-card h-80 flex items-center justify-center">
        <span className="text-sm text-white/20">Keine Artefakt-Daten</span>
      </div>
    )
  }

  const total = typeData.reduce((sum, d) => sum + d.value, 0)

  return (
    <div className="glass-card flex flex-col" style={{ minHeight: 380 }}>
      <h3 className="text-sm font-medium text-white/50 mb-4">Artefakt-Taxonomie</h3>
      {/* Pie Chart — feste Hoehe, kein Clipping */}
      <div className="flex-shrink-0" style={{ height: 230 }}>
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={typeData}
              cx="50%"
              cy="50%"
              innerRadius={60}
              outerRadius={100}
              paddingAngle={2}
              dataKey="value"
            >
              {typeData.map((entry, i) => (
                <Cell key={i} fill={entry.color} stroke="transparent" />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                backgroundColor: 'rgba(0,0,0,0.9)',
                border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: '12px',
                padding: '8px 12px',
              }}
              itemStyle={{ color: 'rgba(255,255,255,0.8)', fontSize: 12 }}
              formatter={(value, name) => [value, name]}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>
      {/* Legende — scrollbar wenn zu viele Eintraege */}
      <div className="flex-1 overflow-y-auto mt-2" style={{ maxHeight: 140 }}>
        <div className="flex flex-wrap gap-x-4 gap-y-1 px-1">
          {typeData.map((entry, i) => (
            <div key={i} className="flex items-center gap-1.5">
              <div
                className="w-2.5 h-2.5 rounded-sm flex-shrink-0"
                style={{ backgroundColor: entry.color }}
              />
              <span className="text-[11px] text-white/50 whitespace-nowrap">
                {entry.name}
              </span>
              <span className="text-[10px] text-white/25">
                {entry.value}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
