/**
 * ============================================================================
 * ARTIFACT TAXONOMY — Artefakt-Typ-Verteilung (Donut Chart)
 * ============================================================================
 * Zeigt die Verteilung der forensischen Artefakt-Typen als interaktives
 * Donut-Diagramm (Recharts PieChart mit innerRadius).
 *
 * Die Komponente:
 *   1. Zählt alle Events pro `event_type` (fällt auf `type` zurück).
 *   2. Sortiert Typen absteigend nach Häufigkeit.
 *   3. Weist jedem Typ eine vordefinierte Farbe aus eventTypeColors zu
 *      (unbekannte Typen erhalten ein neutrales Grau).
 *   4. Rendert Donut-Chart + scrollbare Legende darunter.
 *
 * Props:
 * @param {Object[]} timeline - Normalisierte Event-Liste (aus DataNormalizer)
 *
 * Abhängigkeiten:
 *   - recharts (PieChart, Pie, Cell, ResponsiveContainer, Tooltip)
 *   - utils/colors (eventTypeColors)
 *
 * @component
 */
import React, { useMemo } from 'react'
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts'
import { eventTypeColors } from '../../utils/colors'

// ── Hauptkomponente ────────────────────────────────────────────────────────────

/**
 * Donut-Chart der Artefakt-Typ-Verteilung mit scrollbarer Legende.
 *
 * @param {Object[]} timeline - Normalisierte Event-Liste
 */
export default function ArtifactTaxonomy({ timeline }) {

  // ── Datenaggregation ──────────────────────────────────────────────────────

  /**
   * Zählt Events pro Typ und reichert jeden Eintrag mit der
   * konfigurierten Farbe an. Sortierung: häufigster Typ zuerst.
   *
   * Ergebnis: Array von { name: string, value: number, color: string }
   */
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

  // ── Empty State ───────────────────────────────────────────────────────────

  if (typeData.length === 0) {
    return (
      <div className="glass-card h-80 flex items-center justify-center">
        <span className="text-sm text-white/20">Keine Artefakt-Daten</span>
      </div>
    )
  }

  /** Gesamtzahl aller Events — wird für prozentuale Berechnungen benötigt */
  const total = typeData.reduce((sum, d) => sum + d.value, 0)

  // ── Render ────────────────────────────────────────────────────────────────

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
              innerRadius={60}   /* Donut-Loch */
              outerRadius={100}
              paddingAngle={2}   /* Kleiner Abstand zwischen Segmenten */
              dataKey="value"
            >
              {/* Jedes Segment bekommt seine artefakttyp-spezifische Farbe */}
              {typeData.map((entry, i) => (
                <Cell key={i} fill={entry.color} stroke="transparent" />
              ))}
            </Pie>
            {/* Tooltip zeigt absoluten Zählwert und Typ-Name */}
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
              {/* Farb-Quadrat entspricht dem Segment im Donut */}
              <div
                className="w-2.5 h-2.5 rounded-sm flex-shrink-0"
                style={{ backgroundColor: entry.color }}
              />
              <span className="text-[11px] text-white/50 whitespace-nowrap">
                {entry.name}
              </span>
              {/* Absoluter Zählwert neben dem Label */}
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
