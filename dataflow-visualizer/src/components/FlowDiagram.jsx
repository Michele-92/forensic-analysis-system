import React, { useState, useEffect } from 'react'
import FlowNode from './FlowNode.jsx'
import FlowConnector from './FlowConnector.jsx'
import { TYPE_CFG } from '../utils/colors.js'

export default function FlowDiagram({ flow }) {
  const [visibleRows, setVisibleRows] = useState(flow.rows.length)
  const [playing, setPlaying] = useState(false)

  // Dominante Farbe einer Row (erster Nicht-Datei-Node)
  const rowColor = (nodes) => {
    const n = nodes.find(n => n.type !== 'file') || nodes[0]
    return TYPE_CFG[n?.type]?.color || '#818cf8'
  }

  const rowType = (nodes) => {
    const n = nodes.find(n => n.type !== 'file') || nodes[0]
    return n?.type || 'module'
  }

  // Animated playback — Rows nacheinander aufdecken
  const handlePlay = () => {
    setVisibleRows(0)
    setPlaying(true)
    let i = 0
    const interval = setInterval(() => {
      i++
      setVisibleRows(i)
      if (i >= flow.rows.length) {
        clearInterval(interval)
        setPlaying(false)
      }
    }, 600)
  }

  // Reset wenn anderer Flow gewählt
  useEffect(() => {
    setVisibleRows(flow.rows.length)
    setPlaying(false)
  }, [flow.id])

  return (
    <div className="max-w-4xl mx-auto px-4 pb-16">

      {/* ── Flow Header ── */}
      <div className="text-center mb-10">
        <div
          className="inline-flex items-center justify-center w-16 h-16 rounded-2xl text-3xl mb-4"
          style={{
            background: 'rgba(129,140,248,0.1)',
            border: '1px solid rgba(129,140,248,0.2)',
            animation: 'float 3s ease-in-out infinite',
          }}
        >
          {flow.emoji}
        </div>
        <h2 className="text-2xl font-bold text-white/90 mb-2">{flow.title}</h2>
        <p className="text-sm text-white/35 max-w-lg mx-auto leading-relaxed">{flow.description}</p>

        {/* Play-Button */}
        <button
          onClick={handlePlay}
          disabled={playing}
          className="mt-5 inline-flex items-center gap-2 px-5 py-2 rounded-full text-sm font-medium transition-all duration-200"
          style={{
            background: playing ? 'rgba(255,255,255,0.04)' : 'rgba(129,140,248,0.15)',
            border: `1px solid ${playing ? 'rgba(255,255,255,0.08)' : 'rgba(129,140,248,0.35)'}`,
            color: playing ? 'rgba(255,255,255,0.3)' : '#818cf8',
            cursor: playing ? 'not-allowed' : 'pointer',
          }}
        >
          <span>{playing ? '⏳' : '▶'}</span>
          {playing ? 'Lädt…' : 'Flow animieren'}
        </button>
      </div>

      {/* ── Steps ── */}
      <div className="flex flex-col items-center gap-0">
        {flow.rows.map((row, rowIdx) => {
          if (rowIdx >= visibleRows) return null

          const isLast = !row.arrow
          const nextRow = flow.rows[rowIdx + 1]
          const connType = nextRow ? rowType(nextRow.nodes) : rowType(row.nodes)
          const nodeDelay = rowIdx * 80

          return (
            <React.Fragment key={rowIdx}>
              {/* ── Row ── */}
              <div
                className="flex gap-3 items-stretch justify-center flex-wrap w-full"
                style={{ maxWidth: '860px' }}
              >
                {row.nodes.map((node, nodeIdx) => (
                  <FlowNode
                    key={nodeIdx}
                    node={node}
                    animDelay={nodeDelay + nodeIdx * 60}
                  />
                ))}
              </div>

              {/* ── Connector ── */}
              {!isLast && rowIdx + 1 < visibleRows && (
                <FlowConnector
                  label={row.arrow?.label}
                  toType={connType}
                  delay={nodeDelay + 120}
                />
              )}
            </React.Fragment>
          )
        })}
      </div>

      {/* ── Abschluss-Indikator ── */}
      {visibleRows >= flow.rows.length && (
        <div
          className="flow-enter text-center mt-8"
          style={{ animationDelay: `${flow.rows.length * 80 + 200}ms` }}
        >
          <div
            className="inline-flex items-center gap-2 text-xs px-4 py-2 rounded-full"
            style={{
              background: 'rgba(52,211,153,0.08)',
              border: '1px solid rgba(52,211,153,0.2)',
              color: '#34d399',
            }}
          >
            <span style={{ animation: 'pulse-ring 2s ease-out infinite' }}>✓</span>
            Flow abgeschlossen · {flow.rows.length} Schritte
          </div>
        </div>
      )}
    </div>
  )
}
