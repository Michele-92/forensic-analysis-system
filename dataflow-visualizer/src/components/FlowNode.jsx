import React, { useState } from 'react'
import { TYPE_CFG } from '../utils/colors.js'

export default function FlowNode({ node, animDelay = 0 }) {
  const [hovered, setHovered] = useState(false)
  const [expanded, setExpanded] = useState(false)
  const cfg = TYPE_CFG[node.type] || TYPE_CFG.module
  const isFile = node.type === 'file'

  // ── Datei-Node (klein, sekundär) ────────────────────────────────────────
  if (isFile) {
    return (
      <div
        className="flow-enter flex items-center gap-2 px-3 py-2 rounded-lg"
        style={{
          animationDelay: `${animDelay}ms`,
          background: `rgba(${cfg.rgb}, 0.05)`,
          border: `1px solid rgba(${cfg.rgb}, 0.18)`,
          minWidth: '148px',
        }}
      >
        <span className="text-sm">{node.icon || '📄'}</span>
        <div>
          <div className="text-[11px] font-mono font-medium" style={{ color: cfg.color }}>
            {node.name}
          </div>
          {node.sub && (
            <div className="text-[10px] text-white/30 mt-0.5">{node.sub}</div>
          )}
        </div>
      </div>
    )
  }

  // ── Normaler Node ────────────────────────────────────────────────────────
  return (
    <div
      className="flow-enter relative rounded-2xl flex-1 transition-all duration-300"
      style={{
        animationDelay: `${animDelay}ms`,
        minWidth: '220px',
        maxWidth: '340px',
      }}
    >
      {/* Haupt-Card */}
      <div
        className="rounded-2xl cursor-pointer transition-all duration-300"
        style={{
          background: hovered ? `rgba(${cfg.rgb}, 0.10)` : `rgba(${cfg.rgb}, 0.05)`,
          border: `1px solid rgba(${cfg.rgb}, ${expanded ? '0.5' : hovered ? '0.4' : '0.22'})`,
          boxShadow: hovered
            ? `0 0 32px rgba(${cfg.rgb}, 0.15), inset 0 0 20px rgba(${cfg.rgb}, 0.05)`
            : `0 0 12px rgba(${cfg.rgb}, 0.04)`,
          transform: hovered ? 'translateY(-2px)' : 'translateY(0)',
        }}
        onMouseEnter={() => setHovered(true)}
        onMouseLeave={() => setHovered(false)}
        onClick={() => node.explain && setExpanded(e => !e)}
      >
        {/* Typ-Badge */}
        <div
          className="absolute -top-3 left-4 text-[10px] font-semibold px-2.5 py-0.5 rounded-full tracking-wider uppercase"
          style={{
            background: `rgba(${cfg.rgb}, 0.15)`,
            color: cfg.color,
            border: `1px solid rgba(${cfg.rgb}, 0.3)`,
          }}
        >
          {cfg.icon}  {cfg.label}
        </div>

        {/* Inhalt */}
        <div className="px-4 pt-5 pb-3">
          <div className="flex items-start gap-2.5">
            {/* Pulsierender Dot */}
            <div className="relative flex-shrink-0 mt-1">
              <div
                className="w-2 h-2 rounded-full"
                style={{ background: cfg.color, boxShadow: `0 0 8px ${cfg.color}` }}
              />
              {hovered && (
                <div
                  className="absolute inset-0 rounded-full"
                  style={{ background: cfg.color, animation: 'pulse-ring 1.2s ease-out infinite' }}
                />
              )}
            </div>

            <div className="min-w-0 flex-1">
              {/* Name */}
              <div
                className="text-sm font-semibold font-mono leading-snug transition-colors duration-200"
                style={{ color: hovered ? cfg.color : 'rgba(255,255,255,0.85)' }}
              >
                {node.icon && <span className="mr-1.5">{node.icon}</span>}
                {node.name}
              </div>

              {/* Sub-Info */}
              {node.sub && (
                <div className="text-[11px] text-white/45 mt-1 leading-relaxed">
                  {node.sub}
                </div>
              )}

              {/* Dateipfad */}
              {node.file && (
                <div
                  className="text-[10px] font-mono mt-2 truncate px-2 py-0.5 rounded"
                  style={{
                    color: `rgba(${cfg.rgb}, 0.55)`,
                    background: `rgba(${cfg.rgb}, 0.07)`,
                  }}
                >
                  {node.file}
                </div>
              )}
            </div>
          </div>

          {/* Erklärung-Toggle Hinweis */}
          {node.explain && (
            <div
              className="flex items-center gap-1.5 mt-3 pt-2.5 transition-all duration-200"
              style={{ borderTop: `1px solid rgba(${cfg.rgb}, 0.1)` }}
            >
              <span
                className="text-[10px] font-medium transition-colors duration-200"
                style={{ color: expanded ? cfg.color : 'rgba(255,255,255,0.25)' }}
              >
                {expanded ? '▲ Erklärung ausblenden' : '▼ Erklärung anzeigen'}
              </span>
            </div>
          )}
        </div>
      </div>

      {/* Aufklappbare Erklärung */}
      {expanded && node.explain && (
        <div
          className="flow-enter mt-2 px-4 py-3 rounded-xl text-xs text-white/60 leading-relaxed"
          style={{
            background: `rgba(${cfg.rgb}, 0.06)`,
            border: `1px solid rgba(${cfg.rgb}, 0.15)`,
            borderLeft: `3px solid rgba(${cfg.rgb}, 0.5)`,
            animationDuration: '0.2s',
          }}
        >
          <div
            className="text-[10px] font-semibold uppercase tracking-wider mb-1.5"
            style={{ color: cfg.color }}
          >
            💡 Was passiert hier?
          </div>
          {node.explain}
        </div>
      )}
    </div>
  )
}
