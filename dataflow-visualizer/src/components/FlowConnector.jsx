import React from 'react'
import { TYPE_CFG } from '../utils/colors.js'

export default function FlowConnector({ label, toType = 'module', delay = 0 }) {
  const cfg = TYPE_CFG[toType] || TYPE_CFG.module
  const { color, rgb } = cfg

  return (
    <div className="flex flex-col items-center py-0.5" style={{ animationDelay: `${delay}ms` }}>
      {/* Vertikale Linie mit Partikel */}
      <div className="relative flex flex-col items-center">
        {/* Linie */}
        <div
          className="w-px relative overflow-visible"
          style={{
            height: label ? '40px' : '32px',
            background: `linear-gradient(to bottom, rgba(${rgb},0.5), rgba(${rgb},0.1))`,
          }}
        >
          {/* Animierter Partikel */}
          <div
            className="particle-down w-2 h-2 left-1/2 -translate-x-1/2"
            style={{
              background: color,
              boxShadow: `0 0 10px ${color}, 0 0 20px rgba(${rgb},0.4)`,
              animationDelay: `${delay}ms`,
              animationDuration: '1.4s',
            }}
          />
          {/* Zweiter Partikel versetzt */}
          <div
            className="particle-down w-1.5 h-1.5 left-1/2 -translate-x-1/2"
            style={{
              background: color,
              opacity: 0.5,
              boxShadow: `0 0 6px ${color}`,
              animationDelay: `${delay + 700}ms`,
              animationDuration: '1.4s',
            }}
          />
        </div>

        {/* Pfeilspitze */}
        <svg width="12" height="7" viewBox="0 0 12 7" fill="none">
          <path
            d="M1 1L6 6L11 1"
            stroke={color}
            strokeWidth="1.5"
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeOpacity="0.7"
          />
        </svg>
      </div>

      {/* Label */}
      {label && (
        <div
          className="text-[10px] font-mono mt-1.5 px-2.5 py-0.5 rounded-full whitespace-nowrap max-w-xs text-center truncate"
          style={{
            color: `rgba(${rgb}, 0.7)`,
            background: `rgba(${rgb}, 0.06)`,
            border: `1px solid rgba(${rgb}, 0.15)`,
          }}
        >
          {label}
        </div>
      )}
    </div>
  )
}
