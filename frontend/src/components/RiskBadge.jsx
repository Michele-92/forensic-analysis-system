import React from 'react'
import { getRiskColor } from '../utils/colors'

export default function RiskBadge({ level, size = 'sm' }) {
  const color = getRiskColor(level)
  const sizeClasses = {
    xs: 'text-[10px] px-1.5 py-0.5',
    sm: 'text-xs px-2 py-0.5',
    md: 'text-sm px-2.5 py-1',
  }

  return (
    <span className={`
      inline-flex items-center gap-1 rounded-full font-medium uppercase tracking-wider
      ${sizeClasses[size]}
      ${color.text} bg-current/10
    `}
    style={{ backgroundColor: `${color.hex}15`, color: color.hex }}
    >
      <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: color.hex, boxShadow: `0 0 4px ${color.hex}` }} />
      {level}
    </span>
  )
}
