export const riskColors = {
  critical: { bg: 'bg-risk-critical', text: 'text-risk-critical', hex: '#ef4444', led: 'led-critical' },
  high:     { bg: 'bg-risk-high',     text: 'text-risk-high',     hex: '#f97316', led: 'led-high' },
  medium:   { bg: 'bg-risk-medium',   text: 'text-risk-medium',   hex: '#eab308', led: 'led-medium' },
  low:      { bg: 'bg-risk-low',      text: 'text-risk-low',      hex: '#3b82f6', led: 'led-low' },
  info:     { bg: 'bg-risk-info',     text: 'text-risk-info',     hex: '#6b7280', led: 'led-info' },
}

export function getRiskColor(level) {
  return riskColors[level?.toLowerCase()] || riskColors.info
}

export function getScoreColor(score) {
  if (score >= 0.8) return riskColors.critical
  if (score >= 0.6) return riskColors.high
  if (score >= 0.4) return riskColors.medium
  if (score >= 0.2) return riskColors.low
  return riskColors.info
}

export const chartColors = {
  area: '#3b82f6',
  areaFill: 'rgba(59, 130, 246, 0.15)',
  scatter: {
    critical: '#ef4444',
    high: '#f97316',
    medium: '#eab308',
    low: '#3b82f6',
  },
  grid: 'rgba(255, 255, 255, 0.04)',
  axis: 'rgba(255, 255, 255, 0.3)',
  tooltip: 'rgba(0, 0, 0, 0.9)',
}

export const eventTypeColors = {
  file_system: '#3b82f6',
  registry: '#a855f7',
  network: '#06b6d4',
  process: '#22c55e',
  user_login: '#f97316',
  system_event: '#6b7280',
  application: '#eab308',
  security: '#ef4444',
  custom: '#8b5cf6',
  windows_event: '#a855f7',
  log_entry: '#6b7280',
  unknown: '#4b5563',
}
