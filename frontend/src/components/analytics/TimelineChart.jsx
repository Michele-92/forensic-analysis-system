/**
 * ============================================================================
 * TIMELINE CHART — Temporal Anomaly Engine (v3 — Ermittler-Ansicht)
 * ============================================================================
 * Optimiert für forensische Ermittler der Cyberkriminalpolizei.
 * Zeigt auf einen Blick: Angriffsphasen, kritische Events, IOCs, Zusammenfassung.
 *
 * Neu in v3:
 *   - Zusammenfassungszeile ("47 Events · 3 IPs · höchster Score: 94%")
 *   - Attack-Phase-Leiste über dem Chart (Recon / Initial Access / usw.)
 *   - Top-3 kritische Event-Pins direkt im Chart (Score >= 80%)
 *   - IOC-Tabelle unter dem Chart — aufklappbar (collapsed by default)
 *   - ReferenceLine bei 80% (Kritisch-Schwelle)
 *   - Verbesserter Custom Tooltip mit Event-Details
 *   - Glow abgeschwächt, X-Achse lesbarer formatiert
 *
 * @component
 */
import React, { useMemo, useState } from 'react'
import {
  ComposedChart, Area, Scatter, XAxis, YAxis, Tooltip,
  CartesianGrid, ResponsiveContainer, Cell, ReferenceLine,
  ReferenceArea
} from 'recharts'
import { chartColors } from '../../utils/colors'

// -- Konstanten ----------------------------------------------------------------

const PHASE_COLORS = {
  recon:        { bg: 'rgba(251,191,36,0.08)',  border: 'rgba(251,191,36,0.4)',  label: 'Reconnaissance' },
  initial:      { bg: 'rgba(249,115,22,0.08)',  border: 'rgba(249,115,22,0.4)',  label: 'Initial Access'  },
  persistence:  { bg: 'rgba(168,85,247,0.08)',  border: 'rgba(168,85,247,0.4)',  label: 'Persistence'     },
  exfil:        { bg: 'rgba(239,68,68,0.08)',   border: 'rgba(239,68,68,0.4)',   label: 'Exfiltration'    },
  defense:      { bg: 'rgba(239,68,68,0.12)',   border: 'rgba(239,68,68,0.5)',   label: 'Defense Evasion' },
  c2:           { bg: 'rgba(239,68,68,0.1)',    border: 'rgba(239,68,68,0.45)',  label: 'C2'              },
}

// MITRE-Taktiken -> Phase-Mapping
// Enthält sowohl die Rohwerte aus Log-Dateien (RECON, C2, EXFIL ...)
// als auch die normalisierten event_type-Werte des Backends (c2_beacon, data_exfiltration ...)
// Alle Werte werden vor dem Lookup per .toUpperCase() verglichen.
const TACTIC_TO_PHASE = {
  // ── Rohwerte aus Log-Dateien (zweite Spalte) ──────────────────
  'RECON':              'recon',
  'LATERAL':            'recon',
  'AUTH':               'initial',
  'PROCESS':            'initial',
  'PERSISTENCE':        'persistence',
  'C2':                 'c2',
  'CREDENTIAL':         'exfil',
  'EXFIL':              'exfil',
  'DEFENSE_EVASION':    'defense',
  'DATABASE':           'exfil',
  'ACCOUNT':            'persistence',
  'DOWNLOAD':           'initial',
  'WEB':                'initial',

  // ── Normalisierte Backend-Werte (log_parser.py / normalizer.py) ──
  'C2_BEACON':          'c2',
  'C2_TOOL':            'c2',
  'C2_CONNECTION':      'c2',
  'DATA_EXFILTRATION':  'exfil',
  'NETWORK_SCAN':       'recon',
  'AUTH_FAILURE':       'initial',
  'AUTH_SUCCESS':       'initial',
  'SSH_EVENT':          'initial',
  'PRIVILEGE_ESCALATION': 'initial',
  'FILE_DOWNLOAD':      'initial',
  'WEB_ATTACK':         'initial',
  'WEB_ADMIN':          'initial',
  'ANTI_FORENSICS':     'defense',
  'PERSISTENCE_EVENT':  'persistence',
  'CRON_EVENT':         'persistence',
  'REGISTRY_EVENT':     'persistence',
  'SUDO_EVENT':         'initial',
}

const SCORE_LEVELS = [
  { min: 80, color: '#ef4444', label: 'Kritisch >= 80%' },
  { min: 60, color: '#f97316', label: 'Hoch >= 60%'     },
  { min: 40, color: '#eab308', label: 'Mittel >= 40%'   },
  { min: 0,  color: '#3b82f6', label: 'Niedrig < 40%'   },
]

// -- Hilfsfunktionen -----------------------------------------------------------

const scoreToColor = (score) => {
  for (const level of SCORE_LEVELS) {
    if (score >= level.min) return level.color
  }
  return '#3b82f6'
}

const formatAxisLabel = (key) => {
  if (!key || key.startsWith('unknown')) return ''
  const day   = key.slice(8, 10)
  const month = key.slice(5, 7)
  const hour  = key.slice(11, 13)
  return `${day}.${month} - ${hour}h`
}

const formatTooltipLabel = (key) => {
  if (!key || key.startsWith('unknown')) return ''
  const year  = key.slice(0, 4)
  const month = key.slice(5, 7)
  const day   = key.slice(8, 10)
  const hour  = key.slice(11, 13)
  return `${day}.${month}.${year} - ${hour}:00 Uhr`
}

const extractIp = (eventStr) => {
  if (!eventStr) return null
  const match = eventStr.match(/(?:from|to)\s+([\d.]+)/)
  return match ? match[1] : null
}

const isExternalIp = (ip) => {
  if (!ip) return false
  return !ip.startsWith('10.') && !ip.startsWith('192.168.') &&
         !ip.startsWith('172.') && ip !== '127.0.0.1'
}

// -- Custom Tooltip ------------------------------------------------------------

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null

  const base = {
    backgroundColor: chartColors.tooltip || 'rgba(15,23,42,0.95)',
    border: '1px solid rgba(255,255,255,0.1)',
    borderRadius: 12,
    padding: '10px 14px',
    backdropFilter: 'blur(20px)',
    fontSize: 11,
    minWidth: 220,
  }

  const scatterP = payload.find(p => p.name === 'Anomalien')
  if (scatterP) {
    const e     = scatterP.payload
    const score = Math.round(e.score)
    const color = scoreToColor(score)
    const ip    = extractIp(e.event)
    const ext   = isExternalIp(ip)
    return (
      <div style={base}>
        <p style={{ color: 'rgba(255,255,255,0.45)', marginBottom: 6 }}>
          {formatTooltipLabel(e.time)}
        </p>
        <p style={{ color, fontWeight: 600, marginBottom: 4 }}>
          Anomalie - Score {score}%
        </p>
        {e.event && (
          <p style={{ color: 'rgba(255,255,255,0.7)', marginBottom: 3 }}>
            {e.event.length > 72 ? e.event.slice(0, 72) + '...' : e.event}
          </p>
        )}
        {ip && (
          <p style={{ color: ext ? '#f87171' : 'rgba(255,255,255,0.4)', marginTop: 4 }}>
            {ext ? 'Externe IP: ' : 'IP: '}{ip}
          </p>
        )}
        {e.risk_level && (
          <p style={{ color: 'rgba(255,255,255,0.35)', marginTop: 2 }}>
            Risikostufe: {e.risk_level}
          </p>
        )}
      </div>
    )
  }

  const areaP = payload.find(p => p.name === 'Events')
  if (areaP) {
    const anomCount = areaP.payload?.anomalyCount || 0
    return (
      <div style={base}>
        <p style={{ color: 'rgba(255,255,255,0.45)', marginBottom: 6 }}>
          {formatTooltipLabel(label)}
        </p>
        <p style={{ color: 'rgba(255,255,255,0.85)' }}>
          Events gesamt: {areaP.value}
        </p>
        {anomCount > 0 && (
          <p style={{ color: '#f97316', marginTop: 3 }}>
            davon anomal: {anomCount}
          </p>
        )}
      </div>
    )
  }

  return null
}

// -- Zusammenfassungszeile -----------------------------------------------------

const SummaryBar = ({ totalEvents, topScore, topScoreTime, extIpCount, criticalCount }) => (
  <div style={{
    display: 'flex',
    gap: 20,
    flexWrap: 'wrap',
    marginBottom: 12,
    padding: '8px 12px',
    background: 'rgba(255,255,255,0.04)',
    borderRadius: 8,
    border: '1px solid rgba(255,255,255,0.07)',
    fontSize: 11,
  }}>
    <span style={{ color: 'rgba(255,255,255,0.5)' }}>
      Ereignisse gesamt: <strong style={{ color: 'rgba(255,255,255,0.85)' }}>{totalEvents}</strong>
    </span>
    <span style={{ color: 'rgba(255,255,255,0.5)' }}>
      Externe IPs: <strong style={{ color: extIpCount > 0 ? '#f87171' : 'rgba(255,255,255,0.85)' }}>{extIpCount}</strong>
    </span>
    <span style={{ color: 'rgba(255,255,255,0.5)' }}>
      Kritische Anomalien: <strong style={{ color: criticalCount > 0 ? '#ef4444' : 'rgba(255,255,255,0.85)' }}>{criticalCount}</strong>
    </span>
    {topScore > 0 && (
      <span style={{ color: 'rgba(255,255,255,0.5)' }}>
        Hoechster Score: <strong style={{ color: scoreToColor(topScore) }}>{topScore}%</strong>
        {topScoreTime && <span style={{ color: 'rgba(255,255,255,0.3)' }}> - {topScoreTime}</span>}
      </span>
    )}
  </div>
)

// -- Angriffsphasen-Badge ------------------------------------------------------

const PhaseBadge = ({ phase }) => {
  const cfg = PHASE_COLORS[phase]
  if (!cfg) return null
  return (
    <span style={{
      display: 'inline-block',
      padding: '2px 8px',
      borderRadius: 4,
      fontSize: 10,
      fontWeight: 500,
      background: cfg.bg,
      border: `1px solid ${cfg.border}`,
      color: cfg.border,
      marginRight: 4,
      marginBottom: 4,
    }}>
      {cfg.label}
    </span>
  )
}

// -- IOC-Tabelle (aufklappbar) -------------------------------------------------

const IocTable = ({ extIps }) => {
  const [open, setOpen] = useState(false)

  if (!extIps?.length) return null

  const hasCritical = extIps.some(e => e.maxScore >= 80)

  return (
    <div style={{ marginTop: 14 }}>

      {/* Toggle-Header */}
      <button
        onClick={() => setOpen(prev => !prev)}
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          width: '100%',
          background: 'rgba(255,255,255,0.04)',
          border: '1px solid rgba(255,255,255,0.09)',
          borderRadius: open ? '8px 8px 0 0' : 8,
          padding: '7px 12px',
          cursor: 'pointer',
          fontSize: 11,
          color: 'rgba(255,255,255,0.55)',
          textAlign: 'left',
          transition: 'border-radius 0.15s',
        }}
      >
        {/* Pfeil-Icon rotiert beim Aufklappen */}
        <span style={{
          display: 'inline-block',
          transform: open ? 'rotate(90deg)' : 'rotate(0deg)',
          transition: 'transform 0.2s',
          fontSize: 9,
          lineHeight: 1,
          color: 'rgba(255,255,255,0.35)',
        }}>
          &#9654;
        </span>

        <span style={{ fontWeight: 500 }}>
          Externe IP-Adressen (IOCs)
        </span>

        {/* Anzahl-Badge — rot wenn kritische IPs vorhanden */}
        <span style={{
          marginLeft: 'auto',
          background: hasCritical ? 'rgba(239,68,68,0.15)' : 'rgba(255,255,255,0.07)',
          border: `1px solid ${hasCritical ? 'rgba(239,68,68,0.4)' : 'rgba(255,255,255,0.15)'}`,
          color: hasCritical ? '#f87171' : 'rgba(255,255,255,0.4)',
          borderRadius: 10,
          padding: '1px 8px',
          fontSize: 10,
        }}>
          {extIps.length} IP{extIps.length !== 1 ? 's' : ''}
        </span>
      </button>

      {/* Aufklappbarer Inhalt */}
      {open && (
        <div style={{
          border: '1px solid rgba(255,255,255,0.09)',
          borderTop: 'none',
          borderRadius: '0 0 8px 8px',
          overflow: 'hidden',
        }}>
          {extIps.slice(0, 8).map(({ ip, count, maxScore }, idx) => {
            const color = scoreToColor(maxScore)
            return (
              <div
                key={ip}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 10,
                  padding: '7px 12px',
                  background: idx % 2 === 0
                    ? 'rgba(255,255,255,0.02)'
                    : 'rgba(255,255,255,0.035)',
                  fontSize: 11,
                  borderTop: idx === 0 ? 'none' : '1px solid rgba(255,255,255,0.05)',
                }}
              >
                <span style={{
                  width: 8, height: 8, borderRadius: '50%',
                  background: color, flexShrink: 0,
                  boxShadow: `0 0 4px ${color}88`,
                }} />
                <span style={{
                  color: 'rgba(255,255,255,0.8)',
                  fontFamily: 'monospace',
                  flex: 1,
                  letterSpacing: '0.02em',
                }}>
                  {ip}
                </span>
                <span style={{ color: 'rgba(255,255,255,0.35)', minWidth: 60 }}>
                  {count}x gesehen
                </span>
                <span style={{ color, fontWeight: 500, minWidth: 52, textAlign: 'right' }}>
                  {maxScore > 0 ? `max. ${maxScore}%` : '-'}
                </span>
              </div>
            )
          })}

          {extIps.length > 8 && (
            <div style={{
              padding: '6px 12px',
              fontSize: 10,
              color: 'rgba(255,255,255,0.25)',
              textAlign: 'center',
              background: 'rgba(255,255,255,0.02)',
            }}>
              + {extIps.length - 8} weitere IPs
            </div>
          )}
        </div>
      )}

    </div>
  )
}

// -- Hauptkomponente -----------------------------------------------------------

export default function TimelineChart({ timeline, anomalies }) {

  // Stunden-Buckets
  const hourlyData = useMemo(() => {
    if (!timeline?.length) return []
    const buckets = {}
    timeline.forEach(event => {
      const ts = event.timestamp || event.mtime
      if (!ts) return
      const d = new Date(ts)
      if (isNaN(d.getTime())) return
      const key = d.toISOString().slice(0, 13)
      if (!buckets[key]) buckets[key] = { time: key, count: 0, anomalyCount: 0 }
      buckets[key].count++
      if (event.is_anomaly) buckets[key].anomalyCount++
    })
    return Object.values(buckets).sort((a, b) => a.time.localeCompare(b.time))
  }, [timeline])

  // Scatter-Datenpunkte
  const scatterData = useMemo(() => {
    if (!anomalies?.length) return []
    return anomalies.map((a, i) => {
      const ts  = a.timestamp
      const d   = ts ? new Date(ts) : null
      const key = d && !isNaN(d.getTime()) ? d.toISOString().slice(0, 13) : null
      const bucket = hourlyData.find(h => h.time === key)
      return {
        time:       key || `unknown_${i}`,
        score:      Math.round((a.anomaly_score || 0) * 100),
        risk_level: a.risk_level || 'medium',
        event:      a.event || a.description || '',
        eventType:  a.event_type || '',
        y:          bucket ? bucket.count : 0,
      }
    }).filter(d => !d.time.startsWith('unknown'))
  }, [anomalies, hourlyData])

  // Angriffsphasen aus Timeline ableiten
  const detectedPhases = useMemo(() => {
    if (!timeline?.length) return new Set()
    const phases = new Set()
    timeline.forEach(ev => {
      const type = (ev.event_type || ev.category || '').toUpperCase()
      const phase = TACTIC_TO_PHASE[type]
      if (phase) phases.add(phase)
    })
    return phases
  }, [timeline])

  // Externe IPs aggregieren
  const extIps = useMemo(() => {
    const ipMap = {}
    const allEvents = [
      ...(timeline || []).map(e => e.description || e.event || ''),
      ...(anomalies || []).map(a => a.event || a.description || ''),
    ]
    allEvents.forEach(eventStr => {
      const ip = extractIp(eventStr)
      if (!ip || !isExternalIp(ip)) return
      if (!ipMap[ip]) ipMap[ip] = { ip, count: 0, maxScore: 0 }
      ipMap[ip].count++
    })
    ;(anomalies || []).forEach(a => {
      const ip    = extractIp(a.event || a.description || '')
      const score = Math.round((a.anomaly_score || 0) * 100)
      if (ip && isExternalIp(ip) && ipMap[ip]) {
        ipMap[ip].maxScore = Math.max(ipMap[ip].maxScore, score)
      }
    })
    return Object.values(ipMap).sort((a, b) => b.maxScore - a.maxScore || b.count - a.count)
  }, [timeline, anomalies])

  // Zusammenfassungs-Metriken
  const summary = useMemo(() => {
    const critical = scatterData.filter(d => d.score >= 80)
    const topEntry = [...scatterData].sort((a, b) => b.score - a.score)[0]
    return {
      totalEvents:   timeline?.length || 0,
      extIpCount:    extIps.length,
      criticalCount: critical.length,
      topScore:      topEntry ? topEntry.score : 0,
      topScoreTime:  topEntry ? formatAxisLabel(topEntry.time) : '',
    }
  }, [scatterData, timeline, extIps])

  // Top-3 kritische Pins
  const criticalPins = useMemo(() => {
    return [...scatterData]
      .filter(d => d.score >= 80)
      .sort((a, b) => b.score - a.score)
      .slice(0, 3)
  }, [scatterData])

  // Empty State
  if (hourlyData.length === 0) {
    return (
      <div className="glass-card h-80 flex items-center justify-center">
        <span className="text-sm text-white/20">Keine Timeline-Daten verfuegbar</span>
      </div>
    )
  }

  return (
    <div className="glass-card">

      <h3 className="text-sm font-medium text-white/50 mb-3">Temporal Anomaly Engine</h3>

      <SummaryBar {...summary} />

      {detectedPhases.size > 0 && (
        <div style={{ marginBottom: 12 }}>
          <p style={{ fontSize: 10, color: 'rgba(255,255,255,0.3)', marginBottom: 5 }}>
            Erkannte Angriffsphasen
          </p>
          <div style={{ display: 'flex', flexWrap: 'wrap' }}>
            {[...detectedPhases].map(phase => (
              <PhaseBadge key={phase} phase={phase} />
            ))}
          </div>
        </div>
      )}

      <ResponsiveContainer width="100%" height={300}>
        <ComposedChart data={hourlyData} margin={{ top: 10, right: 60, bottom: 0, left: 10 }}>

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
            tickFormatter={formatAxisLabel}
            stroke={chartColors.grid}
            interval="preserveStartEnd"
          />

          <YAxis
            yAxisId="left"
            tick={{ fill: chartColors.axis, fontSize: 10 }}
            stroke={chartColors.grid}
            label={{
              value: 'Events/h', angle: -90, position: 'insideLeft',
              fill: 'rgba(255,255,255,0.25)', fontSize: 10, dx: -5,
            }}
          />

          <YAxis
            yAxisId="right"
            orientation="right"
            domain={[0, 100]}
            tick={{ fill: chartColors.axis, fontSize: 10 }}
            stroke={chartColors.grid}
            tickFormatter={(v) => `${v}%`}
            label={{
              value: 'Anomaly Score', angle: 90, position: 'insideRight',
              fill: 'rgba(255,255,255,0.25)', fontSize: 10, dx: 5,
            }}
          />

          <ReferenceLine
            yAxisId="right"
            y={80}
            stroke="#ef4444"
            strokeDasharray="4 3"
            strokeOpacity={0.5}
            label={{
              value: 'Kritisch',
              position: 'insideTopRight',
              fill: '#ef4444',
              fontSize: 10,
              opacity: 0.75,
            }}
          />

          {criticalPins.map((pin, i) => (
            <ReferenceLine
              key={`pin-${i}`}
              yAxisId="left"
              x={pin.time}
              stroke="#ef4444"
              strokeOpacity={0.4}
              strokeWidth={1}
              strokeDasharray="2 4"
              label={{
                value: `${pin.score}%`,
                position: 'top',
                fill: '#ef4444',
                fontSize: 9,
                opacity: 0.8,
              }}
            />
          ))}

          <Tooltip content={<CustomTooltip />} />

          <Area
            yAxisId="left"
            type="monotone"
            dataKey="count"
            stroke={chartColors.area}
            strokeWidth={2}
            fill="url(#areaGradient)"
            name="Events"
            style={{ filter: 'drop-shadow(0 0 4px rgba(59,130,246,0.15))' }}
          />

          <Scatter yAxisId="right" data={scatterData} dataKey="score" name="Anomalien">
            {scatterData.map((entry, i) => (
              <Cell
                key={i}
                fill={scoreToColor(entry.score)}
                style={{ filter: `drop-shadow(0 0 4px ${scoreToColor(entry.score)}88)` }}
              />
            ))}
          </Scatter>

        </ComposedChart>
      </ResponsiveContainer>

      <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', marginTop: 10, paddingLeft: 2 }}>
        {SCORE_LEVELS.map(({ color, label }) => (
          <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
            <span style={{
              width: 8, height: 8, borderRadius: '50%',
              background: color, display: 'inline-block', flexShrink: 0,
            }} />
            <span style={{ fontSize: 10, color: 'rgba(255,255,255,0.4)' }}>{label}</span>
          </div>
        ))}
      </div>

      <IocTable extIps={extIps} />

    </div>
  )
}