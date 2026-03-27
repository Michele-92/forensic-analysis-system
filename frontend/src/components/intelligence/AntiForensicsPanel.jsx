/**
 * ============================================================================
 * ANTI-FORENSICS PANEL — Visualisierung von Manipulations- und Verschleierungshinweisen
 * ============================================================================
 * Stellt den Anti-Forensics-Report (FA-23) aus dem Backend dar.
 * Der Report enthält Hinweise, dass ein Angreifer versucht hat, forensische
 * Spuren zu verwischen oder die Analyse zu erschweren.
 *
 * Angezeigte Bereiche:
 *   - Risiko-Header: Gesamtrisiko-Badge (none/low/medium/high/critical)
 *     mit Risikowert (0–100) und Anzahl der gefundenen Hinweise
 *   - Befunde-Liste: Pro Befund wird angezeigt:
 *       · Kategorie (z.B. "Timestomping", "Log-Löschung", "Wipe-Tools")
 *       · Schweregrad-Badge (critical/high/medium/low/info)
 *       · Beschreibung des Befunds
 *       · Aufklappbare Detailansicht (Beweisstücke + MITRE ATT&CK Technik)
 *   - Leer-Zustand: Bei fehlendem Report oder 0 Befunden Hinweis-Karte
 *
 * Neun geprüfte Kategorien (vom Backend):
 *   Timestomping, Log-Lücken, Timestamp-Cluster, Wipe-Tools,
 *   Log-Löschung, Systemzeit-Änderung, Rootkit-Indikatoren,
 *   Truncated Logs, Lösch-Operationen
 *
 * Props:
 * @param {Object|null} antiforensics - Daten aus antiforensics_report.json (FA-23).
 *                                      Felder: findings, findings_count, risk_score,
 *                                      risk_level, stats, total_checks
 *
 * Abhängigkeiten:
 *   - lucide-react (Icons: ShieldOff, AlertTriangle, AlertOctagon, Info)
 *
 * @module components/intelligence/AntiForensicsPanel
 */
import React, { useState } from 'react'
import { ShieldOff, AlertTriangle, AlertOctagon, Info, ChevronDown, ChevronUp } from 'lucide-react'
export default function AntiForensicsPanel({ antiforensics }) {
  if (!antiforensics || antiforensics.findings_count === undefined) {
    return (
      <div className="glass-card text-center py-10">
        <ShieldOff size={28} className="text-white/10 mx-auto mb-3" />
        <p className="text-sm text-white/30">Kein Anti-Forensics-Report verfügbar.</p>
        <p className="text-xs text-white/15 mt-1">
          Der Report wird während der Pipeline-Analyse erstellt.
        </p>
      </div>
    )
  }

  const { findings = [], risk_score = 0, risk_level = 'none', summary = '' } = antiforensics

  return (
    <div className="space-y-4">

      {/* ── Risiko-Übersicht ── */}
      <RiskOverview score={risk_score} level={risk_level} summary={summary} />

      {/* ── Findings ── */}
      {findings.length === 0 ? (
        <div className="glass-card text-center py-8">
          <div className="w-10 h-10 rounded-xl bg-accent-green/10 flex items-center justify-center mx-auto mb-3">
            <ShieldOff size={18} className="text-accent-green" />
          </div>
          <p className="text-sm text-accent-green/80">Keine Anti-Forensics-Indikatoren erkannt.</p>
          <p className="text-xs text-white/20 mt-1">Alle 9 Checks ohne Befund abgeschlossen.</p>
        </div>
      ) : (
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <AlertTriangle size={14} className="text-risk-high" />
            <span className="text-sm font-medium text-white/60">
              {findings.length} Manipulations-Hinweis{findings.length !== 1 ? 'e' : ''} gefunden
            </span>
          </div>
          {findings.map((finding, i) => (
            <FindingCard key={i} finding={finding} />
          ))}
        </div>
      )}
    </div>
  )
}

// ── Risiko-Gauge ──────────────────────────────────────────────────────────────

const RISK_CONFIG = {
  none:     { color: 'text-white/30',      bg: 'bg-white/[0.04]',       bar: 'bg-white/10',         label: 'Kein Risiko' },
  low:      { color: 'text-accent-green',  bg: 'bg-accent-green/10',    bar: 'bg-accent-green',     label: 'Niedrig' },
  medium:   { color: 'text-risk-medium',   bg: 'bg-risk-medium/10',     bar: 'bg-risk-medium',      label: 'Mittel' },
  high:     { color: 'text-risk-high',     bg: 'bg-risk-high/10',       bar: 'bg-risk-high',        label: 'Hoch' },
  critical: { color: 'text-risk-critical', bg: 'bg-risk-critical/10',   bar: 'bg-risk-critical',    label: 'Kritisch' },
}

function RiskOverview({ score, level, summary }) {
  const cfg = RISK_CONFIG[level] || RISK_CONFIG.none

  return (
    <div className="glass-card">
      <div className="flex items-center gap-3 mb-4">
        <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${cfg.bg}`}>
          <ShieldOff size={18} className={cfg.color} />
        </div>
        <div>
          <h3 className="text-sm font-medium text-white/70">Anti-Forensics-Analyse</h3>
          <span className={`text-xs font-medium ${cfg.color}`}>{cfg.label}</span>
        </div>
        <div className="ml-auto text-right">
          <span className={`text-2xl font-bold ${cfg.color}`}>{score}</span>
          <span className="text-xs text-white/25 ml-1">/100</span>
        </div>
      </div>

      {/* Risiko-Balken */}
      <div className="h-1.5 rounded-full bg-white/[0.06] overflow-hidden mb-3">
        <div
          className={`h-full rounded-full transition-all duration-700 ${cfg.bar}`}
          style={{ width: `${Math.min(score, 100)}%` }}
        />
      </div>

      {summary && (
        <p className="text-xs text-white/40 leading-relaxed">{summary}</p>
      )}
    </div>
  )
}

// ── Finding-Card ──────────────────────────────────────────────────────────────

const SEVERITY_CONFIG = {
  high:   { color: 'text-risk-high',     bg: 'bg-risk-high/10',     border: 'border-risk-high/20',     icon: AlertOctagon },
  medium: { color: 'text-risk-medium',   bg: 'bg-risk-medium/10',   border: 'border-risk-medium/20',   icon: AlertTriangle },
  low:    { color: 'text-white/40',      bg: 'bg-white/[0.04]',     border: 'border-white/[0.06]',     icon: Info },
}

const CATEGORY_LABELS = {
  timestomping:         'Zeitstempel-Manipulation (Timestomping)',
  log_gap:              'Log-Lücke',
  timestamp_cluster:    'Identische Timestamp-Cluster',
  wiping:               'Wipe-Tools',
  log_clearing:         'Log- / History-Löschung',
  time_manipulation:    'Systemzeit-Manipulation',
  rootkit_indicator:    'Rootkit-Indikator',
  truncated_logs:       'Truncated Logs (/var/log)',
  suspicious_deletion:  'Verdächtige Löschoperation',
}

function FindingCard({ finding }) {
  const [open, setOpen] = useState(false)
  const { category, severity, description, evidence = [], mitre } = finding
  const cfg = SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.low
  const Icon = cfg.icon

  return (
    <div className={`glass-card border ${cfg.border}`}>
      {/* Header */}
      <button
        className="w-full flex items-start gap-3 text-left"
        onClick={() => setOpen(p => !p)}
      >
        <div className={`w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0 mt-0.5 ${cfg.bg}`}>
          <Icon size={13} className={cfg.color} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={`text-[10px] px-1.5 py-0.5 rounded-full font-medium uppercase tracking-wider ${cfg.bg} ${cfg.color}`}>
              {severity}
            </span>
            <span className="text-xs font-medium text-white/60">
              {CATEGORY_LABELS[category] || category}
            </span>
            {mitre && (
              <code className="text-[10px] px-1.5 py-0.5 rounded bg-accent-purple/10 text-accent-purple font-mono">
                {mitre}
              </code>
            )}
          </div>
          <p className="text-xs text-white/40 mt-1 leading-relaxed line-clamp-2">{description}</p>
        </div>
        <div className="flex-shrink-0 text-white/20 mt-0.5">
          {open ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
        </div>
      </button>

      {/* Evidenz-Liste */}
      {open && evidence.length > 0 && (
        <div className="mt-3 pt-3 border-t border-white/[0.04]">
          <span className="text-[10px] text-white/20 uppercase tracking-wider block mb-2">Belege</span>
          <div className="space-y-1">
            {evidence.map((ev, i) => (
              <code key={i} className="text-[11px] block px-2 py-1 rounded bg-white/[0.02] text-white/40 font-mono break-all">
                {ev}
              </code>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
