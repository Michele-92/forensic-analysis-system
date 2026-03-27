/**
 * ============================================================================
 * COLORS — Farb-Definitionen und Mapping-Funktionen
 * ============================================================================
 * Zentrale Farbpalette für das forensische Analyse-Dashboard.
 * Alle Farben folgen dem ultra-dunklen Glassmorphismus-Design ("Apple-Style Forensics").
 *
 * Drei Farbsysteme:
 *   1. riskColors      → Risikolevel-Farben (critical/high/medium/low/info)
 *                        Mit Tailwind-Klassen (bg-*, text-*), Hex-Werten und LED-Klassen
 *   2. chartColors     → Recharts-Diagramm-Farben (Area, Scatter, Grid, Achsen, Tooltip)
 *   3. eventTypeColors → Forensische Ereignistypen (Dateisystem, Registry, Netzwerk, etc.)
 *
 * Mapping-Funktionen:
 *   - getRiskColor(level)  → Farbpalette für ein Risikolevel-String ("critical", "high", …)
 *   - getScoreColor(score) → Farbpalette für einen numerischen Anomalie-Score (0.0–1.0)
 *
 * Verwendung in der UI:
 *   - IntelligencePanel: Anomalie-Score-Badges, Hypothesen-Bäume
 *   - AnalyticsPanel: Recharts ComposedChart (Area + Scatter), Pie-Chart
 *   - IOCList: Risikolevel-Indikatoren, LED-Badges
 *   - Überall: Tailwind-Klassen aus riskColors.bg / riskColors.text
 *
 * @module utils/colors
 */

// ── Risikolevel-Farben ────────────────────────────────────────────────────────

/**
 * Vollständige Farbpalette pro Risikolevel.
 *
 * Jeder Eintrag enthält:
 *   - bg:  Tailwind-Hintergrundklasse (z. B. "bg-risk-critical")
 *   - text: Tailwind-Textfarb-Klasse (z. B. "text-risk-critical")
 *   - hex:  Hex-Farbwert für Inline-Styles und Recharts
 *   - led:  CSS-Klasse für den blinkenden LED-Indikator (Glassmorphismus-Design)
 *
 * @type {Object.<string, {bg: string, text: string, hex: string, led: string}>}
 */
export const riskColors = {
  critical: { bg: 'bg-risk-critical', text: 'text-risk-critical', hex: '#ef4444', led: 'led-critical' },
  high:     { bg: 'bg-risk-high',     text: 'text-risk-high',     hex: '#f97316', led: 'led-high' },
  medium:   { bg: 'bg-risk-medium',   text: 'text-risk-medium',   hex: '#eab308', led: 'led-medium' },
  low:      { bg: 'bg-risk-low',      text: 'text-risk-low',      hex: '#3b82f6', led: 'led-low' },
  info:     { bg: 'bg-risk-info',     text: 'text-risk-info',     hex: '#6b7280', led: 'led-info' },
}

/**
 * Gibt die Farbpalette für ein Risikolevel zurück.
 *
 * Groß-/Kleinschreibung wird normalisiert (toLowerCase).
 * Unbekannte Levels fallen auf "info" (grau) zurück.
 *
 * @param {string} level - Risikolevel ("critical", "high", "medium", "low", "info")
 * @returns {{bg: string, text: string, hex: string, led: string}} Farbpalette für das Level
 *
 * @example
 * const colors = getRiskColor('high')
 * // → { bg: 'bg-risk-high', text: 'text-risk-high', hex: '#f97316', led: 'led-high' }
 */
export function getRiskColor(level) {
  return riskColors[level?.toLowerCase()] || riskColors.info
}

/**
 * Gibt die Farbpalette für einen numerischen Anomalie-Score zurück.
 *
 * Schwellenwerte (IsolationForest-Score, normiert 0.0–1.0):
 *   >= 0.8 → critical (rot)
 *   >= 0.6 → high     (orange)
 *   >= 0.4 → medium   (gelb)
 *   >= 0.2 → low      (blau)
 *   <  0.2 → info     (grau)
 *
 * @param {number} score - Normierter Anomalie-Score (0.0 = unauffällig, 1.0 = hochverdächtig)
 * @returns {{bg: string, text: string, hex: string, led: string}} Farbpalette für den Score
 *
 * @example
 * const colors = getScoreColor(0.75)
 * // → riskColors.high
 */
export function getScoreColor(score) {
  if (score >= 0.8) return riskColors.critical
  if (score >= 0.6) return riskColors.high
  if (score >= 0.4) return riskColors.medium
  if (score >= 0.2) return riskColors.low
  return riskColors.info
}

// ── Diagramm-Farben ───────────────────────────────────────────────────────────

/**
 * Farben für Recharts-Diagramme im AnalyticsPanel.
 *
 * Verwendet im Temporal Anomaly Engine (ComposedChart: Area + Scatter):
 *   - area/areaFill: Zeitreihen-Flächendiagramm (blaue Linie + transparente Fläche)
 *   - scatter.*: Scatter-Punkte, farbcodiert nach Risikolevel
 *   - grid: Gitternetz-Linien (sehr transparent, kaum sichtbar)
 *   - axis: Achsenbeschriftungen (30 % weiß)
 *   - tooltip: Recharts Tooltip-Hintergrund (fast schwarz)
 *
 * @type {{
 *   area: string,
 *   areaFill: string,
 *   scatter: {critical: string, high: string, medium: string, low: string},
 *   grid: string,
 *   axis: string,
 *   tooltip: string
 * }}
 */
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

// ── Ereignistyp-Farben ────────────────────────────────────────────────────────

/**
 * Farben für forensische Ereignistypen (Artifact-Taxonomy-Pie-Chart und Event-Tabellen).
 *
 * Die Schlüssel entsprechen den "event_type"-Werten aus dem normalisierten
 * Pipeline-Output (normalized_output.json). Unbekannte Typen erhalten "unknown" (dunkelgrau).
 *
 * Typen und ihre Bedeutung:
 *   file_system    → Dateisystem-Ereignisse (MFT-Einträge, Sleuth Kit)
 *   registry       → Windows Registry-Änderungen
 *   network        → Netzwerk-Verbindungen / DNS
 *   process        → Prozess-Start/-Stop-Ereignisse
 *   user_login     → Anmelde-/Abmelde-Ereignisse
 *   system_event   → Allgemeine Windows/Linux System-Events
 *   application    → Anwendungs-spezifische Events
 *   security       → Sicherheitsrelevante Events (Audit-Log)
 *   custom         → Benutzerdefinierte/UAC-Artefakte
 *   windows_event  → Windows Event Log Einträge
 *   log_entry      → Generische Log-Einträge (Syslog, etc.)
 *   unknown        → Nicht klassifizierbare Ereignisse
 *
 * @type {Object.<string, string>}
 */
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
