/**
 * ============================================================================
 * EVENT TABLE — Paginierte forensische Event-Liste
 * ============================================================================
 * Zeigt alle normalisierten Events in einer tabellarischen Ansicht.
 * Unterstützt:
 *   - Freitext-Filterung über Beschreibung, Typ, Quelle und Event-ID
 *   - Spalten-Sortierung (aufsteigend/absteigend) per Klick auf den Header
 *   - Client-seitige Paginierung mit 25 Events pro Seite
 *   - Farbkodierter Anomaly-Score pro Zeile (via getScoreColor)
 *
 * Props:
 * @param {Object[]} timeline - Normalisierte Event-Liste (aus DataNormalizer)
 *
 * Abhängigkeiten:
 *   - RiskBadge (Risiko-Label Komponente)
 *   - utils/formatters (formatTimestamp, formatScore)
 *   - utils/colors (getScoreColor)
 *   - lucide-react (ChevronUp, ChevronDown, Search)
 *
 * @component
 */
import React, { useState, useMemo } from 'react'
import RiskBadge from '../RiskBadge'
import { formatTimestamp, formatScore } from '../../utils/formatters'
import { getScoreColor } from '../../utils/colors'
import { ChevronUp, ChevronDown, Search } from 'lucide-react'

// ── Konstanten ─────────────────────────────────────────────────────────────────

/** Anzahl der Events pro Seite (fest kodiert) */
const PAGE_SIZE = 25

// ── Hauptkomponente ────────────────────────────────────────────────────────────

/**
 * Paginierte Tabelle aller forensischen Events.
 * Unterstützt Freitext-Filter über alle relevanten Felder und
 * Spalten-Sort per Klick auf die Tabellen-Header.
 *
 * @param {Object[]} timeline - Normalisierte Event-Liste
 */
export default function EventTable({ timeline }) {
  /** Aktuell sortierte Spalte — Standard: Zeitstempel */
  const [sortKey, setSortKey] = useState('timestamp')

  /** Sortierrichtung — true = aufsteigend, false = absteigend */
  const [sortAsc, setSortAsc] = useState(true)

  /** Aktiver Filtertext — wird auf mehrere Felder angewendet */
  const [filter, setFilter] = useState('')

  /** Aktuell angezeigte Seite (0-basiert) */
  const [page, setPage] = useState(0)

  // ── Gefilterte & sortierte Daten ─────────────────────────────────────────

  /**
   * Kombiniert Filter und Sortierung in einem einzigen useMemo.
   * Der Filter sucht case-insensitiv in: description, event_type/type,
   * source und event_id. Die Sortierung behandelt anomaly_score numerisch,
   * alle anderen Spalten lexikografisch via localeCompare.
   */
  const filtered = useMemo(() => {
    if (!timeline?.length) return []
    let data = [...timeline]

    // Freitext-Filter über die vier wichtigsten Felder
    if (filter) {
      const q = filter.toLowerCase()
      data = data.filter(e =>
        (e.description || '').toLowerCase().includes(q) ||
        (e.event_type || e.type || '').toLowerCase().includes(q) ||
        (e.source || '').toLowerCase().includes(q) ||
        (e.event_id || '').toLowerCase().includes(q)
      )
    }

    // Spalten-Sortierung — anomaly_score numerisch, Rest lexikografisch
    data.sort((a, b) => {
      let va = a[sortKey], vb = b[sortKey]
      if (sortKey === 'anomaly_score') {
        va = va || 0; vb = vb || 0
        return sortAsc ? va - vb : vb - va
      }
      if (va == null) return 1
      if (vb == null) return -1
      const cmp = String(va).localeCompare(String(vb))
      return sortAsc ? cmp : -cmp
    })

    return data
  }, [timeline, filter, sortKey, sortAsc])

  /** Gesamtzahl der Seiten basierend auf gefilterten Daten */
  const pageCount = Math.ceil(filtered.length / PAGE_SIZE)

  /** Events der aktuellen Seite */
  const pageData = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE)

  // ── Handler ───────────────────────────────────────────────────────────────

  /**
   * Wechselt die Sortierrichtung bei erneutem Klick auf dieselbe Spalte.
   * Bei einer neuen Spalte wird aufsteigend gestartet.
   *
   * @param {string} key - Spalten-Schlüssel (z.B. 'timestamp', 'anomaly_score')
   */
  const toggleSort = (key) => {
    if (sortKey === key) setSortAsc(!sortAsc)
    else { setSortKey(key); setSortAsc(true) }
  }

  // ── Hilfs-Komponente ──────────────────────────────────────────────────────

  /**
   * Rendert einen Sortier-Pfeil (auf/ab) neben dem aktiven Spalten-Header.
   * Gibt null zurück, wenn diese Spalte nicht die aktive Sortierspalte ist.
   *
   * @param {Object} props
   * @param {string} props.col - Spalten-Schlüssel
   */
  const SortIcon = ({ col }) => {
    if (sortKey !== col) return null
    return sortAsc
      ? <ChevronUp size={12} className="inline text-accent-blue" />
      : <ChevronDown size={12} className="inline text-accent-blue" />
  }

  // ── Empty State ───────────────────────────────────────────────────────────

  if (!timeline?.length) {
    return (
      <div className="glass-card flex items-center justify-center h-40">
        <span className="text-sm text-white/20">Keine Events</span>
      </div>
    )
  }

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="glass-card p-0 overflow-hidden">

      {/* ── Suchfeld ── */}
      <div className="p-3 border-b border-white/[0.04]">
        <div className="relative">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-white/20" />
          <input
            type="text"
            placeholder="Events filtern..."
            value={filter}
            onChange={(e) => { setFilter(e.target.value); setPage(0) }}
            className="w-full pl-9 pr-3 py-2 bg-white/[0.03] rounded-lg text-xs text-white/70 placeholder:text-white/20 border border-white/[0.04] focus:border-accent-blue/30 focus:outline-none transition-colors"
          />
        </div>
      </div>

      {/* ── Tabelle ── */}
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-white/[0.06]">
              {/* Spalten-Definitionen — key entspricht dem Event-Feldnamen */}
              {[
                { key: 'timestamp',    label: 'Zeitstempel' },
                { key: 'event_type',   label: 'Typ' },
                { key: 'description',  label: 'Beschreibung' },
                { key: 'source',       label: 'Quelle' },
                { key: 'anomaly_score', label: 'Score' },
              ].map(({ key, label }) => (
                <th
                  key={key}
                  onClick={() => toggleSort(key)}
                  className="text-left text-[10px] uppercase tracking-wider text-white/30 font-medium px-3 py-2 cursor-pointer hover:text-white/50 transition-colors"
                >
                  {label} <SortIcon col={key} />
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {pageData.map((event, i) => {
              const score = event.anomaly_score
              // Null-Prüfung: Score-Farbe nur berechnen wenn vorhanden
              const scoreColor = score ? getScoreColor(score) : null
              return (
                <tr
                  key={event.event_id || i}
                  className="border-b border-white/[0.02] hover:bg-white/[0.02] transition-colors"
                >
                  {/* Zeitstempel: Monospace-Font für einheitliche Spaltenbreite */}
                  <td className="px-3 py-2 text-xs font-mono text-white/40 whitespace-nowrap">
                    {formatTimestamp(event.timestamp || event.mtime)}
                  </td>
                  <td className="px-3 py-2 text-xs text-white/50">
                    {event.event_type || event.type || '—'}
                  </td>
                  {/* Beschreibung: max-width + truncate verhindert Layout-Brüche */}
                  <td className="px-3 py-2 text-xs text-white/60 max-w-[400px] truncate">
                    {event.description || event.name || '—'}
                  </td>
                  <td className="px-3 py-2 text-xs text-white/40 font-mono">
                    {event.source || '—'}
                  </td>
                  {/* Anomaly-Score: farbkodiert via getScoreColor, '—' wenn kein Score */}
                  <td className="px-3 py-2 text-xs font-mono whitespace-nowrap">
                    {score != null ? (
                      <span style={{ color: scoreColor?.hex }}>
                        {formatScore(score)}
                      </span>
                    ) : (
                      <span className="text-white/15">—</span>
                    )}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      {/* ── Pagination — nur anzeigen wenn mehr als eine Seite ── */}
      {pageCount > 1 && (
        <div className="flex items-center justify-between px-3 py-2 border-t border-white/[0.04]">
          <span className="text-[10px] text-white/25">
            {filtered.length} Events | Seite {page + 1} / {pageCount}
          </span>
          <div className="flex gap-1">
            <button
              onClick={() => setPage(Math.max(0, page - 1))}
              disabled={page === 0}
              className="px-2 py-1 text-[10px] rounded bg-white/[0.03] text-white/40 hover:bg-white/[0.06] disabled:opacity-30 transition-all"
            >
              Zurück
            </button>
            <button
              onClick={() => setPage(Math.min(pageCount - 1, page + 1))}
              disabled={page >= pageCount - 1}
              className="px-2 py-1 text-[10px] rounded bg-white/[0.03] text-white/40 hover:bg-white/[0.06] disabled:opacity-30 transition-all"
            >
              Weiter
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
