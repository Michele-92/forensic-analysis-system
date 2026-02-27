import React, { useState, useMemo } from 'react'
import RiskBadge from '../RiskBadge'
import { formatTimestamp, formatScore } from '../../utils/formatters'
import { getScoreColor } from '../../utils/colors'
import { ChevronUp, ChevronDown, Search } from 'lucide-react'

const PAGE_SIZE = 25

export default function EventTable({ timeline }) {
  const [sortKey, setSortKey] = useState('timestamp')
  const [sortAsc, setSortAsc] = useState(true)
  const [filter, setFilter] = useState('')
  const [page, setPage] = useState(0)

  const filtered = useMemo(() => {
    if (!timeline?.length) return []
    let data = [...timeline]

    if (filter) {
      const q = filter.toLowerCase()
      data = data.filter(e =>
        (e.description || '').toLowerCase().includes(q) ||
        (e.event_type || e.type || '').toLowerCase().includes(q) ||
        (e.source || '').toLowerCase().includes(q) ||
        (e.event_id || '').toLowerCase().includes(q)
      )
    }

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

  const pageCount = Math.ceil(filtered.length / PAGE_SIZE)
  const pageData = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE)

  const toggleSort = (key) => {
    if (sortKey === key) setSortAsc(!sortAsc)
    else { setSortKey(key); setSortAsc(true) }
  }

  const SortIcon = ({ col }) => {
    if (sortKey !== col) return null
    return sortAsc
      ? <ChevronUp size={12} className="inline text-accent-blue" />
      : <ChevronDown size={12} className="inline text-accent-blue" />
  }

  if (!timeline?.length) {
    return (
      <div className="glass-card flex items-center justify-center h-40">
        <span className="text-sm text-white/20">Keine Events</span>
      </div>
    )
  }

  return (
    <div className="glass-card p-0 overflow-hidden">
      {/* Search */}
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

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-white/[0.06]">
              {[
                { key: 'timestamp', label: 'Zeitstempel' },
                { key: 'event_type', label: 'Typ' },
                { key: 'description', label: 'Beschreibung' },
                { key: 'source', label: 'Quelle' },
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
              const scoreColor = score ? getScoreColor(score) : null
              return (
                <tr
                  key={event.event_id || i}
                  className="border-b border-white/[0.02] hover:bg-white/[0.02] transition-colors"
                >
                  <td className="px-3 py-2 text-xs font-mono text-white/40 whitespace-nowrap">
                    {formatTimestamp(event.timestamp || event.mtime)}
                  </td>
                  <td className="px-3 py-2 text-xs text-white/50">
                    {event.event_type || event.type || '—'}
                  </td>
                  <td className="px-3 py-2 text-xs text-white/60 max-w-[400px] truncate">
                    {event.description || event.name || '—'}
                  </td>
                  <td className="px-3 py-2 text-xs text-white/40 font-mono">
                    {event.source || '—'}
                  </td>
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

      {/* Pagination */}
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
