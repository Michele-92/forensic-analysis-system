import React, { useState, useMemo, useRef, useEffect } from 'react'
import { useApp } from '../context/AppContext'
import UploadZone from './UploadZone'
import StatusMonitor from './StatusMonitor'
import CaseModal from './CaseModal'
import { getRiskColor } from '../utils/colors'
import { formatTimestamp } from '../utils/formatters'
import {
  Shield, Trash2, HardDrive, FileText, MemoryStick, Network,
  FolderOpen, Folder, Plus, Search, ChevronDown, ChevronRight, X, Pencil,
  GitCompareArrows,
} from 'lucide-react'

const typeIcons = {
  disk_image: HardDrive,
  logs: FileText,
  ram_dump: MemoryStick,
  uac_dump: Network,
  unknown: FileText,
}

const STATUS_COLORS = {
  offen: '#3b82f6',
  in_bearbeitung: '#f97316',
  abgeschlossen: '#22c55e',
  archiviert: '#6b7280',
}

function getJobRiskLevel(job) {
  if (!job.data?.anomalies?.length) return 'info'
  const maxScore = Math.max(...job.data.anomalies.map(a => a.anomaly_score || 0))
  if (maxScore >= 0.8) return 'critical'
  if (maxScore >= 0.6) return 'high'
  if (maxScore >= 0.4) return 'medium'
  return 'low'
}

export default function Sidebar() {
  const {
    jobs, cases, activeJobId, setActiveJobId, deleteJob,
    addJobToCase, removeJobFromCase, createCase, updateCase, deleteCase, getCaseForJob,
    setCaseCorrelationView,
  } = useApp()

  const [expandedCases, setExpandedCases] = useState({})
  const [searchQuery, setSearchQuery] = useState('')
  const [caseModalOpen, setCaseModalOpen] = useState(false)
  const [dragOverCaseId, setDragOverCaseId] = useState(null)
  const [dragOverUngrouped, setDragOverUngrouped] = useState(false)
  const [renamingCaseId, setRenamingCaseId] = useState(null)
  const [renameValue, setRenameValue] = useState('')
  const renameRef = useRef(null)

  // Inline-Rename: Focus auf Input wenn aktiv
  useEffect(() => {
    if (renamingCaseId && renameRef.current) {
      renameRef.current.focus()
      renameRef.current.select()
    }
  }, [renamingCaseId])

  const startRename = (c) => {
    setRenamingCaseId(c.case_id)
    setRenameValue(c.case_name)
  }

  const commitRename = () => {
    if (renamingCaseId && renameValue.trim()) {
      updateCase(renamingCaseId, { case_name: renameValue.trim() })
    }
    setRenamingCaseId(null)
  }

  const cancelRename = () => {
    setRenamingCaseId(null)
  }

  // Jobs die in mindestens einem Fall sind
  const assignedJobIds = useMemo(() => {
    const ids = new Set()
    cases.forEach(c => c.job_ids.forEach(id => ids.add(id)))
    return ids
  }, [cases])

  // Ungroupierte Jobs (in keinem Fall)
  const ungroupedJobs = useMemo(() =>
    jobs.filter(j => !assignedJobIds.has(j.job_id)),
    [jobs, assignedJobIds]
  )

  // Suchfilter
  const matchesSearch = (text) => {
    if (!searchQuery.trim()) return true
    return text.toLowerCase().includes(searchQuery.toLowerCase())
  }

  const filteredCases = useMemo(() => {
    if (!searchQuery.trim()) return cases
    return cases.filter(c => {
      // Case-Name oder Aktenzeichen matcht
      if (matchesSearch(c.case_name) || matchesSearch(c.case_number || '')) return true
      // Oder ein Job im Case matcht
      const caseJobs = jobs.filter(j => c.job_ids.includes(j.job_id))
      return caseJobs.some(j => matchesSearch(j.filename))
    })
  }, [cases, jobs, searchQuery])

  const filteredUngrouped = useMemo(() => {
    if (!searchQuery.trim()) return ungroupedJobs
    return ungroupedJobs.filter(j => matchesSearch(j.filename))
  }, [ungroupedJobs, searchQuery])

  const toggleCase = (caseId) => {
    setExpandedCases(prev => ({ ...prev, [caseId]: !prev[caseId] }))
  }

  // Drag & Drop: Job zwischen Faellen und Ungroupiert verschieben
  const handleDragStart = (e, jobId, sourceCaseId = null) => {
    e.dataTransfer.setData('application/json', JSON.stringify({ jobId, sourceCaseId }))
    e.dataTransfer.effectAllowed = 'move'
  }

  const parseDragData = (e) => {
    try {
      return JSON.parse(e.dataTransfer.getData('application/json'))
    } catch { return null }
  }

  const handleDragOverCase = (e, caseId) => {
    e.preventDefault()
    e.dataTransfer.dropEffect = 'move'
    setDragOverCaseId(caseId)
  }

  const handleDragLeaveCase = () => {
    setDragOverCaseId(null)
  }

  const handleDropOnCase = (e, targetCaseId) => {
    e.preventDefault()
    setDragOverCaseId(null)
    const data = parseDragData(e)
    if (!data?.jobId) return
    // Aus altem Fall entfernen (falls vorhanden und anderer Fall)
    if (data.sourceCaseId && data.sourceCaseId !== targetCaseId) {
      removeJobFromCase(data.sourceCaseId, data.jobId)
    }
    // Zum neuen Fall hinzufuegen
    addJobToCase(targetCaseId, data.jobId)
    setExpandedCases(prev => ({ ...prev, [targetCaseId]: true }))
  }

  // Drop auf "Ungroupiert" — Job aus Fall entfernen
  const handleDragOverUngrouped = (e) => {
    e.preventDefault()
    e.dataTransfer.dropEffect = 'move'
    setDragOverUngrouped(true)
  }

  const handleDragLeaveUngrouped = () => {
    setDragOverUngrouped(false)
  }

  const handleDropOnUngrouped = (e) => {
    e.preventDefault()
    setDragOverUngrouped(false)
    const data = parseDragData(e)
    if (!data?.jobId || !data.sourceCaseId) return
    removeJobFromCase(data.sourceCaseId, data.jobId)
  }

  return (
    <aside className="w-[280px] h-screen flex flex-col border-r border-white/[0.06] bg-surface-50/50">
      {/* Logo */}
      <div className="flex items-center gap-3 px-5 h-14 border-b border-white/[0.06]">
        <Shield size={20} className="text-accent-blue" />
        <div>
          <h1 className="text-sm font-semibold tracking-tight">LFX</h1>
          <p className="text-[10px] text-white/30 -mt-0.5">Forensic Analysis System</p>
        </div>
      </div>

      {/* Search */}
      <div className="px-3 pt-3 pb-1">
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-white/[0.03] border border-white/[0.06]">
          <Search size={12} className="text-white/20 flex-shrink-0" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Suchen..."
            className="flex-1 bg-transparent text-xs text-white/70 placeholder-white/20 outline-none"
          />
          {searchQuery && (
            <button onClick={() => setSearchQuery('')} className="text-white/20 hover:text-white/40">
              <X size={12} />
            </button>
          )}
        </div>
      </div>

      {/* Scrollable Tree */}
      <div className="flex-1 overflow-y-auto py-1">
        {/* ── Cases Section ── */}
        <div className="flex items-center justify-between px-4 py-2">
          <span className="text-[10px] font-medium uppercase tracking-widest text-white/25">
            Faelle
          </span>
          <button
            onClick={() => setCaseModalOpen(true)}
            className="p-1 rounded hover:bg-white/10 transition-all"
            title="Neuer Fall"
          >
            <Plus size={12} className="text-white/30" />
          </button>
        </div>

        {filteredCases.length === 0 && !searchQuery && (
          <div className="px-5 py-2">
            <p className="text-[10px] text-white/15">Noch keine Faelle erstellt</p>
          </div>
        )}

        {filteredCases.map((c) => {
          const isExpanded = !!expandedCases[c.case_id]
          const caseJobs = jobs.filter(j => c.job_ids.includes(j.job_id))
          const statusColor = STATUS_COLORS[c.status] || '#6b7280'
          const isDragOver = dragOverCaseId === c.case_id

          return (
            <div key={c.case_id}>
              {/* Case Header */}
              <div
                onClick={() => toggleCase(c.case_id)}
                onDragOver={(e) => handleDragOverCase(e, c.case_id)}
                onDragLeave={handleDragLeaveCase}
                onDrop={(e) => handleDropOnCase(e, c.case_id)}
                className={`
                  group flex items-center gap-2 mx-2 px-3 py-2 rounded-xl cursor-pointer
                  transition-all duration-200
                  ${isDragOver
                    ? 'bg-accent-blue/10 border border-accent-blue/30'
                    : 'hover:bg-white/[0.03] border border-transparent'
                  }
                `}
              >
                {/* Chevron */}
                <div className="flex-shrink-0">
                  {isExpanded
                    ? <ChevronDown size={12} className="text-white/30" />
                    : <ChevronRight size={12} className="text-white/30" />
                  }
                </div>

                {/* Status LED */}
                <div
                  className="w-2 h-2 rounded-full flex-shrink-0"
                  style={{ backgroundColor: statusColor, boxShadow: `0 0 6px ${statusColor}` }}
                />

                {/* Folder Icon */}
                {isExpanded
                  ? <FolderOpen size={13} className="text-accent-blue flex-shrink-0" />
                  : <Folder size={13} className="text-white/30 flex-shrink-0" />
                }

                {/* Info */}
                <div className="flex-1 min-w-0">
                  {renamingCaseId === c.case_id ? (
                    <input
                      ref={renameRef}
                      value={renameValue}
                      onChange={(e) => setRenameValue(e.target.value)}
                      onBlur={commitRename}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') commitRename()
                        if (e.key === 'Escape') cancelRename()
                      }}
                      onClick={(e) => e.stopPropagation()}
                      className="w-full text-xs font-medium text-white/80 bg-white/[0.06] border border-accent-blue/40 rounded px-1.5 py-0.5 outline-none"
                    />
                  ) : (
                    <span
                      className="text-xs font-medium text-white/80 truncate block"
                      onDoubleClick={(e) => { e.stopPropagation(); startRename(c) }}
                    >
                      {c.case_name}
                    </span>
                  )}
                  <div className="flex items-center gap-1.5">
                    {c.case_number && (
                      <span className="text-[10px] text-white/25 font-mono">{c.case_number}</span>
                    )}
                    <span className="text-[10px] text-white/20">{caseJobs.length} Analysen</span>
                  </div>
                </div>

                {/* Case Actions */}
                <div className="flex items-center gap-0.5 opacity-0 group-hover:opacity-100 transition-all">
                  <button
                    onClick={(e) => { e.stopPropagation(); startRename(c) }}
                    className="p-1 rounded hover:bg-white/10 transition-all"
                    title="Umbenennen"
                  >
                    <Pencil size={10} className="text-white/30" />
                  </button>
                  <button
                    onClick={(e) => {
                      e.stopPropagation()
                      deleteCase(c.case_id)
                    }}
                    className="p-1 rounded hover:bg-white/10 transition-all"
                    title="Fall loeschen"
                  >
                    <Trash2 size={10} className="text-white/30" />
                  </button>
                </div>
              </div>

              {/* Expanded: Nested Jobs */}
              {isExpanded && (
                <div className="ml-5 border-l border-white/[0.06] pl-0.5">
                  {caseJobs.length === 0 && (
                    <div className="px-4 py-2">
                      <p className="text-[10px] text-white/15">Keine Analysen zugeordnet</p>
                    </div>
                  )}
                  {caseJobs.map((job) => (
                    <JobItem
                      key={job.job_id}
                      job={job}
                      isActive={job.job_id === activeJobId}
                      onClick={() => { setCaseCorrelationView(null); setActiveJobId(job.job_id) }}
                      onDelete={() => deleteJob(job.job_id)}
                      onRemoveFromCase={() => removeJobFromCase(c.case_id, job.job_id)}
                      nested
                      draggable
                      onDragStart={(e) => handleDragStart(e, job.job_id, c.case_id)}
                    />
                  ))}
                  {/* Fallkorrelation Button — nur wenn ≥2 abgeschlossene Jobs */}
                  {caseJobs.filter(j => j.status === 'completed').length >= 2 && (
                    <button
                      onClick={() => {
                        setActiveJobId(null)
                        setCaseCorrelationView(c.case_id)
                      }}
                      className="flex items-center gap-2 mx-2 px-3 py-1.5 mt-1 mb-1 rounded-lg text-[11px] font-medium text-cyan-400 bg-cyan-500/5 hover:bg-cyan-500/10 transition-all w-[calc(100%-16px)]"
                    >
                      <GitCompareArrows size={12} />
                      Fallkorrelation
                    </button>
                  )}
                </div>
              )}
            </div>
          )
        })}

        {/* ── Separator ── */}
        {(filteredCases.length > 0 || cases.length > 0) && (
          <div className="h-px bg-white/[0.06] mx-4 my-2" />
        )}

        {/* ── Ungrouped Jobs (Drop-Zone) ── */}
        <div
          onDragOver={handleDragOverUngrouped}
          onDragLeave={handleDragLeaveUngrouped}
          onDrop={handleDropOnUngrouped}
        >
          <div className={`
            mx-2 px-2 py-2 rounded-xl transition-all duration-200
            ${dragOverUngrouped
              ? 'bg-accent-blue/10 border border-dashed border-accent-blue/30'
              : 'border border-transparent'
            }
          `}>
            <span className="text-[10px] font-medium uppercase tracking-widest text-white/25 px-2">
              Ungroupiert
            </span>
            {dragOverUngrouped && (
              <span className="text-[10px] text-accent-blue/50 ml-2">Hier ablegen</span>
            )}
          </div>

          {filteredUngrouped.length === 0 && jobs.length === 0 && (
            <div className="px-5 py-4 text-center">
              <p className="text-xs text-white/20">Keine Analysen vorhanden</p>
              <p className="text-[10px] text-white/10 mt-1">Lade ein forensisches Image hoch</p>
            </div>
          )}

          {filteredUngrouped.length === 0 && ungroupedJobs.length > 0 && searchQuery && (
            <div className="px-5 py-2">
              <p className="text-[10px] text-white/15">Keine Treffer</p>
            </div>
          )}

          {filteredUngrouped.map((job) => (
            <JobItem
              key={job.job_id}
              job={job}
              isActive={job.job_id === activeJobId}
              onClick={() => { setCaseCorrelationView(null); setActiveJobId(job.job_id) }}
              onDelete={() => deleteJob(job.job_id)}
              draggable
              onDragStart={(e) => handleDragStart(e, job.job_id)}
            />
          ))}
        </div>
      </div>

      {/* Pipeline Status */}
      <StatusMonitor />

      {/* Upload Zone */}
      <div className="border-t border-white/[0.06]">
        <UploadZone />
      </div>

      {/* Case Modal */}
      {caseModalOpen && (
        <CaseModal
          onSave={(data) => createCase(data)}
          onClose={() => setCaseModalOpen(false)}
        />
      )}
    </aside>
  )
}

/** Einzelne Job-Zeile (wiederverwendbar fuer nested + ungroupiert) */
function JobItem({ job, isActive, onClick, onDelete, onRemoveFromCase, nested, draggable, onDragStart }) {
  const risk = job.status === 'completed' ? getJobRiskLevel(job) : 'info'
  const riskColor = getRiskColor(risk)
  const TypeIcon = typeIcons[job.input_type] || FileText

  return (
    <div
      onClick={onClick}
      draggable={draggable}
      onDragStart={onDragStart}
      className={`
        group flex items-start gap-2.5 mx-2 px-3 py-2 rounded-xl cursor-pointer
        transition-all duration-200
        ${isActive
          ? 'bg-white/[0.06] border border-white/[0.08]'
          : 'hover:bg-white/[0.03] border border-transparent'
        }
        ${draggable ? 'cursor-grab active:cursor-grabbing select-none' : ''}
      `}
    >
      {/* LED */}
      <div className="mt-1.5 flex-shrink-0">
        {job.status === 'processing' ? (
          <div className="w-2 h-2 rounded-full bg-accent-blue animate-pulse" style={{ boxShadow: '0 0 6px #3b82f6' }} />
        ) : job.status === 'failed' ? (
          <div className="w-2 h-2 rounded-full bg-risk-critical" style={{ boxShadow: '0 0 6px #ef4444' }} />
        ) : (
          <div className="w-2 h-2 rounded-full" style={{ backgroundColor: riskColor.hex, boxShadow: `0 0 6px ${riskColor.hex}` }} />
        )}
      </div>

      {/* Info */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-1.5">
          <TypeIcon size={12} className="text-white/30 flex-shrink-0" />
          <span className={`font-medium text-white/80 truncate ${nested ? 'text-[11px]' : 'text-xs'}`}>
            {job.filename}
          </span>
        </div>
        <span className="text-[10px] text-white/25 font-mono">
          {formatTimestamp(job.created_at)}
        </span>
        {job.status === 'processing' && (
          <div className="mt-1 h-0.5 bg-white/[0.06] rounded-full overflow-hidden">
            <div
              className="h-full bg-accent-blue rounded-full transition-all duration-300"
              style={{ width: `${job.progress || 0}%` }}
            />
          </div>
        )}
      </div>

      {/* Actions */}
      <div className="flex flex-col gap-0.5 opacity-0 group-hover:opacity-100 transition-all">
        {onRemoveFromCase && (
          <button
            onClick={(e) => { e.stopPropagation(); onRemoveFromCase() }}
            className="p-1 rounded hover:bg-white/10 transition-all"
            title="Aus Fall entfernen"
          >
            <X size={10} className="text-white/30" />
          </button>
        )}
        <button
          onClick={(e) => { e.stopPropagation(); onDelete() }}
          className="p-1 rounded hover:bg-white/10 transition-all"
        >
          <Trash2 size={10} className="text-white/30" />
        </button>
      </div>
    </div>
  )
}
