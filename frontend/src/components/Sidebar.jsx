/**
 * ============================================================================
 * SIDEBAR — Job & Fall-Verwaltung (linke Navigation, 280px)
 * ============================================================================
 * Zentrales Navigationselement der Anwendung. Zeigt alle laufenden und
 * abgeschlossenen Analyse-Jobs in einer hierarchischen Baumstruktur mit
 * optionaler Fall-Gruppierung (Cases).
 *
 * Funktionen:
 *   - Drag & Drop Upload für neue forensische Dateien (via UploadZone)
 *   - Job-Liste mit farbkodierten LED-Status-Indikatoren
 *     (blau = läuft, grün = abgeschlossen, rot = fehlgeschlagen,
 *      Risikofarbe nach Anomalie-Score bei abgeschlossenen Jobs)
 *   - Fall-Verwaltung: Erstellen (CaseModal), Umbenennen (Inline-Edit),
 *     Löschen, Drag & Drop Zuweisung von Jobs zu Fällen
 *   - Ungroupiert-Bereich als Drop-Zone zum Entfernen aus Fällen
 *   - Fallkorrelations-Trigger (sichtbar wenn ≥2 abgeschlossene Jobs im Fall)
 *   - Live-Suche über Fall-Namen, Aktenzeichen und Dateinamen
 *   - Pipeline-Fortschritt (StatusMonitor) am unteren Rand
 *
 * Props: keine (liest und schreibt globalen State via useApp Context)
 *
 * Abhängigkeiten:
 *   - AppContext (useApp): jobs, cases, activeJobId, CRUD-Operationen
 *   - UploadZone: Drag-Drop Upload-Bereich am unteren Rand
 *   - StatusMonitor: Pipeline-Fortschrittsanzeige
 *   - CaseModal: Modal zur Fall-Erstellung
 *   - utils/colors (getRiskColor): Farbzuordnung nach Risikostufe
 *   - utils/formatters (formatTimestamp): Zeitstempel-Formatierung
 *
 * @component
 */

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

// ── Konstanten ─────────────────────────────────────────────────────────────

/** Ordnet jeden bekannten Input-Typ ein Lucide-Icon zu (für die Job-Zeile). */
const typeIcons = {
  disk_image: HardDrive,
  logs: FileText,
  ram_dump: MemoryStick,
  uac_dump: Network,
  unknown: FileText,
}

/** Farbkodierung der Fall-Status-LEDs (Badge neben dem Ordner-Icon). */
const STATUS_COLORS = {
  offen: '#3b82f6',
  in_bearbeitung: '#f97316',
  abgeschlossen: '#22c55e',
  archiviert: '#6b7280',
}

// ── Hilfsfunktionen ────────────────────────────────────────────────────────

/**
 * Berechnet die Risikostufe eines abgeschlossenen Jobs anhand des höchsten
 * Anomalie-Scores in den Ergebnisdaten.
 *
 * @param {Object} job - Job-Objekt aus dem globalen State
 * @returns {'critical'|'high'|'medium'|'low'|'info'} Risikostufe als String
 */
function getJobRiskLevel(job) {
  if (!job.data?.anomalies?.length) return 'info'
  const maxScore = Math.max(...job.data.anomalies.map(a => a.anomaly_score || 0))
  if (maxScore >= 0.8) return 'critical'
  if (maxScore >= 0.6) return 'high'
  if (maxScore >= 0.4) return 'medium'
  return 'low'
}

// ── Hauptkomponente ────────────────────────────────────────────────────────

export default function Sidebar() {
  const {
    jobs, cases, activeJobId, setActiveJobId, deleteJob,
    addJobToCase, removeJobFromCase, createCase, updateCase, deleteCase, getCaseForJob,
    setCaseCorrelationView,
  } = useApp()

  // ── Lokaler State ──────────────────────────────────────────────────────

  /** Speichert welche Fälle im Baum aufgeklappt sind (caseId → boolean). */
  const [expandedCases, setExpandedCases] = useState({})

  /** Aktueller Suchbegriff für die Live-Filterung. */
  const [searchQuery, setSearchQuery] = useState('')

  /** Steuert ob das CaseModal (Fall-Erstellung) geöffnet ist. */
  const [caseModalOpen, setCaseModalOpen] = useState(false)

  /** caseId des Falls über dem gerade ein Job-Drag stattfindet (Highlight). */
  const [dragOverCaseId, setDragOverCaseId] = useState(null)

  /** true wenn ein Job-Drag über dem "Ungroupiert"-Bereich ist. */
  const [dragOverUngrouped, setDragOverUngrouped] = useState(false)

  /** caseId des Falls dessen Name gerade inline editiert wird. */
  const [renamingCaseId, setRenamingCaseId] = useState(null)

  /** Puffer für den neuen Namen während des Inline-Renames. */
  const [renameValue, setRenameValue] = useState('')

  /** Ref auf das Inline-Rename-Input für automatischen Fokus. */
  const renameRef = useRef(null)

  // ── Inline-Rename Logik ────────────────────────────────────────────────

  /**
   * Fokussiert und selektiert das Rename-Input sobald es eingeblendet wird,
   * damit der Nutzer sofort tippen kann ohne klicken zu müssen.
   */
  useEffect(() => {
    if (renamingCaseId && renameRef.current) {
      renameRef.current.focus()
      renameRef.current.select()
    }
  }, [renamingCaseId])

  /** Aktiviert den Inline-Rename-Modus für einen Fall. */
  const startRename = (c) => {
    setRenamingCaseId(c.case_id)
    setRenameValue(c.case_name)
  }

  /** Speichert den neuen Namen (wird bei Blur und Enter ausgelöst). */
  const commitRename = async () => {
    if (renamingCaseId && renameValue.trim()) {
      await updateCase(renamingCaseId, { case_name: renameValue.trim() })
    }
    setRenamingCaseId(null)
  }

  /** Verwirft den Rename ohne zu speichern (wird bei Escape ausgelöst). */
  const cancelRename = () => {
    setRenamingCaseId(null)
  }

  // ── Berechnete Listen (memoized) ───────────────────────────────────────

  /**
   * Set aller Job-IDs die mindestens einem Fall zugeordnet sind.
   * Wird genutzt um "Ungroupiert"-Jobs effizient zu berechnen.
   */
  const assignedJobIds = useMemo(() => {
    const ids = new Set()
    cases.forEach(c => c.job_ids.forEach(id => ids.add(id)))
    return ids
  }, [cases])

  /** Alle Jobs die in keinem Fall sind (erscheinen im Ungroupiert-Bereich). */
  const ungroupedJobs = useMemo(() =>
    jobs.filter(j => !assignedJobIds.has(j.job_id)),
    [jobs, assignedJobIds]
  )

  /**
   * Prüft ob ein Text-String den aktuellen Suchbegriff enthält (case-insensitive).
   * Leere Suche matcht immer.
   */
  const matchesSearch = (text) => {
    if (!searchQuery.trim()) return true
    return text.toLowerCase().includes(searchQuery.toLowerCase())
  }

  /**
   * Gefilterte Fall-Liste: Ein Fall ist sichtbar wenn sein Name, Aktenzeichen
   * oder mindestens ein zugehöriger Dateiname den Suchbegriff enthält.
   */
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

  /** Gefilterte Liste der ungroupierten Jobs nach Suchbegriff. */
  const filteredUngrouped = useMemo(() => {
    if (!searchQuery.trim()) return ungroupedJobs
    return ungroupedJobs.filter(j => matchesSearch(j.filename))
  }, [ungroupedJobs, searchQuery])

  // ── Baum-Navigation ────────────────────────────────────────────────────

  /** Schaltet einen Fall im Baum ein- oder aus. */
  const toggleCase = (caseId) => {
    setExpandedCases(prev => ({ ...prev, [caseId]: !prev[caseId] }))
  }

  // ── Drag & Drop Handlers ───────────────────────────────────────────────

  /**
   * Speichert die Job-ID und den Quell-Fall im DataTransfer beim Start
   * eines Drags, damit der Drop-Handler weiß was verschoben wird.
   *
   * @param {DragEvent} e
   * @param {string} jobId - ID des gezogenen Jobs
   * @param {string|null} sourceCaseId - Fall-ID aus der gezogen wird (null = ungroupiert)
   */
  const handleDragStart = (e, jobId, sourceCaseId = null) => {
    e.dataTransfer.setData('application/json', JSON.stringify({ jobId, sourceCaseId }))
    e.dataTransfer.effectAllowed = 'move'
  }

  /**
   * Liest die beim Drag gespeicherten Daten sicher aus dem DataTransfer.
   * Gibt null zurück wenn das Format nicht stimmt (fremde Drag-Quellen).
   */
  const parseDragData = (e) => {
    try {
      return JSON.parse(e.dataTransfer.getData('application/json'))
    } catch { return null }
  }

  /** Aktiviert visuelles Drag-Highlight für den Ziel-Fall. */
  const handleDragOverCase = (e, caseId) => {
    e.preventDefault()
    e.dataTransfer.dropEffect = 'move'
    setDragOverCaseId(caseId)
  }

  /** Entfernt Drag-Highlight wenn der Cursor den Fall-Header verlässt. */
  const handleDragLeaveCase = () => {
    setDragOverCaseId(null)
  }

  /**
   * Verarbeitet einen Drop auf einem Fall-Header:
   * Entfernt den Job aus dem Quell-Fall (wenn vorhanden und anders)
   * und fügt ihn dem Ziel-Fall hinzu. Klappt den Ziel-Fall auf.
   */
  const handleDropOnCase = async (e, targetCaseId) => {
    e.preventDefault()
    setDragOverCaseId(null)
    const data = parseDragData(e)
    if (!data?.jobId) return
    // Aus altem Fall entfernen (falls vorhanden und anderer Fall)
    if (data.sourceCaseId && data.sourceCaseId !== targetCaseId) {
      await removeJobFromCase(data.sourceCaseId, data.jobId)
    }
    // Zum neuen Fall hinzufuegen
    await addJobToCase(targetCaseId, data.jobId)
    setExpandedCases(prev => ({ ...prev, [targetCaseId]: true }))
  }

  /** Aktiviert visuelles Drag-Highlight für den Ungroupiert-Bereich. */
  const handleDragOverUngrouped = (e) => {
    e.preventDefault()
    e.dataTransfer.dropEffect = 'move'
    setDragOverUngrouped(true)
  }

  /** Entfernt Drag-Highlight wenn der Cursor den Ungroupiert-Bereich verlässt. */
  const handleDragLeaveUngrouped = () => {
    setDragOverUngrouped(false)
  }

  /**
   * Drop auf "Ungroupiert" — entfernt den Job aus seinem bisherigen Fall.
   * Nur sinnvoll wenn sourceCaseId gesetzt ist (Job kam aus einem Fall).
   */
  const handleDropOnUngrouped = async (e) => {
    e.preventDefault()
    setDragOverUngrouped(false)
    const data = parseDragData(e)
    if (!data?.jobId || !data.sourceCaseId) return
    await removeJobFromCase(data.sourceCaseId, data.jobId)
  }

  // ── Render ─────────────────────────────────────────────────────────────

  return (
    <aside className="w-[280px] h-screen flex flex-col border-r border-white/[0.06] bg-surface-50/50">

      {/* ── Logo / App-Titel ──────────────────────────────────────────── */}
      <div className="flex items-center gap-3 px-5 h-14 border-b border-white/[0.06]">
        <Shield size={20} className="text-accent-blue" />
        <div>
          <h1 className="text-sm font-semibold tracking-tight">LFX</h1>
          <p className="text-[10px] text-white/30 -mt-0.5">Forensic Analysis System</p>
        </div>
      </div>

      {/* ── Suchfeld ──────────────────────────────────────────────────── */}
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
          {/* X-Button erscheint nur wenn Suchbegriff aktiv ist */}
          {searchQuery && (
            <button onClick={() => setSearchQuery('')} className="text-white/20 hover:text-white/40">
              <X size={12} />
            </button>
          )}
        </div>
      </div>

      {/* ── Scrollbarer Job/Fall-Baum ──────────────────────────────────── */}
      <div className="flex-1 overflow-y-auto py-1">

        {/* ── Fälle-Sektion ──────────────────────────────────────────── */}
        <div className="flex items-center justify-between px-4 py-2">
          <span className="text-[10px] font-medium uppercase tracking-widest text-white/25">
            Faelle
          </span>
          {/* Button öffnet CaseModal zur Erstellung eines neuen Falls */}
          <button
            onClick={() => setCaseModalOpen(true)}
            className="p-1 rounded hover:bg-white/10 transition-all"
            title="Neuer Fall"
          >
            <Plus size={12} className="text-white/30" />
          </button>
        </div>

        {/* Leer-Zustand: keine Fälle vorhanden und keine aktive Suche */}
        {filteredCases.length === 0 && !searchQuery && (
          <div className="px-5 py-2">
            <p className="text-[10px] text-white/15">Noch keine Faelle erstellt</p>
          </div>
        )}

        {/* ── Fall-Einträge (aufklappbar) ────────────────────────────── */}
        {filteredCases.map((c) => {
          const isExpanded = !!expandedCases[c.case_id]
          const caseJobs = jobs.filter(j => c.job_ids.includes(j.job_id))
          const statusColor = STATUS_COLORS[c.status] || '#6b7280'
          const isDragOver = dragOverCaseId === c.case_id

          return (
            <div key={c.case_id}>
              {/* Fall-Header: Klick = aufklappen, Drag-Over = Highlight */}
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
                {/* Chevron zeigt Aufklapp-Zustand */}
                <div className="flex-shrink-0">
                  {isExpanded
                    ? <ChevronDown size={12} className="text-white/30" />
                    : <ChevronRight size={12} className="text-white/30" />
                  }
                </div>

                {/* Status-LED: Farbe entspricht dem Fall-Status (offen/in_bearbeitung/...) */}
                <div
                  className="w-2 h-2 rounded-full flex-shrink-0"
                  style={{ backgroundColor: statusColor, boxShadow: `0 0 6px ${statusColor}` }}
                />

                {/* Ordner-Icon wechselt zwischen offen/geschlossen */}
                {isExpanded
                  ? <FolderOpen size={13} className="text-accent-blue flex-shrink-0" />
                  : <Folder size={13} className="text-white/30 flex-shrink-0" />
                }

                {/* Fall-Metadaten: Name (Inline-Edit per Doppelklick) und Aktenzeichen */}
                <div className="flex-1 min-w-0">
                  {renamingCaseId === c.case_id ? (
                    // Inline-Rename Input: Blur/Enter = speichern, Escape = abbrechen
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
                    // Doppelklick aktiviert Inline-Rename
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

                {/* Fall-Aktionen (erscheinen beim Hover): Umbenennen & Löschen */}
                <div className="flex items-center gap-0.5 opacity-0 group-hover:opacity-100 transition-all">
                  <button
                    onClick={(e) => { e.stopPropagation(); startRename(c) }}
                    className="p-1 rounded hover:bg-white/10 transition-all"
                    title="Umbenennen"
                  >
                    <Pencil size={10} className="text-white/30" />
                  </button>
                  <button
                    onClick={async (e) => {
                      e.stopPropagation()
                      await deleteCase(c.case_id)
                    }}
                    className="p-1 rounded hover:bg-white/10 transition-all"
                    title="Fall loeschen"
                  >
                    <Trash2 size={10} className="text-white/30" />
                  </button>
                </div>
              </div>

              {/* Aufgeklappte Job-Liste: Zeigt alle dem Fall zugeordneten Jobs */}
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
                      onRemoveFromCase={async () => await removeJobFromCase(c.case_id, job.job_id)}
                      nested
                      draggable
                      onDragStart={(e) => handleDragStart(e, job.job_id, c.case_id)}
                    />
                  ))}
                  {/* Fallkorrelations-Button — nur sichtbar wenn ≥2 abgeschlossene Jobs vorhanden */}
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

        {/* Trennlinie zwischen Fälle-Sektion und Ungroupiert-Sektion */}
        {(filteredCases.length > 0 || cases.length > 0) && (
          <div className="h-px bg-white/[0.06] mx-4 my-2" />
        )}

        {/* ── Ungroupiert-Sektion (Drop-Zone) ────────────────────────── */}
        {/* Jobs die hier abgelegt werden, werden aus ihrem Fall entfernt */}
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
            {/* Hinweis-Label erscheint während eines aktiven Drags */}
            {dragOverUngrouped && (
              <span className="text-[10px] text-accent-blue/50 ml-2">Hier ablegen</span>
            )}
          </div>

          {/* Leer-Zustand: noch keine Jobs in der gesamten App */}
          {filteredUngrouped.length === 0 && jobs.length === 0 && (
            <div className="px-5 py-4 text-center">
              <p className="text-xs text-white/20">Keine Analysen vorhanden</p>
              <p className="text-[10px] text-white/10 mt-1">Lade ein forensisches Image hoch</p>
            </div>
          )}

          {/* Leer-Zustand: Jobs vorhanden aber Suche filtert alle heraus */}
          {filteredUngrouped.length === 0 && ungroupedJobs.length > 0 && searchQuery && (
            <div className="px-5 py-2">
              <p className="text-[10px] text-white/15">Keine Treffer</p>
            </div>
          )}

          {/* Ungroupierte Job-Einträge */}
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

      {/* ── Pipeline-Status (erscheint nur wenn ein Job aktiv läuft) ──── */}
      <StatusMonitor />

      {/* ── Upload-Zone (Drag & Drop / Klick-Upload) ─────────────────── */}
      <div className="border-t border-white/[0.06]">
        <UploadZone />
      </div>

      {/* ── Fall-Erstellungs-Modal ─────────────────────────────────────── */}
      {caseModalOpen && (
        <CaseModal
          onSave={async (data) => await createCase(data)}
          onClose={() => setCaseModalOpen(false)}
        />
      )}
    </aside>
  )
}

// ── JobItem ────────────────────────────────────────────────────────────────

/**
 * Einzelne Job-Zeile in der Sidebar-Liste.
 * Wird sowohl für gruppierte (nested) als auch für ungroupierte Jobs verwendet.
 *
 * Zeigt:
 *   - LED-Indikator: pulsierend blau (läuft), rot (fehlgeschlagen),
 *     Risikofarbe (abgeschlossen, basierend auf maximalem Anomalie-Score)
 *   - Input-Typ-Icon (HardDrive / FileText / MemoryStick / Network)
 *   - Dateiname (abgekürzt) und Upload-Zeitstempel
 *   - Mini-Fortschrittsbalken während aktiver Analyse
 *   - Hover-Aktionen: Aus Fall entfernen (optional) und Löschen
 *
 * @param {Object}   props
 * @param {Object}   props.job              - Job-Objekt aus dem globalen State
 * @param {boolean}  props.isActive         - Ob dieser Job gerade ausgewählt ist
 * @param {Function} props.onClick          - Callback beim Klick auf die Zeile
 * @param {Function} props.onDelete         - Callback zum Löschen des Jobs
 * @param {Function} [props.onRemoveFromCase] - Callback zum Entfernen aus dem Fall (nur nested)
 * @param {boolean}  [props.nested]         - Kleinere Schrift wenn innerhalb eines Falls
 * @param {boolean}  [props.draggable]      - Ob der Eintrag per Drag verschoben werden kann
 * @param {Function} [props.onDragStart]    - DragStart-Handler (wird vom Parent gesetzt)
 */
function JobItem({ job, isActive, onClick, onDelete, onRemoveFromCase, nested, draggable, onDragStart }) {
  // Risikostufe nur für abgeschlossene Jobs berechnen, sonst 'info'
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
      {/* LED-Statusindikator: Farbe und Animation je nach Job-Status */}
      <div className="mt-1.5 flex-shrink-0">
        {job.status === 'processing' ? (
          // Pulsierend blau = Job läuft gerade
          <div className="w-2 h-2 rounded-full bg-accent-blue animate-pulse" style={{ boxShadow: '0 0 6px #3b82f6' }} />
        ) : job.status === 'failed' ? (
          // Rot = Analyse fehlgeschlagen
          <div className="w-2 h-2 rounded-full bg-risk-critical" style={{ boxShadow: '0 0 6px #ef4444' }} />
        ) : (
          // Risikofarbe = Analyse abgeschlossen (grün/gelb/orange/rot je Score)
          <div className="w-2 h-2 rounded-full" style={{ backgroundColor: riskColor.hex, boxShadow: `0 0 6px ${riskColor.hex}` }} />
        )}
      </div>

      {/* Job-Metadaten: Icon, Dateiname, Zeitstempel und optionaler Fortschrittsbalken */}
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
        {/* Fortschrittsbalken nur während aktiver Analyse sichtbar */}
        {job.status === 'processing' && (
          <div className="mt-1 h-0.5 bg-white/[0.06] rounded-full overflow-hidden">
            <div
              className="h-full bg-accent-blue rounded-full transition-all duration-300"
              style={{ width: `${job.progress || 0}%` }}
            />
          </div>
        )}
      </div>

      {/* Hover-Aktionen: "Aus Fall entfernen" (nur nested) und "Löschen" */}
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
