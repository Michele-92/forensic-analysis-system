/**
 * ============================================================================
 * STATUSMONITOR — Echtzeit Pipeline-Fortschrittsanzeige
 * ============================================================================
 * Zeigt den Analysestatus des aktuell laufenden Jobs als vertikale
 * Stage-Liste mit Fortschrittsbalken. Die Komponente rendert sich
 * selbst aus wenn kein Job aktiv ist (gibt null zurück).
 *
 * Pipeline-Stages und ihre Fortschritts-Bereiche (0–100%):
 *   File Detection (0–8), UAC Processing (8–18), Log Parsing (18–30),
 *   Dissect Parser (30–42), Sleuth Kit (42–54), Normalization (54–66),
 *   Anomaly Detection (66–76), MITRE ATT&CK (76–84),
 *   AI Preprocessing (84–92), Export (92–100)
 *
 * Stage-Zustände:
 *   - pending  → Kreis-Icon, gedimmt (noch nicht erreicht)
 *   - active   → rotierendes Loader-Icon, blau (aktuell in Bearbeitung)
 *   - done     → Check-Icon, grün (abgeschlossen)
 *
 * Props: keine (liest activeJob aus useApp Context)
 *
 * Abhängigkeiten:
 *   - AppContext (useApp): activeJob (enthält status und progress 0–100)
 *
 * @component
 */

import React from 'react'
import { useApp } from '../context/AppContext'
import { Check, Loader2, Circle } from 'lucide-react'

// ── Konstanten ─────────────────────────────────────────────────────────────

/**
 * Definition aller 10 Pipeline-Stages mit ihren Fortschritts-Bereichen.
 * `range` gibt den [Start, Ende]-Prozentbereich an, in dem die Stage aktiv ist.
 * Die Bereiche korrespondieren mit den Backend-Fortschrittsmeldungen in pipeline.py.
 *
 * @type {Array<{id: string, label: string, range: [number, number]}>}
 */
const PIPELINE_STAGES = [
  { id: 'detect',     label: 'File Detection',    range: [0, 8] },
  { id: 'uac',        label: 'UAC Processing',    range: [8, 18] },
  { id: 'logparse',   label: 'Log Parsing',       range: [18, 30] },
  { id: 'dissect',    label: 'Dissect Parser',    range: [30, 42] },
  { id: 'sleuthkit',  label: 'Sleuth Kit',        range: [42, 54] },
  { id: 'normalize',  label: 'Normalization',     range: [54, 66] },
  { id: 'anomaly',    label: 'Anomaly Detection', range: [66, 76] },
  { id: 'mitre',      label: 'MITRE ATT&CK',     range: [76, 84] },
  { id: 'preprocess', label: 'AI Preprocessing',  range: [84, 92] },
  { id: 'export',     label: 'Export',            range: [92, 100] },
]

// ── Hilfsfunktionen ────────────────────────────────────────────────────────

/**
 * Bestimmt den Zustand einer Stage basierend auf dem aktuellen Fortschritt.
 *
 * @param {{ range: [number, number] }} stage    - Stage-Definition mit Prozentbereich
 * @param {number}                      progress - Aktueller Fortschritt (0–100)
 * @returns {'done'|'active'|'pending'}
 */
function getStageStatus(stage, progress) {
  if (progress >= stage.range[1]) return 'done'
  if (progress >= stage.range[0]) return 'active'
  return 'pending'
}

// ── Hauptkomponente ────────────────────────────────────────────────────────

export default function StatusMonitor() {
  const { activeJob } = useApp()

  // Nur rendern wenn ein Job aktiv verarbeitet wird
  if (!activeJob || activeJob.status !== 'processing') return null

  const progress = activeJob.progress || 0

  return (
    <div className="glass p-4 mx-3 mb-3">

      {/* ── Header: Label und numerischer Prozentwert ────────────────── */}
      <div className="flex items-center justify-between mb-3">
        <span className="text-xs font-medium text-white/60">Pipeline</span>
        <span className="text-xs font-mono text-accent-blue">{progress}%</span>
      </div>

      {/* ── Gesamtfortschrittsbalken ──────────────────────────────────── */}
      {/* Farbverlauf von Blau zu Cyan, füllt sich proportional zum Fortschritt */}
      <div className="h-1 bg-white/[0.06] rounded-full mb-3 overflow-hidden">
        <div
          className="h-full bg-gradient-to-r from-accent-blue to-accent-cyan rounded-full transition-all duration-500"
          style={{ width: `${progress}%` }}
        />
      </div>

      {/* ── Stage-Liste ───────────────────────────────────────────────── */}
      {/* Jede Stage zeigt ein kontextabhängiges Icon und farbkodierten Label */}
      <div className="space-y-1.5">
        {PIPELINE_STAGES.map((stage) => {
          const status = getStageStatus(stage, progress)
          return (
            <div key={stage.id} className="flex items-center gap-2">
              {/* Icon wechselt je nach Status: fertig / läuft / ausstehend */}
              {status === 'done' && <Check size={12} className="text-accent-green flex-shrink-0" />}
              {status === 'active' && <Loader2 size={12} className="text-accent-blue animate-spin flex-shrink-0" />}
              {status === 'pending' && <Circle size={12} className="text-white/15 flex-shrink-0" />}
              {/* Label-Farbe: blau (aktiv), gedimmt (fertig), sehr gedimmt (ausstehend) */}
              <span className={`text-[11px] ${
                status === 'active' ? 'text-accent-blue' :
                status === 'done' ? 'text-white/50' : 'text-white/20'
              }`}>
                {stage.label}
              </span>
            </div>
          )
        })}
      </div>
    </div>
  )
}
