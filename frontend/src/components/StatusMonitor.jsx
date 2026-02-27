import React from 'react'
import { useApp } from '../context/AppContext'
import { Check, Loader2, Circle } from 'lucide-react'

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

function getStageStatus(stage, progress) {
  if (progress >= stage.range[1]) return 'done'
  if (progress >= stage.range[0]) return 'active'
  return 'pending'
}

export default function StatusMonitor() {
  const { activeJob } = useApp()

  if (!activeJob || activeJob.status !== 'processing') return null

  const progress = activeJob.progress || 0

  return (
    <div className="glass p-4 mx-3 mb-3">
      <div className="flex items-center justify-between mb-3">
        <span className="text-xs font-medium text-white/60">Pipeline</span>
        <span className="text-xs font-mono text-accent-blue">{progress}%</span>
      </div>

      {/* Progress bar */}
      <div className="h-1 bg-white/[0.06] rounded-full mb-3 overflow-hidden">
        <div
          className="h-full bg-gradient-to-r from-accent-blue to-accent-cyan rounded-full transition-all duration-500"
          style={{ width: `${progress}%` }}
        />
      </div>

      {/* Stages */}
      <div className="space-y-1.5">
        {PIPELINE_STAGES.map((stage) => {
          const status = getStageStatus(stage, progress)
          return (
            <div key={stage.id} className="flex items-center gap-2">
              {status === 'done' && <Check size={12} className="text-accent-green flex-shrink-0" />}
              {status === 'active' && <Loader2 size={12} className="text-accent-blue animate-spin flex-shrink-0" />}
              {status === 'pending' && <Circle size={12} className="text-white/15 flex-shrink-0" />}
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
