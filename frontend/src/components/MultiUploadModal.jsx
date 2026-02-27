import React, { useState, useEffect } from 'react'
import { X, Upload, FolderPlus, FileText, HardDrive, MemoryStick } from 'lucide-react'

const FILE_ICONS = {
  '.log': FileText, '.txt': FileText, '.syslog': FileText, '.evtx': FileText,
  '.dd': HardDrive, '.raw': HardDrive, '.img': HardDrive, '.e01': HardDrive,
  '.ewf': HardDrive, '.vdi': HardDrive, '.vmdk': HardDrive,
  '.mem': MemoryStick, '.dmp': MemoryStick, '.dump': MemoryStick,
}

function getFileIcon(filename) {
  const ext = '.' + filename.split('.').pop().toLowerCase()
  return FILE_ICONS[ext] || FileText
}

function formatSize(bytes) {
  if (bytes < 1024) return bytes + ' B'
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB'
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB'
}

export default function MultiUploadModal({ files, onUpload, onClose }) {
  const [mode, setMode] = useState('case') // 'single' | 'case'
  const [caseName, setCaseName] = useState('')
  const [caseNumber, setCaseNumber] = useState('')
  const [uploading, setUploading] = useState(false)

  useEffect(() => {
    const handler = (e) => { if (e.key === 'Escape' && !uploading) onClose() }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [onClose, uploading])

  const handleSubmit = async () => {
    setUploading(true)
    const caseInfo = mode === 'case' && caseName.trim()
      ? { case_name: caseName.trim(), case_number: caseNumber.trim() }
      : null
    await onUpload(files, caseInfo)
    onClose()
  }

  const inputClass = 'w-full bg-white/[0.04] border border-white/[0.08] rounded-xl px-3 py-2 text-sm text-white/80 placeholder-white/20 focus:outline-none focus:border-accent-blue/40 transition-colors'

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/80 backdrop-blur-[80px]" onClick={() => !uploading && onClose()} />

      <div className="relative w-full max-w-md glass-strong m-6">
        {/* Header */}
        <div className="flex items-center justify-between p-5 border-b border-white/[0.06]">
          <div className="flex items-center gap-2">
            <Upload size={18} className="text-accent-blue" />
            <h2 className="text-base font-semibold">{files.length} Dateien hochladen</h2>
          </div>
          <button onClick={() => !uploading && onClose()} className="p-1.5 rounded-lg hover:bg-white/10 transition-all">
            <X size={18} className="text-white/40" />
          </button>
        </div>

        <div className="p-5 space-y-4">
          {/* File List */}
          <div className="space-y-1.5 max-h-[160px] overflow-y-auto">
            {files.map((file, i) => {
              const Icon = getFileIcon(file.name)
              return (
                <div key={i} className="flex items-center gap-2.5 px-3 py-2 rounded-lg bg-white/[0.03]">
                  <Icon size={14} className="text-white/30 flex-shrink-0" />
                  <span className="text-xs text-white/70 truncate flex-1">{file.name}</span>
                  <span className="text-[10px] text-white/25 font-mono flex-shrink-0">{formatSize(file.size)}</span>
                </div>
              )
            })}
          </div>

          {/* Mode Selection */}
          <div className="space-y-2">
            <label className="text-[10px] text-white/30 uppercase tracking-wider block">Upload-Modus</label>

            <div
              onClick={() => setMode('single')}
              className={`flex items-center gap-3 px-4 py-3 rounded-xl cursor-pointer transition-all border ${
                mode === 'single'
                  ? 'border-accent-blue/40 bg-accent-blue/5'
                  : 'border-white/[0.06] hover:border-white/[0.12]'
              }`}
            >
              <div className={`w-4 h-4 rounded-full border-2 flex items-center justify-center ${
                mode === 'single' ? 'border-accent-blue' : 'border-white/20'
              }`}>
                {mode === 'single' && <div className="w-2 h-2 rounded-full bg-accent-blue" />}
              </div>
              <div>
                <span className="text-sm text-white/80">Einzeln hochladen</span>
                <p className="text-[10px] text-white/30">Jede Datei wird als eigene Analyse gestartet</p>
              </div>
            </div>

            <div
              onClick={() => setMode('case')}
              className={`flex items-center gap-3 px-4 py-3 rounded-xl cursor-pointer transition-all border ${
                mode === 'case'
                  ? 'border-accent-blue/40 bg-accent-blue/5'
                  : 'border-white/[0.06] hover:border-white/[0.12]'
              }`}
            >
              <div className={`w-4 h-4 rounded-full border-2 flex items-center justify-center ${
                mode === 'case' ? 'border-accent-blue' : 'border-white/20'
              }`}>
                {mode === 'case' && <div className="w-2 h-2 rounded-full bg-accent-blue" />}
              </div>
              <div>
                <span className="text-sm text-white/80 flex items-center gap-1.5">
                  <FolderPlus size={12} className="text-accent-blue" />
                  Als Fall gruppieren
                </span>
                <p className="text-[10px] text-white/30">Erstellt einen Fall und ordnet alle Dateien zu</p>
              </div>
            </div>
          </div>

          {/* Case Fields (only when mode === 'case') */}
          {mode === 'case' && (
            <div className="space-y-3 pt-1">
              <div>
                <label className="text-[10px] text-white/30 uppercase tracking-wider block mb-1.5">Fallname *</label>
                <input
                  type="text"
                  value={caseName}
                  onChange={e => setCaseName(e.target.value)}
                  placeholder="z.B. Incident Webserver 2026-02"
                  className={inputClass}
                  autoFocus
                />
              </div>
              <div>
                <label className="text-[10px] text-white/30 uppercase tracking-wider block mb-1.5">Aktenzeichen</label>
                <input
                  type="text"
                  value={caseNumber}
                  onChange={e => setCaseNumber(e.target.value)}
                  placeholder="FOR-2026-001 (optional)"
                  className={inputClass}
                />
              </div>
            </div>
          )}

          {/* Actions */}
          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={() => !uploading && onClose()}
              disabled={uploading}
              className="px-4 py-2 rounded-xl text-sm text-white/40 hover:text-white/60 transition-colors disabled:opacity-30"
            >
              Abbrechen
            </button>
            <button
              onClick={handleSubmit}
              disabled={uploading || (mode === 'case' && !caseName.trim())}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-accent-blue/20 text-accent-blue text-sm font-medium hover:bg-accent-blue/30 transition-all disabled:opacity-30"
            >
              {uploading ? (
                <div className="w-4 h-4 border-2 border-accent-blue border-t-transparent rounded-full animate-spin" />
              ) : (
                <Upload size={14} />
              )}
              {uploading ? 'Wird hochgeladen...' : `${files.length} Dateien hochladen`}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
