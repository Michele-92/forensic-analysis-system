import React, { useState, useEffect } from 'react'
import { X, FolderPlus, Save } from 'lucide-react'

const STATUS_OPTIONS = [
  { value: 'offen', label: 'Offen' },
  { value: 'in_bearbeitung', label: 'In Bearbeitung' },
  { value: 'abgeschlossen', label: 'Abgeschlossen' },
  { value: 'archiviert', label: 'Archiviert' },
]

export default function CaseModal({ caseData, onSave, onClose }) {
  const isEdit = !!caseData

  const [form, setForm] = useState({
    case_name: caseData?.case_name || '',
    case_number: caseData?.case_number || '',
    description: caseData?.description || '',
    analyst: caseData?.analyst || '',
    tags: caseData?.tags?.join(', ') || '',
    status: caseData?.status || 'offen',
  })

  useEffect(() => {
    const handler = (e) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [onClose])

  const handleSubmit = (e) => {
    e.preventDefault()
    if (!form.case_name.trim()) return
    onSave({
      ...form,
      tags: form.tags.split(',').map(t => t.trim()).filter(Boolean),
    })
    onClose()
  }

  const inputClass = 'w-full bg-white/[0.04] border border-white/[0.08] rounded-xl px-3 py-2 text-sm text-white/80 placeholder-white/20 focus:outline-none focus:border-accent-blue/40 transition-colors'

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/80 backdrop-blur-[80px]" onClick={onClose} />

      <div className="relative w-full max-w-md glass-strong m-6">
        {/* Header */}
        <div className="flex items-center justify-between p-5 border-b border-white/[0.06]">
          <div className="flex items-center gap-2">
            <FolderPlus size={18} className="text-accent-blue" />
            <h2 className="text-base font-semibold">{isEdit ? 'Fall bearbeiten' : 'Neuer Fall'}</h2>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-white/10 transition-all">
            <X size={18} className="text-white/40" />
          </button>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="p-5 space-y-4">
          <div>
            <label className="text-[10px] text-white/30 uppercase tracking-wider block mb-1.5">Fallname *</label>
            <input
              type="text"
              value={form.case_name}
              onChange={e => setForm(f => ({ ...f, case_name: e.target.value }))}
              placeholder="z.B. Incident Webserver 2026-02"
              className={inputClass}
              autoFocus
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-[10px] text-white/30 uppercase tracking-wider block mb-1.5">Aktenzeichen</label>
              <input
                type="text"
                value={form.case_number}
                onChange={e => setForm(f => ({ ...f, case_number: e.target.value }))}
                placeholder="FOR-2026-001"
                className={inputClass}
              />
            </div>
            <div>
              <label className="text-[10px] text-white/30 uppercase tracking-wider block mb-1.5">Analyst</label>
              <input
                type="text"
                value={form.analyst}
                onChange={e => setForm(f => ({ ...f, analyst: e.target.value }))}
                placeholder="Name"
                className={inputClass}
              />
            </div>
          </div>

          <div>
            <label className="text-[10px] text-white/30 uppercase tracking-wider block mb-1.5">Beschreibung</label>
            <textarea
              value={form.description}
              onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
              placeholder="Optionale Notizen zum Fall..."
              className={inputClass + ' h-20 resize-none'}
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-[10px] text-white/30 uppercase tracking-wider block mb-1.5">Tags</label>
              <input
                type="text"
                value={form.tags}
                onChange={e => setForm(f => ({ ...f, tags: e.target.value }))}
                placeholder="Ransomware, Dringend"
                className={inputClass}
              />
            </div>
            <div>
              <label className="text-[10px] text-white/30 uppercase tracking-wider block mb-1.5">Status</label>
              <select
                value={form.status}
                onChange={e => setForm(f => ({ ...f, status: e.target.value }))}
                className={inputClass + ' appearance-none'}
              >
                {STATUS_OPTIONS.map(opt => (
                  <option key={opt.value} value={opt.value} className="bg-[#0a0a0a]">{opt.label}</option>
                ))}
              </select>
            </div>
          </div>

          {/* Actions */}
          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded-xl text-sm text-white/40 hover:text-white/60 transition-colors"
            >
              Abbrechen
            </button>
            <button
              type="submit"
              disabled={!form.case_name.trim()}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-accent-blue/20 text-accent-blue text-sm font-medium hover:bg-accent-blue/30 transition-all disabled:opacity-30"
            >
              <Save size={14} />
              {isEdit ? 'Speichern' : 'Erstellen'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
