/**
 * ============================================================================
 * PDF EXPORT MODAL — Standard PDF-Report Export für einen einzelnen Job
 * ============================================================================
 * Modales Formular zum Generieren des Standard-Forensikberichts als PDF.
 * Enthält alle Kernbefunde der Pipeline (Anomalien, IOCs, MITRE ATT&CK,
 * Timeline), aber ohne die erweiterte Multi-Agent-KI-Analyse.
 * Für den vollständigen Report mit KI-Analyse: FullReportModal verwenden.
 *
 * Formularfelder (Berichtskopf):
 *   - Analyst (Name des Erstellers)
 *   - Qualifikation (z.B. "Certified DFIR Analyst")
 *   - Auftraggeber (Behörde oder Mandant)
 *   - Fallbezeichnung
 *   - Aktenzeichen
 *   - Ort & Datum (vorausgefüllt mit aktuellem Datum)
 *   - Unterschrift (vorausgefüllt mit Analystennamen)
 *
 * Verhalten:
 *   - Formulardaten werden aus jobCase (Fall-Metadaten) vorausgefüllt
 *   - Export-Button sendet Formulardaten an /export-pdf/{job_id}
 *   - Das Backend gibt die PDF-Datei als Binär-Response zurück,
 *     der Browser löst automatisch den Download aus (Blob-URL-Trick)
 *   - Ladeanimation während Export, Erfolgs-/Fehler-Feedback danach
 *
 * Props:
 * @param {Object|null} jobCase - Fall-Metadaten zum Vorausfüllen (kann null sein)
 * @param {string}      jobId   - Job-ID für den Backend-Export-Endpunkt
 * @param {Function}    onClose - Callback zum Schließen des Modals
 *
 * Abhängigkeiten:
 *   - api/backend.js  (exportPdf)
 *
 * @module components/PdfExportModal
 */
import React, { useState } from 'react'
import { X, FileDown, Loader2 } from 'lucide-react'
import { exportPdf } from '../api/backend'

export default function PdfExportModal({ jobCase, jobId, onClose }) {
  const today = new Date().toLocaleDateString('de-DE')

  const [form, setForm] = useState({
    analyst:       jobCase?.analyst       || '',
    qualifikation: jobCase?.qualifikation || '',
    auftraggeber:  jobCase?.auftraggeber  || '',
    case_name:     jobCase?.case_name     || '',
    case_number:   jobCase?.case_number   || '',
    ort_datum:     `___, ${today}`,
    unterschrift:  jobCase?.analyst       || '',
  })
  const [loading, setLoading]   = useState(false)
  const [error,   setError]     = useState(null)

  const handleExport = async () => {
    setLoading(true)
    setError(null)
    try {
      await exportPdf(jobId, form)
      onClose()
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const inputClass =
    'w-full bg-white/[0.04] border border-white/[0.08] rounded-xl px-3 py-2 text-sm ' +
    'text-white/80 placeholder-white/20 focus:outline-none focus:border-accent-purple/40 transition-colors'

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/80 backdrop-blur-[80px]" onClick={onClose} />

      <div className="relative w-full max-w-lg glass-strong m-6 overflow-y-auto max-h-[90vh]">
        {/* Header */}
        <div className="flex items-center justify-between p-5 border-b border-white/[0.06]">
          <div className="flex items-center gap-2">
            <FileDown size={18} className="text-accent-purple" />
            <h2 className="text-base font-semibold">PDF Export — Gutachter-Angaben</h2>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-white/10 transition-all">
            <X size={18} className="text-white/40" />
          </button>
        </div>

        {/* Hinweis */}
        <div className="px-5 pt-4">
          <p className="text-[11px] text-white/30 leading-relaxed">
            Diese Angaben erscheinen auf dem Deckblatt und in der Sachverständigen-Erklärung (§ 79 StPO).
            Vorausgefüllt aus den Fall-Daten — bitte vor dem Export prüfen und ggf. anpassen.
          </p>
        </div>

        {/* Formular */}
        <div className="p-5 space-y-4">

          {/* Name + Qualifikation */}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-[10px] text-white/30 uppercase tracking-wider block mb-1.5">
                Name / Gutachter
              </label>
              <input
                type="text"
                value={form.analyst}
                onChange={e => setForm(f => ({ ...f, analyst: e.target.value }))}
                placeholder="Max Mustermann"
                className={inputClass}
              />
            </div>
            <div>
              <label className="text-[10px] text-white/30 uppercase tracking-wider block mb-1.5">
                Qualifikation
              </label>
              <input
                type="text"
                value={form.qualifikation}
                onChange={e => setForm(f => ({ ...f, qualifikation: e.target.value }))}
                placeholder="BSc Informatik, Forensik-Analyst"
                className={inputClass}
              />
            </div>
          </div>

          {/* Auftraggeber */}
          <div>
            <label className="text-[10px] text-white/30 uppercase tracking-wider block mb-1.5">
              Auftraggeber
            </label>
            <input
              type="text"
              value={form.auftraggeber}
              onChange={e => setForm(f => ({ ...f, auftraggeber: e.target.value }))}
              placeholder="z. B. Staatsanwaltschaft München I"
              className={inputClass}
            />
          </div>

          {/* Ort, Datum */}
          <div>
            <label className="text-[10px] text-white/30 uppercase tracking-wider block mb-1.5">
              Ort, Datum
            </label>
            <input
              type="text"
              value={form.ort_datum}
              onChange={e => setForm(f => ({ ...f, ort_datum: e.target.value }))}
              placeholder={`München, ${today}`}
              className={inputClass}
            />
            <p className="text-[10px] text-white/20 mt-1">
              Format: Stadt, TT.MM.JJJJ — erscheint in der Sachverständigen-Erklärung
            </p>
          </div>

          {/* Unterschrift */}
          <div>
            <label className="text-[10px] text-white/30 uppercase tracking-wider block mb-1.5">
              Unterschrift (getippt)
            </label>
            <input
              type="text"
              value={form.unterschrift}
              onChange={e => setForm(f => ({ ...f, unterschrift: e.target.value }))}
              placeholder="Vorname Nachname"
              className={inputClass}
            />
            <p className="text-[10px] text-white/20 mt-1">
              In Produktivumgebung: qualifizierte elektronische Signatur nach eIDAS erforderlich
            </p>
          </div>

          {error && (
            <div className="text-xs text-risk-critical bg-risk-critical/10 border border-risk-critical/20 rounded-xl px-3 py-2">
              Fehler: {error}
            </div>
          )}

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
              onClick={handleExport}
              disabled={loading}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-accent-purple/20 text-accent-purple text-sm font-medium hover:bg-accent-purple/30 transition-all disabled:opacity-50"
            >
              {loading
                ? <Loader2 size={14} className="animate-spin" />
                : <FileDown size={14} />
              }
              {loading ? 'Wird erstellt…' : 'PDF erstellen'}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
