/**
 * ============================================================================
 * FULL REPORT MODAL — Vollständiger PDF-Export mit Multi-Agent-KI-Analyse
 * ============================================================================
 * Modales Formular zum Generieren des erweiterten Forensik-Reports (PDF).
 * Im Gegensatz zum Standard-PDF-Export (PdfExportModal) enthält dieser
 * Report zusätzlich die vollständigen Ergebnisse der Multi-Agenten-Analyse
 * (Triage, DFIR-Analyst und Reporter) falls diese bereits durchgeführt wurde.
 *
 * Formularfelder (Berichtskopf):
 *   - Analyst (Name des Erstellers)
 *   - Qualifikation (z.B. "Certified DFIR Analyst")
 *   - Auftraggeber (Behörde oder Mandant)
 *   - Fallbezeichnung
 *   - Aktenzeichen
 *   - Ort & Datum
 *   - Unterschrift
 *
 * Verhalten:
 *   - Zeigt Hinweis wenn noch keine Multi-Agent-Analyse durchgeführt wurde
 *     (hasAgentAnalysis=false) — Export trotzdem möglich, aber ohne KI-Teil
 *   - Klick auf "Intelligence-Analyse starten" → wechselt zur Intelligence-Ansicht
 *   - Export-Button sendet Formulardaten + Job-ID an /export-full-pdf/{job_id}
 *   - Zeigt Ladeanimation während Export, Erfolgs-/Fehler-Feedback danach
 *
 * Props:
 * @param {Object|null} jobCase       - Fall-Metadaten zum Vorausfüllen des Formulars
 * @param {string}      jobId         - Job-ID für den Backend-Export-Endpunkt
 * @param {Object|null} agentAnalysis - Ergebnis der Multi-Agenten-Analyse (kann null sein)
 * @param {Function}    onClose       - Callback zum Schließen des Modals
 *
 * Abhängigkeiten:
 *   - api/backend.js  (exportFullPdf)
 *   - AppContext       (setActiveView — für Navigation zur Intelligence-Ansicht)
 *
 * @module components/FullReportModal
 */
import React, { useState } from 'react'
import { X, FileDown, Loader2, AlertTriangle, CheckCircle, ArrowRight } from 'lucide-react'
import { exportFullPdf } from '../api/backend'
import { useApp } from '../context/AppContext'

export default function FullReportModal({ jobCase, jobId, agentAnalysis, onClose }) {
  const { setActiveView } = useApp()
  const today = new Date().toLocaleDateString('de-DE')
  const hasAgentAnalysis = !!(agentAnalysis?.reporter || agentAnalysis?.triage)

  const [form, setForm] = useState({
    analyst:       jobCase?.analyst       || '',
    qualifikation: jobCase?.qualifikation || '',
    auftraggeber:  jobCase?.auftraggeber  || '',
    case_name:     jobCase?.case_name     || '',
    case_number:   jobCase?.case_number   || '',
    ort_datum:     `___, ${today}`,
    unterschrift:  jobCase?.analyst       || '',
  })
  const [loading, setLoading] = useState(false)
  const [error,   setError]   = useState(null)

  const handleExport = async () => {
    setLoading(true)
    setError(null)
    try {
      await exportFullPdf(jobId, { ...form, agent_analysis: agentAnalysis || null })
      onClose()
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const handleGoToIntelligence = () => {
    onClose()
    setActiveView('intelligence')
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
            <FileDown size={18} className="text-accent-cyan" />
            <h2 className="text-base font-semibold">Vollständiger Report</h2>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-white/10 transition-all">
            <X size={18} className="text-white/40" />
          </button>
        </div>

        {/* Multi-Agent Status */}
        <div className="px-5 pt-4">
          {hasAgentAnalysis ? (
            <div className="flex items-start gap-2 px-3 py-2.5 rounded-xl text-[11px]
              bg-accent-green/10 text-accent-green border border-accent-green/20 leading-relaxed">
              <CheckCircle size={13} className="mt-0.5 flex-shrink-0" />
              <span>
                Multi-Agent KI-Analyse wird eingeschlossen —
                Sektion 9: Forensischer Bericht (Reporter) +
                Anhang A: Triage + Anhang B: DFIR-Tiefenanalyse
              </span>
            </div>
          ) : (
            <div className="flex items-start gap-2 px-3 py-2.5 rounded-xl text-[11px]
              bg-risk-high/10 text-risk-high border border-risk-high/20 leading-relaxed">
              <AlertTriangle size={13} className="mt-0.5 flex-shrink-0" />
              <div className="flex-1">
                <span className="font-medium block mb-1">
                  Multi-Agent Analyse noch nicht durchgeführt
                </span>
                <span className="text-white/40">
                  Für den vollständigen Report wird die Multi-Agent Analyse benötigt
                  (ca. 5–15 Min). Starte sie im Intelligence Tab.
                </span>
                <button
                  onClick={handleGoToIntelligence}
                  className="flex items-center gap-1 mt-2 text-accent-cyan hover:text-accent-cyan/80 transition-colors font-medium"
                >
                  <ArrowRight size={11} />
                  Zum Intelligence Tab
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Hinweis */}
        <div className="px-5 pt-3">
          <p className="text-[11px] text-white/30 leading-relaxed">
            Gutachter-Angaben erscheinen auf dem Deckblatt und in der Sachverständigen-Erklärung (§ 79 StPO).
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
              disabled={loading || !hasAgentAnalysis}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-accent-cyan/20 text-accent-cyan text-sm font-medium hover:bg-accent-cyan/30 transition-all disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {loading
                ? <Loader2 size={14} className="animate-spin" />
                : <FileDown size={14} />
              }
              {loading ? 'Wird erstellt…' : 'Vollständigen Report erstellen'}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
