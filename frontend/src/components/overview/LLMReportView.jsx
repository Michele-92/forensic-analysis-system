import React, { useState, useEffect, useMemo } from 'react'
import { marked } from 'marked'
import DOMPurify from 'dompurify'
import { generateLocalReport } from '../../api/llm'
import { useApp } from '../../context/AppContext'
import { X, FileText, Loader2, Cpu, Check } from 'lucide-react'

export default function LLMReportView({ report, anomalies, indicators, summary, onClose }) {
  const { activeJob, updateJobData } = useApp()

  // Gespeicherten Full-Report aus Job-Daten laden
  const savedLlmReport = activeJob?.data?.llmFullReport || null

  const [activeTab, setActiveTab] = useState(savedLlmReport ? 'llm' : 'backend')
  const [llmReport, setLlmReport] = useState(savedLlmReport)
  const [llmLoading, setLlmLoading] = useState(false)
  const [llmError, setLlmError] = useState(null)

  const generateLLMReport = async () => {
    setLlmLoading(true)
    setLlmError(null)
    try {
      const result = await generateLocalReport({ anomalies, indicators, summary })
      setLlmReport(result)
      setActiveTab('llm')
      // Ergebnis persistent in Job-Daten speichern (localStorage)
      if (activeJob) {
        updateJobData(activeJob.job_id, { llmFullReport: result })
      }
    } catch (err) {
      setLlmError(err.message)
    } finally {
      setLlmLoading(false)
    }
  }

  const renderedReport = useMemo(() => {
    const source = activeTab === 'llm' && llmReport ? llmReport : report
    if (!source) return '<p class="text-white/30">Kein Report verfügbar.</p>'
    return DOMPurify.sanitize(marked.parse(source))
  }, [activeTab, llmReport, report])

  // Close on Escape
  useEffect(() => {
    const handler = (e) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [onClose])

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/80 backdrop-blur-[80px]"
        onClick={onClose}
      />

      {/* Modal */}
      <div className="relative w-full max-w-4xl max-h-[85vh] glass-strong flex flex-col m-6">
        {/* Header */}
        <div className="flex items-center justify-between p-5 border-b border-white/[0.06]">
          <div className="flex items-center gap-3">
            <FileText size={18} className="text-accent-blue" />
            <h2 className="text-lg font-semibold">Forensic Report</h2>
          </div>

          <div className="flex items-center gap-2">
            {/* Tab: Backend Report */}
            <button
              onClick={() => setActiveTab('backend')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                activeTab === 'backend'
                  ? 'bg-white/10 text-white'
                  : 'text-white/40 hover:text-white/60'
              }`}
            >
              Backend Report
            </button>

            {/* Tab: Local LLM */}
            <button
              onClick={() => llmReport ? setActiveTab('llm') : generateLLMReport()}
              disabled={llmLoading}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                activeTab === 'llm'
                  ? 'bg-accent-purple/20 text-accent-purple'
                  : 'text-white/40 hover:text-accent-purple'
              }`}
            >
              {llmLoading ? (
                <Loader2 size={12} className="animate-spin" />
              ) : llmReport ? (
                <Check size={12} />
              ) : (
                <Cpu size={12} />
              )}
              Ollama Analysis
            </button>

            {/* Regenerate button when viewing saved LLM report */}
            {llmReport && activeTab === 'llm' && !llmLoading && (
              <button
                onClick={generateLLMReport}
                className="px-2 py-1.5 rounded-lg text-[10px] text-white/30 hover:text-accent-purple hover:bg-white/5 transition-all"
                title="Report neu generieren"
              >
                Neu generieren
              </button>
            )}

            <div className="w-px h-6 bg-white/[0.06] mx-1" />

            <button
              onClick={onClose}
              className="p-1.5 rounded-lg hover:bg-white/10 transition-all"
            >
              <X size={18} className="text-white/40" />
            </button>
          </div>
        </div>

        {/* Error */}
        {llmError && (
          <div className="mx-5 mt-4 p-3 rounded-lg bg-risk-critical/10 text-risk-critical text-xs">
            LLM-Fehler: {llmError}
          </div>
        )}

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6">
          {llmLoading && activeTab === 'llm' ? (
            <div className="flex flex-col items-center justify-center py-20 gap-4">
              <div className="w-10 h-10 border-2 border-accent-purple border-t-transparent rounded-full animate-spin" />
              <p className="text-sm text-white/40">Ollama generiert Report...</p>
              <p className="text-xs text-white/20">Kann bis zu 5 Minuten dauern</p>
            </div>
          ) : (
            <div
              className="report-content"
              dangerouslySetInnerHTML={{ __html: renderedReport }}
            />
          )}
        </div>
      </div>
    </div>
  )
}
