import React, { useState } from 'react'
import { verifyEvidence } from '../../api/backend'
import { Shield, ShieldCheck, ShieldX, Copy, Check, Loader2, Clock } from 'lucide-react'

const STATUS = {
  unchecked: { color: 'text-white/30', bg: 'bg-white/[0.06]', icon: Shield, label: 'Nicht geprueft' },
  verified: { color: 'text-accent-green', bg: 'bg-accent-green/10', icon: ShieldCheck, label: 'Verifiziert' },
  tampered: { color: 'text-risk-critical', bg: 'bg-risk-critical/10', icon: ShieldX, label: 'Manipuliert' },
}

const EVENT_LABELS = {
  upload: 'Datei hochgeladen',
  analysis_started: 'Analyse gestartet',
  analysis_completed: 'Analyse abgeschlossen',
  verification: 'Integritaet geprueft',
}

export default function EvidenceIntegrity({ fileHash, jobId }) {
  const [status, setStatus] = useState('unchecked')
  const [loading, setLoading] = useState(false)
  const [auditTrail, setAuditTrail] = useState(null)
  const [copied, setCopied] = useState(false)

  if (!fileHash) return null

  const handleVerify = async () => {
    setLoading(true)
    try {
      const result = await verifyEvidence(jobId)
      setStatus(result.verified ? 'verified' : 'tampered')
      setAuditTrail(result.audit_trail || [])
    } catch (err) {
      console.error('Verification failed:', err)
    } finally {
      setLoading(false)
    }
  }

  const handleCopy = async () => {
    await navigator.clipboard.writeText(fileHash)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const st = STATUS[status]
  const StatusIcon = st.icon

  return (
    <div className="glass-card">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-medium text-white/50 flex items-center gap-2">
          <Shield size={14} className="text-accent-cyan" />
          Evidence Integrity (Chain of Custody)
        </h3>
        <button
          onClick={handleVerify}
          disabled={loading}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-accent-cyan/10 text-accent-cyan hover:bg-accent-cyan/20 transition-all disabled:opacity-50"
        >
          {loading ? (
            <Loader2 size={12} className="animate-spin" />
          ) : (
            <ShieldCheck size={12} />
          )}
          Verifizieren
        </button>
      </div>

      {/* Hash + Status */}
      <div className="flex items-center gap-3 mb-4">
        {/* Status LED */}
        <div className={`w-8 h-8 rounded-lg ${st.bg} flex items-center justify-center flex-shrink-0`}>
          <StatusIcon size={16} className={st.color} />
        </div>

        {/* Hash */}
        <div className="flex-1 min-w-0">
          <span className="text-[10px] text-white/25 uppercase tracking-wider block mb-0.5">SHA256</span>
          <div className="flex items-center gap-2">
            <code className="text-xs font-mono text-white/60 truncate">{fileHash}</code>
            <button
              onClick={handleCopy}
              className="flex-shrink-0 p-1 rounded hover:bg-white/[0.05] transition-colors"
              title="Hash kopieren"
            >
              {copied ? (
                <Check size={12} className="text-accent-green" />
              ) : (
                <Copy size={12} className="text-white/25 hover:text-white/50" />
              )}
            </button>
          </div>
        </div>

        {/* Status Badge */}
        <div className={`px-2.5 py-1 rounded-lg text-[10px] font-medium ${st.bg} ${st.color} flex-shrink-0`}>
          {st.label}
        </div>
      </div>

      {/* Audit Trail */}
      {auditTrail && auditTrail.length > 0 && (
        <div className="border-t border-white/[0.04] pt-3">
          <span className="text-[10px] text-white/25 uppercase tracking-wider block mb-2">Audit Trail</span>
          <div className="relative pl-4">
            {/* Vertical line */}
            <div className="absolute left-[5px] top-1 bottom-1 w-px bg-white/[0.08]" />

            <div className="space-y-2">
              {auditTrail.map((entry, i) => (
                <div key={i} className="relative flex items-start gap-2">
                  {/* Dot */}
                  <div className="absolute left-[-13px] top-1.5 w-2 h-2 rounded-full bg-accent-cyan/40 border border-accent-cyan/60" />

                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-white/60">
                        {EVENT_LABELS[entry.event] || entry.event}
                      </span>
                      {entry.details?.verified !== undefined && (
                        <span className={`text-[10px] px-1.5 py-0.5 rounded-full ${
                          entry.details.verified
                            ? 'bg-accent-green/10 text-accent-green'
                            : 'bg-risk-critical/10 text-risk-critical'
                        }`}>
                          {entry.details.verified ? 'OK' : 'FAIL'}
                        </span>
                      )}
                    </div>
                    <span className="text-[10px] text-white/20 font-mono flex items-center gap-1">
                      <Clock size={8} />
                      {new Date(entry.timestamp).toLocaleString('de-DE')}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
