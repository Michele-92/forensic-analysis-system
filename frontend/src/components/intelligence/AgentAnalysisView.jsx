import React, { useState } from 'react'
import { useApp } from '../../context/AppContext'
import { runAgentAnalysis } from '../../api/llm'
import { marked } from 'marked'
import DOMPurify from 'dompurify'
import {
  Users, Shield, Search, FileText,
  Loader2, CheckCircle, XCircle, Play, ChevronDown, ChevronRight,
} from 'lucide-react'

const AGENTS = [
  {
    id: 'triage',
    name: 'Triage Agent',
    role: 'SOC Level 1',
    description: 'Klassifiziert Anomalien als Kritisch, Verdaechtig oder False Positive',
    icon: Shield,
    colorHex: '#3b82f6',
  },
  {
    id: 'analyst',
    name: 'Analyst Agent',
    role: 'Senior DFIR',
    description: 'Korrelation, Angriffsketten, MITRE ATT&CK Mapping',
    icon: Search,
    colorHex: '#a855f7',
  },
  {
    id: 'reporter',
    name: 'Reporter Agent',
    role: 'Forensic Writer',
    description: 'Erstellt gerichtsverwertbaren forensischen Bericht',
    icon: FileText,
    colorHex: '#06b6d4',
  },
]

const INITIAL_STATES = {
  triage: { status: 'pending', result: null },
  analyst: { status: 'pending', result: null },
  reporter: { status: 'pending', result: null },
}

export default function AgentAnalysisView() {
  const { activeJob, updateJobData } = useApp()

  const savedResults = activeJob?.data?.agentAnalysis || null

  const [agentStates, setAgentStates] = useState(
    savedResults
      ? {
          triage: { status: 'done', result: savedResults.triage },
          analyst: { status: 'done', result: savedResults.analyst },
          reporter: { status: 'done', result: savedResults.reporter },
        }
      : { ...INITIAL_STATES }
  )
  const [isRunning, setIsRunning] = useState(false)
  const [error, setError] = useState(null)
  const [expandedAgent, setExpandedAgent] = useState(savedResults ? 'reporter' : null)

  const handleStart = async () => {
    setIsRunning(true)
    setError(null)
    setAgentStates({ ...INITIAL_STATES })
    setExpandedAgent(null)

    try {
      const results = {}

      await runAgentAnalysis(activeJob.job_id, (event) => {
        if (event.agent && event.status) {
          setAgentStates((prev) => ({
            ...prev,
            [event.agent]: {
              status: event.status === 'done' ? 'done' : event.status === 'error' ? 'error' : 'running',
              result: event.result || event.error || null,
            },
          }))

          if (event.status === 'done') {
            results[event.agent] = event.result
            setExpandedAgent(event.agent)
          }

          if (event.status === 'error') {
            setError(`Agent "${event.agent}" fehlgeschlagen: ${event.error}`)
          }
        }

        if (event.status === 'complete') {
          updateJobData(activeJob.job_id, {
            agentAnalysis: {
              triage: results.triage || null,
              analyst: results.analyst || null,
              reporter: results.reporter || null,
              final_report: event.final_report,
              timestamp: new Date().toISOString(),
            },
          })
        }
      })
    } catch (err) {
      setError(err.message)
    } finally {
      setIsRunning(false)
    }
  }

  return (
    <div className="glass-card">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-medium text-white/50 flex items-center gap-2">
          <Users size={14} className="text-accent-cyan" />
          Multi-Agent Analyse
        </h3>
        <button
          onClick={handleStart}
          disabled={isRunning}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-accent-cyan/10 text-accent-cyan hover:bg-accent-cyan/20 transition-all disabled:opacity-50"
        >
          {isRunning ? (
            <Loader2 size={12} className="animate-spin" />
          ) : savedResults ? (
            <CheckCircle size={12} />
          ) : (
            <Play size={12} />
          )}
          {isRunning ? 'Analyse laeuft...' : savedResults ? 'Neu analysieren' : 'Analyse starten'}
        </button>
      </div>

      {/* Error */}
      {error && (
        <div className="mb-4 p-3 rounded-lg bg-risk-critical/10 text-risk-critical text-xs">
          {error}
        </div>
      )}

      {/* Agent Cards */}
      <div className="space-y-2">
        {AGENTS.map((agent, index) => (
          <AgentCard
            key={agent.id}
            agent={agent}
            state={agentStates[agent.id]}
            index={index}
            expanded={expandedAgent === agent.id}
            onToggle={() => setExpandedAgent(expandedAgent === agent.id ? null : agent.id)}
          />
        ))}
      </div>

      {/* Connection line between cards */}
      {isRunning && (
        <div className="mt-3 flex items-center justify-center gap-2 text-[10px] text-white/20">
          <div className="w-2 h-2 rounded-full bg-accent-cyan animate-pulse" />
          <span>Agenten kommunizieren sequentiell...</span>
        </div>
      )}

      {/* Hint */}
      {!savedResults && !isRunning && (
        <p className="text-xs text-white/25 mt-4">
          3 spezialisierte KI-Agenten: Triage (SOC L1) → Analyst (DFIR) → Reporter.
          Dauer: ca. 5-15 Minuten je nach System.
        </p>
      )}
    </div>
  )
}

function AgentCard({ agent, state, index, expanded, onToggle }) {
  const Icon = agent.icon

  const isRunning = state.status === 'running'
  const isDone = state.status === 'done'
  const isError = state.status === 'error'
  const isPending = state.status === 'pending'

  const borderColor = isRunning ? `${agent.colorHex}4D` : isDone ? 'rgba(255,255,255,0.08)' : 'rgba(255,255,255,0.04)'
  const bgColor = isRunning ? `${agent.colorHex}0D` : isDone ? 'rgba(255,255,255,0.02)' : 'rgba(255,255,255,0.01)'

  return (
    <div
      className="rounded-xl transition-all duration-300 overflow-hidden"
      style={{ border: `1px solid ${borderColor}`, backgroundColor: bgColor }}
    >
      {/* Header Row */}
      <div
        className={`flex items-center gap-3 px-4 py-3 ${state.result ? 'cursor-pointer' : ''}`}
        onClick={() => state.result && onToggle()}
      >
        {/* Step Number */}
        <div
          className="w-7 h-7 rounded-full flex items-center justify-center flex-shrink-0 text-xs font-bold"
          style={{
            backgroundColor: isDone ? `${agent.colorHex}20` : 'rgba(255,255,255,0.03)',
            color: isDone ? agent.colorHex : 'rgba(255,255,255,0.2)',
          }}
        >
          {index + 1}
        </div>

        {/* Agent Info */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <Icon size={12} style={{ color: agent.colorHex }} />
            <span className="text-sm font-medium text-white/80">{agent.name}</span>
            <span className="text-[10px] text-white/30">({agent.role})</span>
          </div>
          <p className="text-[10px] text-white/25 mt-0.5">{agent.description}</p>
        </div>

        {/* Status */}
        <div className="flex items-center gap-1.5 flex-shrink-0">
          {isRunning && (
            <>
              <Loader2 size={12} className="animate-spin" style={{ color: agent.colorHex }} />
              <span className="text-[10px] font-medium" style={{ color: agent.colorHex }}>Analysiert...</span>
            </>
          )}
          {isDone && (
            <>
              <CheckCircle size={12} className="text-accent-green" />
              <span className="text-[10px] font-medium text-accent-green">Abgeschlossen</span>
              {state.result && (
                expanded ? <ChevronDown size={12} className="text-white/30" /> : <ChevronRight size={12} className="text-white/30" />
              )}
            </>
          )}
          {isError && (
            <>
              <XCircle size={12} className="text-risk-critical" />
              <span className="text-[10px] font-medium text-risk-critical">Fehler</span>
            </>
          )}
          {isPending && (
            <span className="text-[10px] text-white/25">Ausstehend</span>
          )}
        </div>
      </div>

      {/* Running Progress Bar */}
      {isRunning && (
        <div className="h-0.5 overflow-hidden">
          <div
            className="h-full animate-pulse"
            style={{ backgroundColor: agent.colorHex, width: '60%' }}
          />
        </div>
      )}

      {/* Expanded Result */}
      {expanded && state.result && (
        <div className="px-4 pb-4 border-t border-white/[0.04]">
          <div
            className="report-content text-sm mt-3 max-h-[400px] overflow-y-auto"
            dangerouslySetInnerHTML={{
              __html: DOMPurify.sanitize(marked.parse(state.result)),
            }}
          />
        </div>
      )}

      {/* Error Detail */}
      {isError && state.result && (
        <div className="px-4 pb-3">
          <p className="text-[10px] text-risk-critical/70">{state.result}</p>
        </div>
      )}
    </div>
  )
}
