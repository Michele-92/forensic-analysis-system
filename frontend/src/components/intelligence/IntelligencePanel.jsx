/**
 * ============================================================================
 * INTELLIGENCE PANEL — Threat Intelligence Hub
 * ============================================================================
 * Hauptcontainer der Intelligence-Ansicht. Bündelt alle bedrohungsbezogenen
 * Analysen in drei Sub-Tabs:
 *
 *   1. "Threat Intelligence" (Standard):
 *      - KI-Bedrohungsanalyse via Ollama (On-Demand)
 *      - Attack Kill Chain (AttackGraph)
 *      - Multi-Agent LLM Analyse (AgentAnalysisView)
 *      - Bewertete Anomalie-Liste (AnomalyList)
 *
 *   2. "Täterinfrastruktur":
 *      - Fokus auf Angreifer-Perspektive: C2, VPN, Tool-Staging, Exfiltration
 *      - MITRE ATT&CK Kill Chain Coverage (aufgeteilt in Täter- vs. Opfer-Taktiken)
 *      - Gefilterte Infrastruktur-Event-Liste (InfraEventRow)
 *
 *   3. "Anti-Forensics":
 *      - Weiterleitung an AntiForensicsPanel mit antiforensics-Report-Daten
 *
 * Props: keine — liest `activeJob` und `updateJobData` aus dem AppContext.
 *
 * Abhängigkeiten:
 *   - AppContext (activeJob, updateJobData)
 *   - AnomalyList, AttackGraph, AgentAnalysisView, AntiForensicsPanel
 *   - api/llm (analyzeAnomaliesLocal)
 *   - marked, DOMPurify (Markdown-Rendering mit XSS-Sanitierung)
 *   - lucide-react (diverse Icons)
 *
 * @component
 */
import React, { useState, useMemo } from 'react'
import { useApp } from '../../context/AppContext'
import AnomalyList from './AnomalyList'
import AttackGraph from './AttackGraph'
import AgentAnalysisView from './AgentAnalysisView'
import AntiForensicsPanel from './AntiForensicsPanel'
import { analyzeAnomaliesLocal } from '../../api/llm'
import { marked } from 'marked'
import DOMPurify from 'dompurify'
import {
  Sparkles, Loader2, Brain, Check,
  Shield, Target, Server, Network, AlertOctagon,
  Package, Key, ArrowRight, ShieldOff,
} from 'lucide-react'

// ── Konstanten auf Modul-Ebene (außerhalb der Komponente) ─────────────────────

/**
 * Event-Typen, die auf Täterinfrastruktur hinweisen.
 * Wird für die Filterung des "Täterinfrastruktur"-Tabs verwendet.
 */
const INFRA_EVENT_TYPES = new Set([
  'c2_beacon', 'c2_tool', 'vpn_connection', 'vpn_disconnect', 'vpn_ip_assigned',
  'dns_query', 'network_connect', 'suspicious_tool_installed', 'package_install',
  'reverse_shell_attempt',
])

/**
 * MITRE ATT&CK Taktiken, die der Angreifer-Infrastruktur zuzuordnen sind.
 * Alle anderen Taktiken werden als "Angriff auf Opfersystem" klassifiziert.
 */
const ATTACKER_INFRA_TACTICS = new Set([
  'Resource Development',
  'Command and Control',
  'Exfiltration',
  'Lateral Movement',
])

/**
 * Mapping von MITRE-Taktik-Namen auf Icon-Komponente und Farbklassen.
 * Wird für die Kill-Chain-Coverage-Darstellung im Täterinfrastruktur-Tab genutzt.
 */
const TACTIC_CONFIG = {
  'Resource Development':   { icon: Package,      color: 'text-accent-purple', bg: 'bg-accent-purple/10' },
  'Command and Control':    { icon: Network,      color: 'text-risk-critical', bg: 'bg-risk-critical/10' },
  'Exfiltration':           { icon: ArrowRight,   color: 'text-risk-high',     bg: 'bg-risk-high/10' },
  'Lateral Movement':       { icon: Server,       color: 'text-accent-blue',   bg: 'bg-accent-blue/10' },
  'Initial Access':         { icon: AlertOctagon, color: 'text-risk-high',     bg: 'bg-risk-high/10' },
  'Credential Access':      { icon: Key,          color: 'text-risk-medium',   bg: 'bg-risk-medium/10' },
  'Privilege Escalation':   { icon: Shield,       color: 'text-accent-orange', bg: 'bg-accent-orange/10' },
  'Defense Evasion':        { icon: Shield,       color: 'text-accent-cyan',   bg: 'bg-accent-cyan/10' },
  'Persistence':            { icon: Target,       color: 'text-accent-green',  bg: 'bg-accent-green/10' },
  'Execution':              { icon: Sparkles,     color: 'text-white/50',      bg: 'bg-white/[0.06]' },
  'Discovery':              { icon: Network,      color: 'text-white/50',      bg: 'bg-white/[0.06]' },
  'Impact':                 { icon: AlertOctagon, color: 'text-risk-critical', bg: 'bg-risk-critical/10' },
  'Reconnaissance':         { icon: Network,      color: 'text-accent-blue',   bg: 'bg-accent-blue/10' },
}

// ── Hauptkomponente ────────────────────────────────────────────────────────────

/**
 * Threat Intelligence Hub mit drei Analyse-Perspektiven.
 * Verwaltet Tab-Zustand und triggert On-Demand Ollama-Analyse.
 */
export default function IntelligencePanel() {
  const { activeJob, updateJobData } = useApp()

  /** Ladeindikator für die Ollama Quick-Analyse */
  const [llmLoading, setLlmLoading]   = useState(false)

  /** Aktiver Tab: 'threat' | 'attacker_infra' | 'antiforensics' */
  const [activeTab, setActiveTab]     = useState('threat')

  const data = activeJob?.data

  // Null-sichere Datenzugriffe — useMemo muss VOR jedem early return stehen (Rules of Hooks)
  const anomalies = data?.anomalies || []

  /**
   * Aggregiert MITRE-Taktiken aus allen Anomalien.
   * Ergebnis: Array von { tactic, count }, absteigend sortiert.
   * Wird im Täterinfrastruktur-Tab für die Kill-Chain-Coverage benötigt.
   */
  const tacticSummary = useMemo(() => {
    const counts = {}
    for (const a of anomalies) {
      for (const tech of a.mitre_techniques || []) {
        counts[tech.tactic] = (counts[tech.tactic] || 0) + 1
      }
    }
    return Object.entries(counts)
      .map(([tactic, count]) => ({ tactic, count }))
      .sort((a, b) => b.count - a.count)
  }, [anomalies])

  /**
   * Filtert Anomalien, die auf Täterinfrastruktur hinweisen:
   * Entweder per Event-Typ (INFRA_EVENT_TYPES) oder
   * per MITRE-Taktik (ATTACKER_INFRA_TACTICS).
   */
  const infraAnomalies = useMemo(
    () => anomalies.filter(a =>
      INFRA_EVENT_TYPES.has(a.event_type) ||
      (a.mitre_techniques || []).some(t => ATTACKER_INFRA_TACTICS.has(t.tactic))
    ),
    [anomalies]
  )

  // Early return NACH allen Hooks
  if (!data) return null

  /** Gespeichertes Ergebnis einer früheren Ollama-Analyse (aus Job-Daten) */
  const llmInsight    = data.llmQuickAnalysis || null

  /** Taktiken die der Angreifer-Infrastruktur zugeordnet werden */
  const infraTactics  = tacticSummary.filter(t => ATTACKER_INFRA_TACTICS.has(t.tactic))

  /** Taktiken die dem Angriff auf das Opfersystem zugeordnet werden */
  const victimTactics = tacticSummary.filter(t => !ATTACKER_INFRA_TACTICS.has(t.tactic))

  /**
   * Startet die lokale Ollama-Bedrohungsanalyse der Anomalien.
   * Speichert das Ergebnis im Job-State (bleibt bei Tab-Wechsel erhalten).
   */
  const handleAnalyze = async () => {
    setLlmLoading(true)
    try {
      const result = await analyzeAnomaliesLocal(anomalies)
      updateJobData(activeJob.job_id, { llmQuickAnalysis: result })
    } catch (err) {
      updateJobData(activeJob.job_id, { llmQuickAnalysis: `**Fehler:** ${err.message}` })
    } finally {
      setLlmLoading(false)
    }
  }

  return (
    <div className="space-y-6">

      {/* ── Tab-Switcher: Threat Intelligence vs. Täterinfrastruktur vs. Anti-Forensics ── */}
      {anomalies.length > 0 && (
        <div className="flex items-center gap-1 p-1 rounded-xl bg-white/[0.03] border border-white/[0.05] w-fit">
          <button
            onClick={() => setActiveTab('threat')}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${
              activeTab === 'threat'
                ? 'bg-white/[0.08] text-white'
                : 'text-white/40 hover:text-white/60'
            }`}
          >
            <Brain size={14} className={activeTab === 'threat' ? 'text-accent-purple' : 'text-white/30'} />
            Threat Intelligence
          </button>
          <button
            onClick={() => setActiveTab('attacker_infra')}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${
              activeTab === 'attacker_infra'
                ? 'bg-white/[0.08] text-white'
                : 'text-white/40 hover:text-white/60'
            }`}
          >
            <Target size={14} className={activeTab === 'attacker_infra' ? 'text-risk-critical' : 'text-white/30'} />
            Täterinfrastruktur
            {/* Badge zeigt Anzahl der Infrastruktur-Anomalien */}
            {infraAnomalies.length > 0 && (
              <span className="text-[9px] bg-risk-critical/20 text-risk-critical px-1.5 py-0.5 rounded-full">
                {infraAnomalies.length}
              </span>
            )}
          </button>
          <button
            onClick={() => setActiveTab('antiforensics')}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${
              activeTab === 'antiforensics'
                ? 'bg-white/[0.08] text-white'
                : 'text-white/40 hover:text-white/60'
            }`}
          >
            <ShieldOff size={14} className={activeTab === 'antiforensics' ? 'text-risk-high' : 'text-white/30'} />
            Anti-Forensics
            {/* Badge zeigt Anzahl der Anti-Forensik-Befunde */}
            {data?.antiforensics?.findings_count > 0 && (
              <span className="text-[9px] bg-risk-high/20 text-risk-high px-1.5 py-0.5 rounded-full">
                {data.antiforensics.findings_count}
              </span>
            )}
          </button>
        </div>
      )}

      {/* ══════════════════════════════════════════════════════════════════ */}
      {/* TAB: Threat Intelligence (Standard-Ansicht) */}
      {/* ══════════════════════════════════════════════════════════════════ */}
      {activeTab === 'threat' && (
        <>
          {/* ── LLM Quick Analysis (Ollama, On-Demand) ── */}
          {anomalies.length > 0 && (
            <div className="glass-card">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-sm font-medium text-white/50 flex items-center gap-2">
                  <Brain size={14} className="text-accent-purple" />
                  KI Threat Intelligence (Ollama)
                </h3>
                {/* Button-Icon wechselt je nach Zustand: Sparkles / Loader / Check */}
                <button
                  onClick={handleAnalyze}
                  disabled={llmLoading}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-accent-purple/10 text-accent-purple hover:bg-accent-purple/20 transition-all disabled:opacity-50"
                >
                  {llmLoading ? (
                    <Loader2 size={12} className="animate-spin" />
                  ) : llmInsight ? (
                    <Check size={12} />
                  ) : (
                    <Sparkles size={12} />
                  )}
                  {llmInsight ? 'Neu analysieren' : 'Analysieren'}
                </button>
              </div>

              {/* Markdown-gerenderte LLM-Antwort (mit XSS-Sanitierung via DOMPurify) */}
              {llmInsight && (
                <div
                  className="report-content text-sm"
                  dangerouslySetInnerHTML={{
                    __html: DOMPurify.sanitize(marked.parse(llmInsight))
                  }}
                />
              )}
              {!llmInsight && !llmLoading && (
                <p className="text-xs text-white/25">
                  Klicke "Analysieren" um eine lokale KI-Bedrohungsanalyse zu starten (Ollama).
                </p>
              )}
              {llmLoading && (
                <div className="flex items-center gap-3 py-4">
                  <div className="w-6 h-6 border-2 border-accent-purple border-t-transparent rounded-full animate-spin" />
                  <span className="text-xs text-white/30">Ollama analysiert Anomalien… (ca. 2–3 Min)</span>
                </div>
              )}
            </div>
          )}

          {/* ── MITRE ATT&CK Kill Chain Visualisierung ── */}
          {anomalies.length > 0 && <AttackGraph anomalies={anomalies} />}

          {/* ── Multi-Agent LLM Analyse (Triage → Analyst → Reporter) ── */}
          {anomalies.length > 0 && <AgentAnalysisView />}

          {/* ── Vollständige bewertete Anomalie-Liste ── */}
          <AnomalyList anomalies={anomalies} />
        </>
      )}

      {/* ══════════════════════════════════════════════════════════════════ */}
      {/* TAB: Täterinfrastruktur-Analyse */}
      {/* ══════════════════════════════════════════════════════════════════ */}
      {activeTab === 'attacker_infra' && (
        <div className="space-y-6">

          {/* ── Erklärungstext: Perspektiven-Unterschied Täter vs. Opfer ── */}
          <div className="glass-card border border-accent-blue/10 bg-accent-blue/[0.03]">
            <div className="flex items-start gap-3">
              <Target size={16} className="text-accent-blue flex-shrink-0 mt-0.5" />
              <div>
                <p className="text-sm font-medium text-white/70 mb-1">Täterinfrastruktur-Analyse</p>
                <p className="text-xs text-white/40 leading-relaxed">
                  Diese Ansicht fokussiert auf Hinweise die auf die <strong className="text-white/60">Infrastruktur des Angreifers</strong> hinweisen —
                  C2-Server, VPN-Nutzung, Tool-Staging, Lateral Movement und Exfiltration.
                  Im Gegensatz zur klassischen Opfer-Analyse wird hier die Perspektive des Täters eingenommen.
                </p>
              </div>
            </div>
          </div>

          {/* ── MITRE ATT&CK Kill Chain Coverage (aufgeteilt) ── */}
          {tacticSummary.length > 0 && (
            <div className="glass-card">
              <h3 className="text-sm font-medium text-white/50 mb-4 flex items-center gap-2">
                <Shield size={14} className="text-accent-blue" />
                MITRE ATT&CK Kill Chain Coverage
              </h3>

              {/* Täterinfrastruktur-Taktiken: Grid-Karten mit Icon und Zähler */}
              {infraTactics.length > 0 && (
                <div className="mb-4">
                  <div className="text-[10px] text-risk-critical uppercase tracking-wider mb-2 flex items-center gap-1.5">
                    <Target size={9} />
                    Täterinfrastruktur-Taktiken
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    {infraTactics.map(({ tactic, count }) => {
                      const cfg = TACTIC_CONFIG[tactic] || { icon: Network, color: 'text-white/50', bg: 'bg-white/[0.05]' }
                      const Icon = cfg.icon
                      return (
                        <div key={tactic} className={`flex items-center gap-2.5 p-3 rounded-xl ${cfg.bg} border border-white/[0.04]`}>
                          <Icon size={14} className={cfg.color} />
                          <div className="min-w-0 flex-1">
                            <div className="text-xs font-medium text-white/70 truncate">{tactic}</div>
                            <div className={`text-[10px] ${cfg.color}`}>{count} Ereignis{count !== 1 ? 'se' : ''}</div>
                          </div>
                        </div>
                      )
                    })}
                  </div>
                </div>
              )}

              {/* Opfersystem-Taktiken: kompaktere Chip-Darstellung */}
              {victimTactics.length > 0 && (
                <div>
                  <div className="text-[10px] text-white/30 uppercase tracking-wider mb-2">Angriffs-Taktiken (Opfersystem)</div>
                  <div className="flex flex-wrap gap-2">
                    {victimTactics.map(({ tactic, count }) => {
                      const cfg = TACTIC_CONFIG[tactic] || { icon: Shield, color: 'text-white/40', bg: 'bg-white/[0.04]' }
                      const Icon = cfg.icon
                      return (
                        <div key={tactic} className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg ${cfg.bg}`}>
                          <Icon size={10} className={cfg.color} />
                          <span className="text-xs text-white/50">{tactic}</span>
                          <span className={`text-[9px] ${cfg.color} font-mono`}>{count}×</span>
                        </div>
                      )
                    })}
                  </div>
                </div>
              )}

              {tacticSummary.length === 0 && (
                <p className="text-xs text-white/25">Keine MITRE-Taktiken in den Anomalien erkannt.</p>
              )}
            </div>
          )}

          {/* ── Infrastruktur-Indikatoren: expandierbare Event-Zeilen ── */}
          {infraAnomalies.length > 0 ? (
            <div className="glass-card">
              <h3 className="text-sm font-medium text-white/50 mb-3 flex items-center gap-2">
                <Network size={14} className="text-risk-critical" />
                Infrastruktur-Indikatoren
                <span className="text-[10px] bg-risk-critical/15 text-risk-critical px-2 py-0.5 rounded-full">
                  {infraAnomalies.length} Events
                </span>
              </h3>
              <div className="space-y-2">
                {/* Maximal 50 Events anzeigen, Rest wird durch "+ N weitere" angezeigt */}
                {infraAnomalies.slice(0, 50).map((event, idx) => (
                  <InfraEventRow key={idx} event={event} />
                ))}
                {infraAnomalies.length > 50 && (
                  <p className="text-xs text-white/25 text-center pt-2">
                    + {infraAnomalies.length - 50} weitere Events
                  </p>
                )}
              </div>
            </div>
          ) : (
            <div className="glass-card text-center py-8">
              <Target size={24} className="text-white/15 mx-auto mb-2" />
              <p className="text-sm text-white/30">Keine Täterinfrastruktur-Indikatoren erkannt.</p>
              <p className="text-xs text-white/20 mt-1">
                Für diese Analyse werden C2-Beacons, VPN-Events, Tool-Staging und Lateral-Movement-Events ausgewertet.
              </p>
            </div>
          )}

          {/* ── Anomalie-Liste gefiltert auf MITRE-Infra-Taktiken ── */}
          <AnomalyList anomalies={anomalies} filterTactics={ATTACKER_INFRA_TACTICS} />

        </div>
      )}

      {/* ══════════════════════════════════════════════════════════════════ */}
      {/* TAB: Anti-Forensics (FA-23) */}
      {/* ══════════════════════════════════════════════════════════════════ */}
      {activeTab === 'antiforensics' && (
        <AntiForensicsPanel antiforensics={data?.antiforensics} />
      )}

    </div>
  )
}

// ── Einzelne Infra-Event-Zeile ─────────────────────────────────────────────────

/**
 * Komprimierte Zeile für ein einzelnes Infrastruktur-Event.
 * Per Klick expandierbar, zeigt dann vollständige MITRE-Techniken
 * und Netzwerk-Metadaten (IPs, Port, Nutzer, Zeitstempel).
 *
 * @param {Object} props
 * @param {Object} props.event - Anomalie-Event mit Infrastruktur-Bezug
 */
function InfraEventRow({ event }) {
  const [expanded, setExpanded] = useState(false)

  const techniques = event.mitre_techniques || []

  // Netzwerk-Metadaten aus direkten Feldern oder metadata-Objekt extrahieren
  const src_ip  = event.src_ip  || event.metadata?.src_ip  || event.client_ip || ''
  const dst_ip  = event.dst_ip  || event.metadata?.dst_ip  || ''
  const user    = event.user    || event.metadata?.user    || ''
  const port    = event.dst_port || event.metadata?.dst_port || ''

  /**
   * Farbkodierung nach Event-Typ — kritische Typen (C2, Reverse Shell)
   * erscheinen in Rot, weniger kritische in Orange/Blau/Lila.
   */
  const TYPE_COLORS = {
    'c2_beacon':               'text-risk-critical',
    'reverse_shell_attempt':   'text-risk-critical',
    'c2_tool':                 'text-risk-high',
    'vpn_connection':          'text-accent-blue',
    'suspicious_tool_installed': 'text-risk-high',
    'data_exfiltration':       'text-risk-high',
    'lateral_movement':        'text-accent-purple',
  }
  const typeColor = TYPE_COLORS[event.event_type] || 'text-white/40'

  return (
    <div
      className="rounded-xl bg-white/[0.02] border border-white/[0.04] hover:border-white/[0.07] transition-all cursor-pointer"
      onClick={() => setExpanded(prev => !prev)}
    >
      {/* ── Zusammengeklappte Zeile ── */}
      <div className="flex items-center gap-3 px-3 py-2.5">
        {/* Event-Typ: farbkodiert, Monospace, feste Breite */}
        <span className={`text-xs font-mono font-medium ${typeColor} flex-shrink-0 w-48 truncate`}>
          {event.event_type}
        </span>

        {/* Kurzbeschreibung: message bevorzugt, fällt auf description zurück */}
        <span className="text-xs text-white/50 flex-1 truncate">
          {event.message || event.description || '—'}
        </span>

        {/* IP-Verbindung: src → dst:port in kompakter Notation */}
        {(src_ip || dst_ip) && (
          <span className="text-[10px] font-mono text-white/25 flex-shrink-0">
            {src_ip}{src_ip && dst_ip ? ' → ' : ''}{dst_ip}{port ? `:${port}` : ''}
          </span>
        )}

        {/* MITRE-Badges: max. 2 sichtbar, Rest als "+N" */}
        {techniques.length > 0 && (
          <div className="flex items-center gap-1 flex-shrink-0">
            {techniques.slice(0, 2).map((t, i) => (
              <span key={i} className="text-[9px] bg-risk-critical/10 text-risk-critical px-1.5 py-0.5 rounded font-mono">
                {t.id}
              </span>
            ))}
            {techniques.length > 2 && (
              <span className="text-[9px] text-white/25">+{techniques.length - 2}</span>
            )}
          </div>
        )}
      </div>

      {/* ── Expandiertes Detail ── */}
      {expanded && (
        <div className="border-t border-white/[0.04] px-3 py-3 space-y-2">
          {/* Alle MITRE-Techniken mit vollständigem Namen und Taktik */}
          {techniques.length > 0 && (
            <div>
              <span className="text-[9px] text-white/25 uppercase tracking-wider block mb-1.5">MITRE ATT&CK</span>
              <div className="flex flex-wrap gap-1.5">
                {techniques.map((t, i) => (
                  <div key={i} className="flex items-center gap-1.5 bg-white/[0.03] rounded-lg px-2 py-1">
                    <span className="text-[10px] font-mono text-risk-critical">{t.id}</span>
                    <span className="text-[10px] text-white/50">{t.name}</span>
                    <span className="text-[9px] text-white/25">{t.tactic}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Netzwerk-Metadaten im 3-Spalten-Grid */}
          <div className="grid grid-cols-3 gap-2 text-xs">
            {src_ip  && <InfoCell label="Quell-IP"    value={src_ip} />}
            {dst_ip  && <InfoCell label="Ziel-IP"     value={dst_ip} />}
            {port    && <InfoCell label="Port"        value={port} />}
            {user    && <InfoCell label="Nutzer"      value={user} />}
            {event.source && <InfoCell label="Quelle" value={event.source} />}
            {event.timestamp && <InfoCell label="Zeit" value={new Date(event.timestamp).toLocaleString('de-DE')} />}
          </div>
        </div>
      )}
    </div>
  )
}

// ── Metadaten-Zelle ────────────────────────────────────────────────────────────

/**
 * Einfache Label + Wert Darstellung für die Detail-Expansion von InfraEventRow.
 *
 * @param {Object} props
 * @param {string} props.label - Beschriftung (z.B. "Quell-IP")
 * @param {string} props.value - Anzuzeigender Wert
 */
function InfoCell({ label, value }) {
  return (
    <div>
      <span className="text-[9px] text-white/25 uppercase tracking-wider block">{label}</span>
      <span className="font-mono text-white/60 text-xs truncate block">{value}</span>
    </div>
  )
}
