/**
 * ============================================================================
 * IOC LIST — Indicators of Compromise mit Threat-Intelligence-Lookup
 * ============================================================================
 * Zeigt alle vom Backend extrahierten Indicators of Compromise (IOCs) an,
 * gegliedert in zwei Bereiche:
 *
 *   1. Attacker Infrastructure (Täterinfrastruktur):
 *      Automatisch aus Anomalien gefilterte C2-IPs, Domains und eingesetzte
 *      Tools (nur Events die explizit auf Täterinfrastruktur hinweisen).
 *
 *   2. Standard IOCs:
 *      Alle vom AIPreprocessor extrahierten Indikatoren in Kategorien:
 *      IP-Adressen, Domains, Suspicious Files, Benutzer, Prozesse.
 *      Mit optionalem Threat-Intelligence-Lookup via Backend-API.
 *
 * Threat-Intelligence-Ergebnisse werden pro IOC als Verdict-Badge angezeigt
 * (malicious / suspicious / clean / unknown) und per Klick als Detail-Popup
 * geöffnet (Quellen: lokale KB, AbuseIPDB).
 *
 * Props:
 *   indicators — Objekt mit IOC-Arrays aus preprocessed.indicators
 *
 * State:
 *   loading      — TI-Lookup läuft gerade
 *   detailPopup  — aktuell geöffnetes TI-Detail-Popup (null = geschlossen)
 *
 * Abhängigkeiten:
 *   AppContext (activeJob, updateJobData), backend API (lookupThreatIntel), lucide-react
 *
 * @component
 */
import React, { useState, useMemo } from 'react'
import { useApp } from '../../context/AppContext'
import { lookupThreatIntel } from '../../api/backend'
import {
  Globe, Server, Hash, FileCode, Search, Loader2,
  ShieldAlert, ShieldCheck, ShieldQuestion, X, Target, Network,
} from 'lucide-react'

// ── Konfiguration ─────────────────────────────────────────────────────────────

/**
 * Darstellungs-Konfiguration für die fünf IOC-Kategorien.
 * `key` muss mit den Feldern in preprocessed.indicators übereinstimmen.
 */
const IOC_TYPES = [
  { key: 'ips',       label: 'IP Addresses',     icon: Server,   color: 'text-risk-high' },
  { key: 'domains',   label: 'Domains',           icon: Globe,    color: 'text-accent-purple' },
  { key: 'files',     label: 'Suspicious Files',  icon: FileCode, color: 'text-risk-medium' },
  { key: 'users',     label: 'Users',             icon: Hash,     color: 'text-accent-cyan' },
  { key: 'processes', label: 'Processes',         icon: Hash,     color: 'text-accent-green' },
]

// Event-Typen die auf Täterinfrastruktur hinweisen
const ATTACKER_INFRA_EVENT_TYPES = new Set([
  'c2_beacon', 'c2_tool', 'vpn_connection', 'vpn_ip_assigned',
  'reverse_shell_attempt', 'suspicious_tool_installed', 'data_exfiltration',
  'network_connect', 'dns_query',
])

/**
 * Farbschema und Icon-Mapping für TI-Verdicts.
 * Wird sowohl für Badges in der Liste als auch im Detail-Popup verwendet.
 */
const VERDICT_CONFIG = {
  malicious:  { color: 'text-risk-critical', bg: 'bg-risk-critical/10', icon: ShieldAlert, label: 'Malicious' },
  suspicious: { color: 'text-risk-high',     bg: 'bg-risk-high/10',     icon: ShieldAlert, label: 'Suspicious' },
  clean:      { color: 'text-accent-green',  bg: 'bg-accent-green/10',  icon: ShieldCheck, label: 'Clean' },
  unknown:    { color: 'text-white/30',      bg: 'bg-white/[0.04]',     icon: ShieldQuestion, label: 'Unknown' },
}

// ── Hauptkomponente ───────────────────────────────────────────────────────────

/**
 * IOC-Übersicht mit Täterinfrastruktur-Sektion und Standard-IOC-Grid.
 * Rendert nichts, wenn keine aktiven IOC-Kategorien vorhanden sind.
 *
 * @param {Object}    indicators             - IOC-Objekt aus preprocessed.indicators
 * @param {string[]}  [indicators.ips]       - Liste der extrahierten IP-Adressen
 * @param {string[]}  [indicators.domains]   - Liste der extrahierten Domains
 * @param {string[]}  [indicators.files]     - Liste verdächtiger Dateipfade
 * @param {string[]}  [indicators.users]     - Liste auffälliger Benutzer
 * @param {string[]}  [indicators.processes] - Liste auffälliger Prozesse
 */
export default function IOCList({ indicators }) {
  const { activeJob, updateJobData } = useApp()
  const [loading, setLoading]       = useState(false)
  const [detailPopup, setDetailPopup] = useState(null)

  // ── Täterinfrastruktur-IOCs aus Anomalien extrahieren ─────────────────────
  // Filtert Anomalien nach bekannten Infrastruktur-Event-Typen und sammelt
  // zugehörige IPs, DNS-Query-Domains und installierte Tools.
  const infraIocs = useMemo(() => {
    const anomalies = activeJob?.data?.anomalies || []
    const infraIps     = new Set()
    const infraDomains = new Set()
    const infraTools   = new Set()

    for (const a of anomalies) {
      const isInfra =
        ATTACKER_INFRA_EVENT_TYPES.has(a.event_type) ||
        a.is_attacker_infra === true

      if (!isInfra) continue

      // IPs sammeln (Loopback und IPv6-Loopback ausschließen)
      const srcIp = a.src_ip || a.metadata?.src_ip || a.client_ip
      const dstIp = a.dst_ip || a.metadata?.dst_ip
      if (srcIp && !srcIp.startsWith('127.') && srcIp !== '::1') infraIps.add(srcIp)
      if (dstIp && !dstIp.startsWith('127.') && dstIp !== '::1') infraIps.add(dstIp)

      // Domains aus DNS-Queries extrahieren (aus Metadaten oder Message-Regex)
      if (a.event_type === 'dns_query') {
        const q = a.metadata?.query_name || a.message?.match(/fragt '([^']+)'/)?.[1]
        if (q) infraDomains.add(q)
      }

      // Tools aus Package-Install / Staging-Events
      if (a.event_type === 'suspicious_tool_installed') {
        const pkg = a.package || a.metadata?.package
        if (pkg) infraTools.add(pkg)
      }
    }

    return {
      ips:     [...infraIps].slice(0, 30),
      domains: [...infraDomains].slice(0, 20),
      tools:   [...infraTools].slice(0, 20),
    }
  }, [activeJob?.data?.anomalies])

  const hasInfraIocs = infraIocs.ips.length > 0 || infraIocs.domains.length > 0 || infraIocs.tools.length > 0
  // Nur Kategorien anzeigen, die tatsächlich Einträge haben
  const activeTypes  = IOC_TYPES.filter(t => indicators[t.key]?.length > 0)

  if (activeTypes.length === 0) return null

  // TI-Ergebnisse aus Job-Daten laden (persistent im localStorage via AppContext)
  const tiResults = activeJob?.data?.threatIntelResults || []

  /**
   * Sucht das TI-Ergebnis für einen einzelnen IOC-Wert.
   * @param {string} value - Der IOC-Wert (IP, Domain etc.)
   * @returns {Object|null} TI-Ergebnis oder null wenn nicht vorhanden
   */
  const getVerdictForIOC = (value) => {
    const result = tiResults.find(r => r.value === String(value))
    return result || null
  }

  /**
   * Startet den Threat-Intelligence-Lookup für alle aktuellen Indikatoren.
   * Ergebnisse werden persistent in den Job-Daten (localStorage) gespeichert.
   */
  const handleLookup = async () => {
    setLoading(true)
    try {
      const data = await lookupThreatIntel(indicators)
      updateJobData(activeJob.job_id, { threatIntelResults: data.results || [] })
    } catch (err) {
      console.error('TI Lookup failed:', err)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-6">

      {/* ── Attacker Infrastructure IOCs (neu) ── */}
      {hasInfraIocs && (
        <div>
          <div className="flex items-center gap-2 mb-3">
            <Target size={14} className="text-risk-critical" />
            <h3 className="text-sm font-medium text-risk-critical">Attacker Infrastructure</h3>
            <span className="text-[9px] bg-risk-critical/15 text-risk-critical px-1.5 py-0.5 rounded-full uppercase tracking-wider">
              Täterinfrastruktur
            </span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {infraIocs.ips.length > 0 && (
              <InfraIocCard
                label="C2 / Infra IPs"
                icon={<Server size={13} className="text-risk-critical" />}
                items={infraIocs.ips}
                colorClass="text-risk-critical"
                bgClass="bg-risk-critical/10 border-risk-critical/20"
              />
            )}
            {infraIocs.domains.length > 0 && (
              <InfraIocCard
                label="C2 Domains"
                icon={<Globe size={13} className="text-risk-high" />}
                items={infraIocs.domains}
                colorClass="text-risk-high"
                bgClass="bg-risk-high/10 border-risk-high/20"
              />
            )}
            {infraIocs.tools.length > 0 && (
              <InfraIocCard
                label="Eingesetzte Tools"
                icon={<Network size={13} className="text-accent-purple" />}
                items={infraIocs.tools}
                colorClass="text-accent-purple"
                bgClass="bg-accent-purple/10 border-accent-purple/20"
              />
            )}
          </div>
        </div>
      )}

      {/* ── Standard IOCs ── */}
      <div>
      {/* Header mit Lookup-Button */}
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-medium text-white/50">Indicators of Compromise</h3>
        <button
          onClick={handleLookup}
          disabled={loading}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-accent-purple/10 text-accent-purple hover:bg-accent-purple/20 transition-all disabled:opacity-50"
        >
          {loading ? (
            <Loader2 size={12} className="animate-spin" />
          ) : (
            <Search size={12} />
          )}
          {tiResults.length > 0 ? 'Erneut pruefen' : 'TI Lookup'}
        </button>
      </div>

      {/* IOC-Karten pro Kategorie */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {activeTypes.map(({ key, label, icon: Icon, color }) => (
          <div key={key} className="glass-card">
            <div className="flex items-center gap-2 mb-3">
              <Icon size={14} className={color} />
              <span className="text-xs font-medium text-white/50">{label}</span>
              <span className="text-[10px] bg-white/[0.05] px-1.5 py-0.5 rounded-full text-white/30">
                {indicators[key].length}
              </span>
            </div>

            <div className="space-y-1">
              {indicators[key].map((val, i) => {
                const ti      = getVerdictForIOC(val)
                const verdict = ti ? VERDICT_CONFIG[ti.verdict] || VERDICT_CONFIG.unknown : null

                return (
                  <div
                    key={i}
                    className="flex items-center gap-2 px-2 py-1 rounded-lg hover:bg-white/[0.03] transition-colors group"
                  >
                    {/* Verdict badge — klickbar wenn TI-Daten vorhanden */}
                    {verdict ? (
                      <button
                        onClick={() => setDetailPopup(ti)}
                        className={`flex-shrink-0 w-5 h-5 rounded flex items-center justify-center ${verdict.bg} cursor-pointer hover:opacity-80 transition-opacity`}
                        title={verdict.label}
                      >
                        <verdict.icon size={10} className={verdict.color} />
                      </button>
                    ) : (
                      <span className="w-1 h-1 rounded-full bg-white/20 flex-shrink-0" />
                    )}

                    <code className="text-xs font-mono text-white/60 group-hover:text-white/80 truncate flex-1">
                      {val}
                    </code>

                    {/* Verdict text */}
                    {verdict && (
                      <span className={`text-[9px] px-1.5 py-0.5 rounded-full ${verdict.bg} ${verdict.color} flex-shrink-0`}>
                        {verdict.label}
                      </span>
                    )}
                  </div>
                )
              })}
            </div>
          </div>
        ))}
      </div>

      {/* Detail Popup */}
      {detailPopup && (
        <TIDetailPopup result={detailPopup} onClose={() => setDetailPopup(null)} />
      )}
      </div>
    </div>
  )
}

// ── Hilfskomponenten ──────────────────────────────────────────────────────────

/**
 * Karte für einen einzelnen Täterinfrastruktur-IOC-Typ (IPs, Domains oder Tools).
 * Zeigt alle Items als monospace-Liste mit farblicher Hervorhebung.
 *
 * @param {string}          label      - Bezeichnung der Kategorie (z.B. "C2 / Infra IPs")
 * @param {React.ReactNode} icon       - Lucide-Icon bereits als JSX
 * @param {string[]}        items      - Liste der IOC-Werte
 * @param {string}          colorClass - Tailwind-Textfarbe (z.B. "text-risk-critical")
 * @param {string}          bgClass    - Tailwind-Hintergrundfarbe + Border (z.B. "bg-risk-critical/10 border-risk-critical/20")
 */
function InfraIocCard({ label, icon, items, colorClass, bgClass }) {
  return (
    <div className={`glass-card border ${bgClass}`}>
      <div className="flex items-center gap-2 mb-3">
        {icon}
        <span className={`text-xs font-medium ${colorClass}`}>{label}</span>
        <span className={`text-[10px] px-1.5 py-0.5 rounded-full ${bgClass} ${colorClass} ml-auto`}>
          {items.length}
        </span>
      </div>
      <div className="space-y-1">
        {items.map((val, i) => (
          <div key={i} className="flex items-center gap-2 px-2 py-1 rounded-lg hover:bg-white/[0.03]">
            <span className="w-1 h-1 rounded-full bg-current flex-shrink-0 opacity-40" />
            <code className={`text-xs font-mono ${colorClass} opacity-70 truncate`}>{val}</code>
          </div>
        ))}
      </div>
    </div>
  )
}

/**
 * Detail-Popup für ein einzelnes Threat-Intelligence-Ergebnis.
 * Angezeigt nach Klick auf ein Verdict-Badge in der Standard-IOC-Liste.
 * Schließt sich per Klick auf Backdrop oder X-Button (kein Escape-Handler).
 *
 * @param {Object}   result          - TI-Ergebnis-Objekt
 * @param {string}   result.value    - IOC-Wert (IP, Domain etc.)
 * @param {string}   result.verdict  - "malicious" | "suspicious" | "clean" | "unknown"
 * @param {string}   result.confidence - Konfidenz-Einschätzung (z.B. "high")
 * @param {string}   result.type     - IOC-Typ (z.B. "ip", "domain")
 * @param {Object[]} [result.sources] - Array der TI-Quellen mit Details
 * @param {Function} onClose         - Callback zum Schließen des Popups
 */
function TIDetailPopup({ result, onClose }) {
  const verdict = VERDICT_CONFIG[result.verdict] || VERDICT_CONFIG.unknown

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={onClose}>
      <div
        className="glass-card w-full max-w-md mx-4 border border-white/[0.08]"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <verdict.icon size={16} className={verdict.color} />
            <span className="text-sm font-medium text-white/70">Threat Intelligence</span>
          </div>
          <button onClick={onClose} className="text-white/30 hover:text-white/60 transition-colors">
            <X size={16} />
          </button>
        </div>

        {/* IOC Value */}
        <div className="mb-3">
          <span className="text-[10px] text-white/25 uppercase tracking-wider block mb-0.5">IOC</span>
          <code className="text-sm font-mono text-white/80">{result.value}</code>
        </div>

        {/* Verdict + Confidence */}
        <div className="flex items-center gap-3 mb-4">
          <div className={`px-3 py-1.5 rounded-lg ${verdict.bg} ${verdict.color} text-xs font-medium`}>
            {verdict.label}
          </div>
          <div className="text-xs text-white/40">
            Confidence: <span className="text-white/60">{result.confidence}</span>
          </div>
          <div className="text-xs text-white/40">
            Typ: <span className="text-white/60">{result.type}</span>
          </div>
        </div>

        {/* Quellen-Details (lokale KB, AbuseIPDB etc.) */}
        {result.sources?.length > 0 && (
          <div className="border-t border-white/[0.04] pt-3">
            <span className="text-[10px] text-white/25 uppercase tracking-wider block mb-2">Quellen</span>
            <div className="space-y-2">
              {result.sources.map((src, i) => (
                <div key={i} className="p-2 rounded-lg bg-white/[0.02] border border-white/[0.04]">
                  <span className="text-xs font-medium text-accent-cyan block mb-1">
                    {src.source === 'local_kb' ? 'Lokale Knowledge-Base' :
                     src.source === 'abuseipdb' ? 'AbuseIPDB' : src.source}
                  </span>

                  {src.threat && (
                    <div className="text-xs text-white/50">Threat: {src.threat}</div>
                  )}
                  {src.original_source && (
                    <div className="text-xs text-white/40">Quelle: {src.original_source}</div>
                  )}
                  {src.abuse_score !== undefined && (
                    <div className="text-xs text-white/50">Abuse Score: {src.abuse_score}%</div>
                  )}
                  {src.country && (
                    <div className="text-xs text-white/40">Land: {src.country}</div>
                  )}
                  {src.isp && (
                    <div className="text-xs text-white/40">ISP: {src.isp}</div>
                  )}
                  {src.total_reports !== undefined && (
                    <div className="text-xs text-white/40">Reports: {src.total_reports}</div>
                  )}
                  {src.tags?.length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-1">
                      {src.tags.map((tag, j) => (
                        <span key={j} className="text-[9px] px-1.5 py-0.5 rounded-full bg-accent-purple/10 text-accent-purple">
                          {tag}
                        </span>
                      ))}
                    </div>
                  )}
                  {src.first_seen && (
                    <div className="text-[10px] text-white/25 mt-1">Erstmals: {src.first_seen}</div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
