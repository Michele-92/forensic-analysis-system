/**
 * ============================================================================
 * SYSTEM PROFILE CARD — Profil des analysierten Systems (FA-22)
 * ============================================================================
 * Zeigt das automatisch aus dem Disk-Image oder den Logs extrahierte
 * Systemprofil an. Die Daten stammen aus `system_profile.json` (FA-22) und
 * werden vom Backend in `data.systemProfile` bereitgestellt.
 *
 * Kompakte Übersicht (immer sichtbar):
 *   - Betriebssystem (Typ + Distribution + Version, mit OS-Emoji)
 *   - Kernel-Version
 *   - Hostname
 *   - Erkannte Benutzer (max. 3 angezeigt + Überzahl)
 *
 * Erweiterter Bereich (per Chevron-Button auf-/zuklappbar):
 *   - Erkannte Dienste (max. 20)
 *   - Netzwerk-IPs / Interfaces (max. 15)
 *   - Verdächtige Verzeichnisse / Pfade (max. 10, rot hervorgehoben)
 *   - Profil-Indikatoren (Anti-Forensics-Hinweise)
 *   - Erkennungs-Evidenz (wie das Profil ermittelt wurde)
 *
 * Rendert nichts wenn kein Profil vorhanden oder `os_type` undefiniert ist.
 *
 * Props:
 *   profile — Objekt aus system_profile.json (kann null/undefined sein)
 *
 * State:
 *   expanded — ob der erweiterte Bereich aufgeklappt ist
 *
 * Abhängigkeiten:
 *   lucide-react
 *
 * @component
 */
import React, { useState } from 'react'
import {
  Monitor, Server, Cpu, Users, Globe,
  ShieldAlert, ChevronDown, ChevronUp, FolderOpen,
} from 'lucide-react'

/**
 * SystemProfileCard — Zeigt das automatisch erstellte Systemprofil (FA-22).
 *
 * Props:
 *   profile — Objekt aus system_profile.json (kann null/undefined sein)
 */
export default function SystemProfileCard({ profile }) {
  const [expanded, setExpanded] = useState(false)

  // Keine Anzeige wenn kein Profil oder OS-Typ nicht erkannt
  if (!profile || profile.os_type === undefined) return null

  const {
    os_type, distribution, version, kernel, hostname,
    users = [], services = [], network_ifaces = [],
    suspicious_dirs = [], indicators = [],
    confidence, evidence = [],
  } = profile

  // Tailwind-Klassen für das Confidence-Badge je nach Erkennungssicherheit
  const confidenceColor = {
    high:   'text-accent-green  bg-accent-green/10',
    medium: 'text-risk-medium   bg-risk-medium/10',
    low:    'text-white/30      bg-white/[0.04]',
  }[confidence] || 'text-white/30 bg-white/[0.04]'

  // OS-Emoji zur schnellen visuellen Unterscheidung des Betriebssystems
  const osIcon = os_type === 'linux' ? '🐧'
    : os_type === 'windows' ? '🪟'
    : os_type === 'macos'   ? '🍎'
    : '❓'

  return (
    <div className="glass-card">
      {/* Header: Titel, Confidence-Badge, Pfad-Warnung, Expand-Toggle */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Monitor size={15} className="text-accent-cyan" />
          <h3 className="text-sm font-medium text-white/60">System-Profil</h3>
          <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${confidenceColor}`}>
            Confidence: {confidence}
          </span>
          {suspicious_dirs.length > 0 && (
            <span className="text-[10px] px-2 py-0.5 rounded-full bg-risk-high/10 text-risk-high">
              {suspicious_dirs.length} verdächtige Pfade
            </span>
          )}
        </div>
        <button
          onClick={() => setExpanded(p => !p)}
          className="text-white/25 hover:text-white/50 transition-colors"
        >
          {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
        </button>
      </div>

      {/* Kompakte Übersicht (immer sichtbar) */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <ProfileItem
          icon={<span className="text-sm">{osIcon}</span>}
          label="Betriebssystem"
          value={distribution
            ? `${distribution}${version ? ` ${version}` : ''}`
            : os_type !== 'unknown' ? os_type : '—'}
        />
        <ProfileItem
          icon={<Cpu size={13} className="text-accent-blue" />}
          label="Kernel"
          value={kernel || '—'}
          mono
        />
        <ProfileItem
          icon={<Server size={13} className="text-accent-purple" />}
          label="Hostname"
          value={hostname || '—'}
          mono
        />
        {/* Zeigt max. 3 Benutzer + Anzahl der Übrigen */}
        <ProfileItem
          icon={<Users size={13} className="text-accent-cyan" />}
          label="Benutzer"
          value={users.length > 0 ? `${users.slice(0, 3).join(', ')}${users.length > 3 ? ` +${users.length - 3}` : ''}` : '—'}
        />
      </div>

      {/* Erweiterter Bereich — nur sichtbar wenn expanded === true */}
      {expanded && (
        <div className="mt-4 pt-4 border-t border-white/[0.04] space-y-4">

          {/* Erkannte Dienste (max. 20 als Pills) */}
          {services.length > 0 && (
            <div>
              <span className="text-[10px] text-white/25 uppercase tracking-wider block mb-2">
                Erkannte Dienste ({services.length})
              </span>
              <div className="flex flex-wrap gap-1.5">
                {services.slice(0, 20).map((svc, i) => (
                  <span key={i} className="text-[11px] px-2 py-0.5 rounded-full bg-accent-blue/10 text-accent-blue font-mono">
                    {svc}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Netzwerk-IPs (max. 15) */}
          {network_ifaces.length > 0 && (
            <div>
              <span className="text-[10px] text-white/25 uppercase tracking-wider block mb-2 flex items-center gap-1">
                <Globe size={10} />
                Netzwerk-IPs ({network_ifaces.length})
              </span>
              <div className="flex flex-wrap gap-1.5">
                {network_ifaces.slice(0, 15).map((ip, i) => (
                  <code key={i} className="text-[11px] px-2 py-0.5 rounded-full bg-white/[0.04] text-white/50">
                    {ip}
                  </code>
                ))}
              </div>
            </div>
          )}

          {/* Verdächtige Verzeichnisse (max. 10, rot hervorgehoben) */}
          {suspicious_dirs.length > 0 && (
            <div>
              <span className="text-[10px] text-white/25 uppercase tracking-wider block mb-2 flex items-center gap-1">
                <FolderOpen size={10} className="text-risk-high" />
                <span className="text-risk-high">Verdächtige Pfade ({suspicious_dirs.length})</span>
              </span>
              <div className="space-y-1">
                {suspicious_dirs.slice(0, 10).map((p, i) => (
                  <code key={i} className="text-[11px] block px-2 py-0.5 rounded bg-risk-high/5 text-risk-high/70">
                    {p}
                  </code>
                ))}
              </div>
            </div>
          )}

          {/* Anti-Forensics-Indikatoren aus dem Profil */}
          {indicators.length > 0 && (
            <div>
              <span className="text-[10px] text-white/25 uppercase tracking-wider block mb-2 flex items-center gap-1">
                <ShieldAlert size={10} className="text-risk-medium" />
                <span className="text-risk-medium">Profil-Indikatoren</span>
              </span>
              <div className="space-y-1">
                {indicators.map((ind, i) => (
                  <div key={i} className="text-[11px] text-risk-medium/70 px-2 py-0.5 rounded bg-risk-medium/5">
                    {ind}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Erkennungs-Evidenz: erklärt wie das OS-Profil ermittelt wurde */}
          {evidence.length > 0 && (
            <div>
              <span className="text-[10px] text-white/25 uppercase tracking-wider block mb-2">
                Erkennungs-Evidenz
              </span>
              <div className="space-y-1">
                {evidence.map((ev, i) => (
                  <div key={i} className="text-[11px] text-white/30 px-2 py-0.5 rounded bg-white/[0.02]">
                    {ev}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ── Hilfskomponenten ──────────────────────────────────────────────────────────

/**
 * Einzelnes Profil-Datenpunkt-Item in der kompakten Übersicht.
 * Zeigt Icon, Label und Wert in einem kleinen Kachel-Layout.
 *
 * @param {React.ReactNode} icon    - Lucide-Icon oder Emoji als JSX
 * @param {string}          label   - Bezeichnung des Feldes (z.B. "Betriebssystem")
 * @param {string}          value   - Anzuzeigender Wert
 * @param {boolean}         [mono]  - Monospace-Schrift für technische Werte (Kernel, Hostname)
 */
function ProfileItem({ icon, label, value, mono }) {
  return (
    <div className="p-2 rounded-lg bg-white/[0.02]">
      <div className="flex items-center gap-1.5 mb-1">
        {icon}
        <span className="text-[10px] text-white/25 uppercase tracking-wider">{label}</span>
      </div>
      <span className={`text-xs text-white/70 truncate block ${mono ? 'font-mono' : ''}`} title={value}>
        {value}
      </span>
    </div>
  )
}
