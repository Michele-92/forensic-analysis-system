import React, { useState } from 'react'

// ── Daten ────────────────────────────────────────────────────────────────────

const UPLOAD_TYPES = [
  { icon: '💿', name: 'Disk-Images', formats: '.dd · .raw · .img · .e01 · .vmdk · .vhd', desc: 'Vollständige Kopien einer Festplatte oder virtuellen Maschine' },
  { icon: '📋', name: 'Log-Dateien', formats: '.log · .txt · .syslog · .evtx', desc: 'Protokolldateien von Systemen, Webservern, Firewalls oder Datenbanken' },
  { icon: '📦', name: 'Archive', formats: '.zip · .tar · .gz', desc: 'Komprimierte Pakete mit mehreren Dateien oder UAC-Dumps' },
]

const PIPELINE_STEPS = [
  { icon: '🔍', label: 'Erkennung',       desc: 'Dateiformat automatisch identifizieren' },
  { icon: '📂', label: 'Extraktion',      desc: 'Alle Ereignisse und Artefakte auslesen' },
  { icon: '⚖',  label: 'Normalisierung', desc: 'Alles in ein einheitliches Format bringen' },
  { icon: '🧠', label: 'KI-Analyse',      desc: 'Anomalien mit Machine Learning finden' },
  { icon: '🗺',  label: 'MITRE Mapping',  desc: 'Angriffstechniken automatisch zuordnen' },
  { icon: '🖥',  label: 'Systemprofile',  desc: 'OS, Dienste und Netzwerk rekonstruieren' },
  { icon: '🕵',  label: 'Anti-Forensics', desc: 'Spurenverwischung erkennen' },
  { icon: '📤',  label: 'Export',          desc: 'Alle Ergebnisse als JSON/CSV/Markdown' },
]

const CAPABILITIES = [
  {
    icon: '📊',
    color: '#818cf8',
    rgb: '129,140,248',
    title: 'Übersicht & Zusammenfassung',
    badge: 'Overview',
    short: 'Sofort verstehen, was passiert ist',
    desc: 'Die wichtigsten Erkenntnisse auf einen Blick: Gesamtrisiko, Top-Befunde, erkannte Angreifer-IPs, betroffene Benutzerkonten und ein System-Profil des analysierten Computers.',
    bullets: ['Risikobewertung (Kritisch · Hoch · Mittel · Niedrig)', 'Erkanntes Betriebssystem & Dienste', 'Beweissicherung mit MD5 + SHA256', 'Indikatoren (IPs, Domains, Prozesse)'],
  },
  {
    icon: '📈',
    color: '#34d399',
    rgb: '52,211,153',
    title: 'Zeitliche Analyse',
    badge: 'Analytics',
    short: 'Wann ist was passiert?',
    desc: 'Interaktive Zeitlinie aller Ereignisse mit farbigen Anomalie-Markierungen. Ein Donut-Chart zeigt die Verteilung der Ereignistypen. Die vollständige Ereignistabelle ist sortier- und durchsuchbar.',
    bullets: ['Zeitlinie mit Anomalie-Markierungen', 'Ereignistyp-Verteilung als Diagramm', 'Durchsuchbare Ereignistabelle', 'Partition-Filter bei Disk-Images'],
  },
  {
    icon: '🧠',
    color: '#a78bfa',
    rgb: '167,139,250',
    title: 'KI-Tiefenanalyse',
    badge: 'Intelligence',
    short: '3 KI-Agenten analysieren den Vorfall',
    desc: 'Drei spezialisierte KI-Agenten (Triage, Analyst, Reporter) arbeiten nacheinander und erstellen eine vollständige forensische Analyse – inklusive Angriffskette, MITRE ATT&CK Mapping und einem gerichtsverwertbaren Bericht.',
    bullets: ['Automatische Triage (Kritisch / Verdächtig / Fehlalarm)', 'Angriffsketten-Rekonstruktion', 'MITRE ATT&CK Kill Chain (12 Phasen)', 'Anti-Forensics-Befunde mit Risiko-Score'],
  },
  {
    icon: '🛡',
    color: '#f97316',
    rgb: '249,115,22',
    title: 'Bedrohungs-Intelligence',
    badge: 'Threat Intel',
    short: 'Sind die gefundenen IPs bekannte Angreifer?',
    desc: 'Jede erkannte IP-Adresse und Domain kann gegen eine lokale Bedrohungsdatenbank und AbuseIPDB geprüft werden. Das Ergebnis: farbige Bewertungen pro IOC.',
    bullets: ['Lokale Wissensdatenbank (offline)', 'AbuseIPDB-Abfrage (optional)', 'Farbige Verdict-Badges: Malicious · Suspicious · Clean', 'Detail-Popup mit Herkunft und Tags'],
  },
  {
    icon: '📁',
    color: '#c084fc',
    rgb: '192,132,252',
    title: 'Fallverwaltung',
    badge: 'Case Management',
    short: 'Mehrere Quellen zu einem Vorfall zusammenfassen',
    desc: 'Mehrere Analysen können einem Fall zugeordnet werden – z.B. alle Log-Dateien eines Vorfalls. Der Fall wird dauerhaft auf dem Server gespeichert und überlebt Browser-Neustarts.',
    bullets: ['Drag & Drop Zuweisung', 'Quellenübergreifende KI-Korrelation', 'Gemeinsame IOCs über alle Quellen', 'Backend-persistent (kein Datenverlust)'],
  },
  {
    icon: '📄',
    color: '#60a5fa',
    rgb: '96,165,250',
    title: 'Berichte & Beweissicherung',
    badge: 'Export',
    short: 'Professionelle PDF-Reports für Gericht & Management',
    desc: 'Mit einem Klick wird ein strukturierter forensischer PDF-Report erstellt. Die integrierten MD5/SHA256-Hashes ermöglichen den Nachweis, dass die Beweisdatei nicht verändert wurde.',
    bullets: ['PDF-Report mit Deckblatt & Executive Summary', 'MITRE ATT&CK Tabelle & IOC-Liste', 'MD5 + SHA256 auf dem Deckblatt', 'Vollständiger Audit-Trail (Chain of Custody)'],
  },
]

// ── Komponenten ──────────────────────────────────────────────────────────────

function UploadCard({ item }) {
  return (
    <div className="flex-1 min-w-[180px] rounded-2xl p-4 transition-all duration-200 hover:scale-105"
      style={{ background: 'rgba(129,140,248,0.06)', border: '1px solid rgba(129,140,248,0.18)' }}>
      <div className="text-3xl mb-2">{item.icon}</div>
      <div className="text-sm font-semibold text-white/80 mb-1">{item.name}</div>
      <div className="text-[10px] font-mono text-indigo-400/70 mb-2">{item.formats}</div>
      <div className="text-[11px] text-white/35 leading-relaxed">{item.desc}</div>
    </div>
  )
}

function PipelineStep({ step, idx, total }) {
  return (
    <div className="flex items-center gap-0">
      <div className="flex flex-col items-center">
        <div className="w-10 h-10 rounded-xl flex items-center justify-center text-lg flex-shrink-0"
          style={{ background: 'rgba(251,191,36,0.1)', border: '1px solid rgba(251,191,36,0.2)' }}>
          {step.icon}
        </div>
        <div className="text-[10px] text-white/40 mt-1 text-center w-16 leading-tight">{step.label}</div>
      </div>
      {idx < total - 1 && (
        <div className="relative w-8 h-px mb-5 overflow-visible flex-shrink-0"
          style={{ background: 'rgba(251,191,36,0.2)' }}>
          <div className="particle-right w-2 h-2 top-1/2 -translate-y-1/2"
            style={{
              background: '#fbbf24',
              boxShadow: '0 0 8px #fbbf24',
              animationDelay: `${idx * 200}ms`,
              animationDuration: '2s',
            }} />
          <svg className="absolute right-0 top-1/2 -translate-y-1/2" width="6" height="8" viewBox="0 0 6 8">
            <path d="M0 0L6 4L0 8" fill="none" stroke="rgba(251,191,36,0.5)" strokeWidth="1.2" />
          </svg>
        </div>
      )}
    </div>
  )
}

function CapabilityCard({ cap }) {
  const [open, setOpen] = useState(false)
  return (
    <div
      className="rounded-2xl cursor-pointer transition-all duration-300"
      style={{
        background: open ? `rgba(${cap.rgb}, 0.09)` : `rgba(${cap.rgb}, 0.05)`,
        border: `1px solid rgba(${cap.rgb}, ${open ? '0.4' : '0.18'})`,
        boxShadow: open ? `0 0 30px rgba(${cap.rgb}, 0.12)` : 'none',
      }}
      onClick={() => setOpen(o => !o)}
    >
      <div className="p-5">
        <div className="flex items-start gap-3">
          <div className="w-11 h-11 rounded-xl flex items-center justify-center text-2xl flex-shrink-0"
            style={{ background: `rgba(${cap.rgb}, 0.12)`, border: `1px solid rgba(${cap.rgb}, 0.2)` }}>
            {cap.icon}
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-sm font-semibold text-white/85">{cap.title}</span>
              <span className="text-[10px] px-2 py-0.5 rounded-full font-medium"
                style={{ background: `rgba(${cap.rgb}, 0.15)`, color: cap.color }}>
                {cap.badge}
              </span>
            </div>
            <div className="text-xs text-white/45 mt-0.5">{cap.short}</div>
          </div>
          <span className="text-white/25 text-sm flex-shrink-0 mt-0.5">
            {open ? '▲' : '▼'}
          </span>
        </div>

        {open && (
          <div className="mt-4 pt-4" style={{ borderTop: `1px solid rgba(${cap.rgb}, 0.12)` }}>
            <p className="text-xs text-white/50 leading-relaxed mb-3">{cap.desc}</p>
            <ul className="space-y-1.5">
              {cap.bullets.map((b, i) => (
                <li key={i} className="flex items-start gap-2 text-xs text-white/60">
                  <span style={{ color: cap.color }} className="mt-0.5 flex-shrink-0">✓</span>
                  {b}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  )
}

// ── Hauptkomponente ───────────────────────────────────────────────────────────

export default function BigPicture() {
  return (
    <div className="max-w-5xl mx-auto px-4 pb-20">

      {/* Hero */}
      <div className="text-center mb-14 pt-2">
        <div className="inline-flex items-center justify-center w-20 h-20 rounded-3xl text-4xl mb-5"
          style={{ background: 'rgba(129,140,248,0.1)', border: '1px solid rgba(129,140,248,0.2)', animation: 'float 3s ease-in-out infinite' }}>
          🔬
        </div>
        <h2 className="text-3xl font-bold text-white/90 mb-3">
          Was kann das System?
        </h2>
        <p className="text-base text-white/40 max-w-xl mx-auto leading-relaxed">
          Eine Datei hochladen – und das System führt automatisch eine vollständige
          digitale Forensik-Analyse durch. Hier ist alles, was danach möglich ist.
        </p>
      </div>

      {/* ── Schritt 1: Upload ── */}
      <Section
        step="1"
        color="#818cf8" rgb="129,140,248"
        icon="⬆" title="Datei hochladen"
        sub="Einfach per Drag & Drop in die Sidebar ziehen – fertig."
      >
        <div className="flex gap-3 flex-wrap">
          {UPLOAD_TYPES.map((t, i) => <UploadCard key={i} item={t} />)}
        </div>
        <div className="mt-4 text-xs text-white/30 text-center">
          Maximale Dateigröße: 10 GB · Mehrere Dateien gleichzeitig möglich
        </div>
      </Section>

      <BigArrow label="Analyse startet automatisch im Hintergrund" />

      {/* ── Schritt 2: Pipeline ── */}
      <Section
        step="2"
        color="#fbbf24" rgb="251,191,36"
        icon="⚙" title="Automatische Analyse (dauert je nach Dateigröße 1–10 Minuten)"
        sub="11 Verarbeitungsstufen laufen vollautomatisch – keine Eingabe nötig."
      >
        <div className="flex items-start justify-center flex-wrap gap-0 py-2">
          {PIPELINE_STEPS.map((s, i) => (
            <PipelineStep key={i} step={s} idx={i} total={PIPELINE_STEPS.length} />
          ))}
        </div>
        <div className="mt-5 grid grid-cols-2 md:grid-cols-4 gap-2">
          {[
            { icon: '🤖', text: '100% lokal · keine Cloud' },
            { icon: '🔒', text: 'Daten verlassen den Server nicht' },
            { icon: '⚡', text: 'ML + KI vollautomatisch' },
            { icon: '📋', text: '85 MITRE ATT&CK Techniken' },
          ].map((f, i) => (
            <div key={i} className="flex items-center gap-2 px-3 py-2 rounded-xl text-xs text-white/45"
              style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)' }}>
              <span>{f.icon}</span>{f.text}
            </div>
          ))}
        </div>
      </Section>

      <BigArrow label="Ergebnisse sofort abrufbar" />

      {/* ── Schritt 3: Möglichkeiten ── */}
      <Section
        step="3"
        color="#34d399" rgb="52,211,153"
        icon="✨" title="Was kann ich jetzt tun?"
        sub="Klicke auf eine Karte, um mehr zu erfahren."
      >
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {CAPABILITIES.map((cap, i) => (
            <CapabilityCard key={i} cap={cap} />
          ))}
        </div>
      </Section>

      {/* ── Abschluss-Karte ── */}
      <div className="mt-12 text-center">
        <div className="inline-block px-8 py-5 rounded-2xl"
          style={{ background: 'rgba(129,140,248,0.06)', border: '1px solid rgba(129,140,248,0.15)' }}>
          <div className="text-2xl mb-2">🎓</div>
          <div className="text-sm font-semibold text-white/70 mb-1">
            Entwickelt als Bachelorarbeit
          </div>
          <div className="text-xs text-white/30 max-w-sm leading-relaxed">
            LFX kombiniert klassische Forensik-Tools (Dissect, Sleuth Kit) mit
            modernen KI-Methoden (Ollama/Llama 3.1, Isolation Forest) zu einem
            vollständig offline-fähigen Analyse-System.
          </div>
        </div>
      </div>

    </div>
  )
}

// ── Hilfskomponenten ─────────────────────────────────────────────────────────

function Section({ step, color, rgb, icon, title, sub, children }) {
  return (
    <div className="flow-enter rounded-3xl p-6 md:p-8"
      style={{ background: `rgba(${rgb}, 0.04)`, border: `1px solid rgba(${rgb}, 0.14)` }}>
      {/* Header */}
      <div className="flex items-center gap-4 mb-6">
        <div className="w-12 h-12 rounded-2xl flex items-center justify-center text-2xl flex-shrink-0"
          style={{ background: `rgba(${rgb}, 0.12)`, border: `1px solid rgba(${rgb}, 0.25)` }}>
          {icon}
        </div>
        <div>
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-bold px-2 py-0.5 rounded-full uppercase tracking-widest"
              style={{ background: `rgba(${rgb}, 0.15)`, color }}>
              Schritt {step}
            </span>
          </div>
          <div className="text-base font-bold text-white/85 mt-1">{title}</div>
          <div className="text-xs text-white/35 mt-0.5">{sub}</div>
        </div>
      </div>
      {children}
    </div>
  )
}

function BigArrow({ label }) {
  return (
    <div className="flex flex-col items-center py-3">
      <div className="relative w-px h-10 overflow-visible"
        style={{ background: 'linear-gradient(to bottom, rgba(255,255,255,0.15), rgba(255,255,255,0.03))' }}>
        <div className="particle-down w-2.5 h-2.5 left-1/2 -translate-x-1/2"
          style={{ background: '#818cf8', boxShadow: '0 0 12px #818cf8', animationDuration: '1.2s' }} />
      </div>
      <svg width="14" height="8" viewBox="0 0 14 8" fill="none">
        <path d="M1 1L7 7L13 1" stroke="rgba(255,255,255,0.2)" strokeWidth="1.5" strokeLinecap="round" />
      </svg>
      {label && (
        <div className="text-[11px] text-white/25 font-mono mt-1 px-3 py-0.5 rounded-full"
          style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.06)' }}>
          {label}
        </div>
      )}
    </div>
  )
}
