import React, { useState } from 'react'
import FlowDiagram from './components/FlowDiagram.jsx'
import BigPicture from './components/BigPicture.jsx'
import { FLOWS } from './data/flows.js'
import { TYPE_CFG } from './utils/colors.js'

const BIG_PICTURE_TAB = { id: 'bigpicture', title: 'Großes Bild', emoji: '🗺' }

export default function App() {
  const [activeTab, setActiveTab] = useState('bigpicture')

  const allTabs = [BIG_PICTURE_TAB, ...FLOWS]
  const isBigPicture = activeTab === 'bigpicture'
  const activeFlow = FLOWS.find(f => f.id === activeTab)

  return (
    <div className="min-h-screen bg-app text-white relative">

      {/* ── Hintergrund-Glow ── */}
      <div className="fixed inset-0 pointer-events-none overflow-hidden z-0">
        <div className="absolute -top-40 left-1/4 w-[700px] h-[700px] rounded-full"
          style={{ background: 'radial-gradient(circle, rgba(99,102,241,0.07) 0%, transparent 70%)' }} />
        <div className="absolute bottom-0 right-1/4 w-[500px] h-[500px] rounded-full"
          style={{ background: 'radial-gradient(circle, rgba(167,139,250,0.06) 0%, transparent 70%)' }} />
        <div className="absolute top-1/2 -left-20 w-[400px] h-[400px] rounded-full"
          style={{ background: 'radial-gradient(circle, rgba(249,115,22,0.04) 0%, transparent 70%)' }} />
      </div>

      {/* ── Header ── */}
      <header
        className="relative z-10 sticky top-0"
        style={{
          background: 'rgba(3,3,12,0.88)',
          borderBottom: '1px solid rgba(255,255,255,0.06)',
          backdropFilter: 'blur(20px)',
        }}
      >
        {/* Titel */}
        <div className="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div
              className="w-9 h-9 rounded-xl flex items-center justify-center text-xl flex-shrink-0"
              style={{ background: 'rgba(99,102,241,0.15)', border: '1px solid rgba(99,102,241,0.25)' }}
            >
              🔬
            </div>
            <div>
              <h1 className="text-sm font-semibold text-white/90 leading-none">
                LFX — Datenfluss Visualisierung
              </h1>
              <p className="text-[11px] text-white/30 mt-0.5">
                Forensic Analysis System · Aufrufstruktur &amp; Datenverarbeitung
              </p>
            </div>
          </div>
          <div
            className="flex-shrink-0 text-[11px] font-mono px-3 py-1 rounded-full"
            style={{
              background: 'rgba(52,211,153,0.08)',
              border: '1px solid rgba(52,211,153,0.2)',
              color: '#34d399',
            }}
          >
            localhost:5174
          </div>
        </div>

        {/* Tabs */}
        <div className="max-w-6xl mx-auto px-4 flex gap-0 overflow-x-auto">
          {allTabs.map(tab => {
            const active = activeTab === tab.id
            const isBP = tab.id === 'bigpicture'
            const color = isBP ? '#34d399' : '#818cf8'
            const rgb  = isBP ? '52,211,153' : '129,140,248'
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className="relative flex items-center gap-2 px-5 py-3 text-xs font-medium whitespace-nowrap transition-all duration-200 border-b-2"
                style={{
                  borderColor: active ? color : 'transparent',
                  color: active ? color : 'rgba(255,255,255,0.35)',
                  background: active ? `rgba(${rgb}, 0.06)` : 'transparent',
                }}
              >
                <span className="text-base leading-none">{tab.emoji}</span>
                <span>{tab.title}</span>
                {isBP && !active && (
                  <span
                    className="text-[9px] px-1.5 py-0.5 rounded-full font-semibold"
                    style={{ background: 'rgba(52,211,153,0.15)', color: '#34d399' }}
                  >
                    NEU
                  </span>
                )}
                {active && (
                  <div
                    className="absolute bottom-0 left-0 right-0 h-px"
                    style={{ background: `linear-gradient(90deg, transparent, ${color}, transparent)` }}
                  />
                )}
              </button>
            )
          })}
        </div>
      </header>

      {/* ── Legende (nur bei Flow-Tabs) ── */}
      {!isBigPicture && (
        <div
          className="relative z-10 sticky top-[97px]"
          style={{
            background: 'rgba(3,3,12,0.75)',
            borderBottom: '1px solid rgba(255,255,255,0.04)',
            backdropFilter: 'blur(12px)',
          }}
        >
          <div className="max-w-6xl mx-auto px-6 py-2 flex items-center gap-5 flex-wrap overflow-x-auto">
            <span className="text-[10px] text-white/20 uppercase tracking-widest flex-shrink-0">
              Legende
            </span>
            {Object.entries(TYPE_CFG).map(([type, cfg]) => (
              <div key={type} className="flex items-center gap-1.5 flex-shrink-0">
                <div className="w-2 h-2 rounded-full"
                  style={{ background: cfg.color, boxShadow: `0 0 5px ${cfg.color}` }} />
                <span className="text-[10px] text-white/40">{cfg.icon} {cfg.label}</span>
              </div>
            ))}
            <span className="text-[10px] text-white/20 ml-2">
              · Auf einen Node klicken für Erklärung
            </span>
          </div>
        </div>
      )}

      {/* ── Hinweis-Banner für Big Picture ── */}
      {isBigPicture && (
        <div
          className="relative z-10"
          style={{
            background: 'rgba(52,211,153,0.05)',
            borderBottom: '1px solid rgba(52,211,153,0.1)',
          }}
        >
          <div className="max-w-6xl mx-auto px-6 py-2 flex items-center gap-2 text-xs text-emerald-400/60">
            <span>💡</span>
            <span>Diese Ansicht erklärt das System ohne technische Details — für alle verständlich. Die anderen Tabs zeigen den genauen Code-Aufruffluss.</span>
          </div>
        </div>
      )}

      {/* ── Haupt-Content ── */}
      <main className="relative z-10 pt-10 min-h-screen">
        {isBigPicture
          ? <BigPicture key="bigpicture" />
          : activeFlow
            ? <FlowDiagram key={activeTab} flow={activeFlow} />
            : null
        }
      </main>

      {/* ── Footer ── */}
      <footer
        className="relative z-10 text-center py-6 text-[11px] text-white/15"
        style={{ borderTop: '1px solid rgba(255,255,255,0.04)' }}
      >
        LFX Forensic Analysis System · Datenfluss Visualisierung · Port 5174
      </footer>
    </div>
  )
}
