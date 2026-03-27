/**
 * ============================================================================
 * ANALYTICS PANEL — Zeitliche & Artefakt-Analyse
 * ============================================================================
 * Hauptcontainer der Analytics-Ansicht. Bündelt vier Analyse-Perspektiven:
 *   1. Partition-Selector: Dropdown für Multi-Partition Disk-Images — nur
 *      sichtbar, wenn das Image mehr als eine Partition enthält.
 *   2. Timeline Chart: Stündliche Event-Dichte + Anomalie-Scatter (Recharts).
 *   3. Artifact Taxonomy: Kreisdiagramm der Artefakt-Typ-Verteilung.
 *   4. Event Table: Vollständige, filterbare und sortierbare Event-Liste.
 *
 * Props: keine — liest `activeJob` aus dem globalen AppContext.
 *
 * Abhängigkeiten:
 *   - AppContext  (activeJob)
 *   - TimelineChart, ArtifactTaxonomy, EventTable (Child-Komponenten)
 *   - lucide-react (HardDrive, Layers, ChevronDown)
 *
 * @component
 */
import React, { useState, useMemo } from 'react'
import { useApp } from '../../context/AppContext'
import TimelineChart from './TimelineChart'
import ArtifactTaxonomy from './ArtifactTaxonomy'
import EventTable from './EventTable'
import { HardDrive, Layers, ChevronDown } from 'lucide-react'

// ── Hauptkomponente ────────────────────────────────────────────────────────────

/**
 * Orchestriert die gesamte Analytics-Ansicht für den aktuell aktiven Job.
 * Verwaltet den Partition-Filterzustand und leitet gefilterte Daten
 * an alle Child-Komponenten weiter.
 */
export default function AnalyticsPanel() {
  const { activeJob } = useApp()

  /** Aktuell gewählte Partition — 'all' bedeutet keine Filterung */
  const [selectedPartition, setSelectedPartition] = useState('all')

  /** Steuert die Sichtbarkeit des Partition-Dropdowns */
  const [partitionDropdownOpen, setPartitionDropdownOpen] = useState(false)

  const data = activeJob?.data

  // Null-sichere Datenzugriffe — useMemo muss VOR jedem early return stehen (Rules of Hooks)

  /**
   * Vollständige Timeline — bevorzugt normalisierte Daten, fällt auf
   * preprocessed-Daten zurück, wenn der Normalizer noch nicht gelaufen ist.
   */
  const allTimeline = data?.normalized?.timeline || data?.preprocessed?.timeline || []

  /** Alle erkannten Anomalien aus dem IsolationForest-Schritt */
  const anomalies   = data?.anomalies || []

  /**
   * Extrahiert alle eindeutigen Partitionen aus der Timeline.
   * Partition-Informationen können direkt im Event oder im metadata-Objekt
   * stehen — beide Varianten werden berücksichtigt.
   *
   * Ergebnis: Array von { label, filesystem, count }
   */
  const partitions = useMemo(() => {
    const partitionMap = {}
    for (const event of allTimeline) {
      const p = event.partition || event.metadata?.partition
      if (p && !partitionMap[p]) {
        partitionMap[p] = {
          label:      p,
          filesystem: event.filesystem || event.metadata?.filesystem || '?',
          count:      0,
        }
      }
      if (p) partitionMap[p].count++
    }
    return Object.values(partitionMap)
  }, [allTimeline])

  /** true, wenn das Image mehr als eine Partition enthält */
  const hasMultiplePartitions = partitions.length > 1

  /**
   * Gefilterte Timeline — enthält bei Auswahl 'all' alle Events,
   * sonst nur die Events der gewählten Partition.
   */
  const timeline = useMemo(() => {
    if (selectedPartition === 'all' || !hasMultiplePartitions) return allTimeline
    return allTimeline.filter(e =>
      (e.partition || e.metadata?.partition) === selectedPartition
    )
  }, [allTimeline, selectedPartition, hasMultiplePartitions])

  /**
   * Analog zu `timeline`: Anomalien gefiltert nach gewählter Partition.
   * Wird separat berechnet, da Anomalien eine eigene Datenstruktur haben.
   */
  const filteredAnomalies = useMemo(() => {
    if (selectedPartition === 'all' || !hasMultiplePartitions) return anomalies
    return anomalies.filter(e =>
      (e.partition || e.metadata?.partition) === selectedPartition
    )
  }, [anomalies, selectedPartition, hasMultiplePartitions])

  // Early return NACH allen Hooks
  if (!data) return null

  /**
   * Metadaten der aktuell gewählten Partition für die Label-Anzeige
   * im Dropdown-Button (Filesystem-Typ, Event-Anzahl).
   */
  const selectedInfo = selectedPartition === 'all'
    ? null
    : partitions.find(p => p.label === selectedPartition)

  return (
    <div className="space-y-6">

      {/* ── Partition-Selector (nur bei Multi-Partition-Images) ── */}
      {hasMultiplePartitions && (
        <div className="glass-card">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-accent-blue/10 flex items-center justify-center">
                <HardDrive size={14} className="text-accent-blue" />
              </div>
              <div>
                <span className="text-xs text-white/30 block">Partitionen erkannt</span>
                <span className="text-sm font-medium text-white/70">
                  {partitions.length} Partitionen im Image
                </span>
              </div>
            </div>

            {/* Dropdown — zeigt Partition-Label, Filesystem und Event-Anzahl */}
            <div className="relative">
              <button
                onClick={() => setPartitionDropdownOpen(prev => !prev)}
                className="flex items-center gap-2 px-3 py-2 rounded-lg bg-white/[0.05] hover:bg-white/[0.08] transition-all text-sm text-white/70 border border-white/[0.06]"
              >
                <Layers size={13} className="text-accent-blue" />
                <span>
                  {selectedPartition === 'all'
                    ? `Alle (${allTimeline.length} Events)`
                    : `${selectedPartition} · ${selectedInfo?.filesystem || '?'} · ${selectedInfo?.count ?? 0} Events`
                  }
                </span>
                {/* Pfeil dreht sich bei geöffnetem Dropdown */}
                <ChevronDown
                  size={12}
                  className={`text-white/30 transition-transform ${partitionDropdownOpen ? 'rotate-180' : ''}`}
                />
              </button>

              {/* Dropdown-Menü — absolute positioniert unterhalb des Buttons */}
              {partitionDropdownOpen && (
                <div
                  className="absolute right-0 top-full mt-1 w-72 rounded-xl bg-[#0d0d0d] border border-white/[0.08] shadow-2xl z-20 overflow-hidden"
                  onBlur={() => setPartitionDropdownOpen(false)}
                >
                  {/* Alle Partitionen Option */}
                  <button
                    onClick={() => { setSelectedPartition('all'); setPartitionDropdownOpen(false) }}
                    className={`w-full flex items-center gap-3 px-4 py-3 hover:bg-white/[0.04] transition-colors text-left ${selectedPartition === 'all' ? 'bg-accent-blue/10' : ''}`}
                  >
                    <Layers size={13} className="text-accent-blue flex-shrink-0" />
                    <div>
                      <span className="text-sm text-white/70">Alle Partitionen</span>
                      <span className="text-xs text-white/30 block">{allTimeline.length} Events gesamt</span>
                    </div>
                  </button>

                  <div className="border-t border-white/[0.04]" />

                  {/* Einzelne Partitionen — eine Zeile pro erkannter Partition */}
                  {partitions.map(p => (
                    <button
                      key={p.label}
                      onClick={() => { setSelectedPartition(p.label); setPartitionDropdownOpen(false) }}
                      className={`w-full flex items-center gap-3 px-4 py-3 hover:bg-white/[0.04] transition-colors text-left ${selectedPartition === p.label ? 'bg-accent-blue/10' : ''}`}
                    >
                      <HardDrive size={13} className="text-white/30 flex-shrink-0" />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-sm font-mono text-white/70 truncate">{p.label}</span>
                          <span className="text-xs bg-white/[0.05] px-1.5 py-0.5 rounded-full text-white/30 flex-shrink-0">
                            {p.count} Events
                          </span>
                        </div>
                        <span className="text-xs text-accent-cyan">{p.filesystem}</span>
                      </div>
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Partition-Info-Chips — schnelle Toggle-Chips unterhalb des Dropdowns */}
          <div className="flex flex-wrap gap-2 mt-3 pt-3 border-t border-white/[0.04]">
            {partitions.map(p => (
              <button
                key={p.label}
                onClick={() => setSelectedPartition(p.label === selectedPartition ? 'all' : p.label)}
                className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs transition-all border ${
                  selectedPartition === p.label
                    ? 'bg-accent-blue/15 text-accent-blue border-accent-blue/30'
                    : 'bg-white/[0.03] text-white/40 border-white/[0.05] hover:bg-white/[0.06] hover:text-white/60'
                }`}
              >
                <HardDrive size={10} />
                <span className="font-mono">{p.label}</span>
                <span className="text-[9px] opacity-60">({p.filesystem})</span>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* ── Charts Row — Timeline (2/3 Breite) + Taxonomie (1/3 Breite) ── */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <div className="xl:col-span-2">
          <TimelineChart
            timeline={timeline}
            anomalies={filteredAnomalies}
          />
        </div>
        <div>
          <ArtifactTaxonomy timeline={timeline} />
        </div>
      </div>

      {/* ── Event Table — volle Breite, mit aktivem Partition-Label ── */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-medium text-white/50">Event-Timeline</h3>
          {/* Zeigt aktuell gewählte Partition als Kontext-Badge */}
          {hasMultiplePartitions && selectedPartition !== 'all' && (
            <span className="text-xs text-accent-blue font-mono bg-accent-blue/10 px-2 py-1 rounded-lg">
              {selectedPartition} · {selectedInfo?.filesystem}
            </span>
          )}
        </div>
        <EventTable timeline={timeline} />
      </div>

    </div>
  )
}
