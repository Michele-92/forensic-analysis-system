/**
 * ============================================================================
 * useLocalStorage — Persistenter React-State via localStorage
 * ============================================================================
 * Ersatz für useState mit automatischer Persistenz im Browser-localStorage.
 * Der State überlebt Seitenneuladen und Browser-Neustarts.
 *
 * Verhalten:
 *   - Initialisierung: Beim ersten Render wird der gespeicherte Wert aus
 *     localStorage gelesen und als Startwert verwendet. Ist kein Wert
 *     gespeichert, wird initialValue genutzt.
 *   - Synchronisierung: Jede State-Änderung wird automatisch in localStorage
 *     geschrieben (via useEffect).
 *   - Fehlertoleranz: JSON-Parse-Fehler beim Lesen und QuotaExceeded-Fehler
 *     beim Schreiben werden still ignoriert; der Hook fällt auf initialValue
 *     zurück bzw. überspringt das Schreiben.
 *
 * Einsatz im Projekt:
 *   AppContext verwendet diesen Hook für:
 *   - 'lfx-jobs'            → Liste aller Analyse-Jobs
 *   - 'lfx-active-job'      → ID des aktuell angezeigten Jobs
 *   - 'lfx-active-view'     → Aktiver Tab (overview/analytics/intelligence)
 *   - 'lfx-active-case'     → ID des aktiven Cases
 *   - 'lfx-correlation-view'→ Aktive Korrelationsansicht
 *
 * API-Kompatibilität:
 *   Identisch zu useState: gibt [value, setValue] zurück.
 *   setValue kann sowohl direkt (setValue(newVal)) als auch
 *   funktional (setValue(prev => ...)) aufgerufen werden.
 *
 * @module hooks/useLocalStorage
 */

import { useState, useEffect } from 'react'

// ── Hook-Definition ───────────────────────────────────────────────────────────

/**
 * React-State-Hook mit automatischer localStorage-Persistenz.
 *
 * @template T
 * @param {string} key - localStorage-Schlüssel unter dem der Wert gespeichert wird
 * @param {T} initialValue - Startwert, wenn noch kein Wert im localStorage vorhanden ist
 * @returns {[T, function(T|function(T): T): void]} Tupel aus aktuellem Wert und Setter-Funktion
 *
 * @example
 * // Einfacher Wert
 * const [activeJobId, setActiveJobId] = useLocalStorage('lfx-active-job', null)
 *
 * @example
 * // Array mit Objekten
 * const [jobs, setJobs] = useLocalStorage('lfx-jobs', [])
 */
export function useLocalStorage(key, initialValue) {
  // Lazy Initializer: liest localStorage nur beim ersten Render (nicht bei jedem Re-Render)
  const [value, setValue] = useState(() => {
    try {
      const stored = localStorage.getItem(key)
      return stored ? JSON.parse(stored) : initialValue
    } catch {
      // JSON.parse-Fehler (z. B. korrupte Daten) → Fallback auf initialValue
      return initialValue
    }
  })

  // Synchronisiert State-Änderungen zurück in localStorage
  useEffect(() => {
    try {
      localStorage.setItem(key, JSON.stringify(value))
    } catch {
      // quota exceeded or private browsing
    }
  }, [key, value])

  return [value, setValue]
}
