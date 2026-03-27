/**
 * ============================================================================
 * FORMATTERS — Anzeigeformatierungen für forensische Daten
 * ============================================================================
 * Reine Hilfsfunktionen (pure functions) zur Formatierung von Rohdaten
 * aus der Analyse-Pipeline in für Menschen lesbare Zeichenketten.
 *
 * Alle Funktionen sind fehlertolerant:
 *   - null/undefined-Eingaben geben '—' (Gedankenstrich) oder '' zurück
 *   - Ungültige Datumswerte geben den Original-String zurück
 *   - Randwerte (0, null bei Zahlen) werden korrekt behandelt
 *
 * Exportierte Funktionen:
 *   - formatTimestamp(ts)   → Vollständiges Datum + Uhrzeit (de-DE, Sekunden-genau)
 *   - formatTime(ts)        → Nur Uhrzeit HH:MM:SS (de-DE)
 *   - formatDate(ts)        → Nur Datum TT.MM.JJJJ (de-DE)
 *   - formatFileSize(bytes) → Lesbare Dateigröße (B/KB/MB/GB/TB)
 *   - formatScore(score)    → Anomalie-Score als Prozentwert (z. B. "73%")
 *   - formatDuration(ms)    → Analysedauer (ms/s/min)
 *   - truncate(str, len)    → Text kürzen mit "…"-Suffix
 *
 * Locale: Alle Datums-/Uhrzeitausgaben verwenden 'de-DE' (DD.MM.YYYY, HH:MM:SS).
 *
 * @module utils/formatters
 */

// ── Datum & Uhrzeit ───────────────────────────────────────────────────────────

/**
 * Formatiert einen Zeitstempel als vollständiges deutsches Datum mit Uhrzeit.
 *
 * Ausgabeformat: "TT.MM.JJJJ, HH:MM:SS" (de-DE Locale)
 * Beispiel: "15.03.2024, 14:32:07"
 *
 * @param {string|number|Date|null} ts - Zeitstempel (ISO-String, Unix-Timestamp oder Date-Objekt)
 * @returns {string} Formatiertes Datum+Uhrzeit oder '—' bei null/undefined oder den Original-String bei ungültigem Datum
 */
export function formatTimestamp(ts) {
  if (!ts) return '—'
  const d = new Date(ts)
  if (isNaN(d.getTime())) return ts
  return d.toLocaleString('de-DE', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

/**
 * Formatiert einen Zeitstempel als reine Uhrzeitangabe.
 *
 * Ausgabeformat: "HH:MM:SS" (de-DE Locale)
 * Beispiel: "14:32:07"
 *
 * Nützlich für die Zeitachse im Temporal Anomaly Engine Chart,
 * wo Platz für vollständige Datumsstempel fehlt.
 *
 * @param {string|number|Date|null} ts - Zeitstempel
 * @returns {string} Formatierte Uhrzeit oder '—' bei null/undefined
 */
export function formatTime(ts) {
  if (!ts) return '—'
  const d = new Date(ts)
  if (isNaN(d.getTime())) return ts
  return d.toLocaleTimeString('de-DE', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

/**
 * Formatiert einen Zeitstempel als reines Datum ohne Uhrzeit.
 *
 * Ausgabeformat: "TT.MM.JJJJ" (de-DE Locale)
 * Beispiel: "15.03.2024"
 *
 * @param {string|number|Date|null} ts - Zeitstempel
 * @returns {string} Formatiertes Datum oder '—' bei null/undefined
 */
export function formatDate(ts) {
  if (!ts) return '—'
  const d = new Date(ts)
  if (isNaN(d.getTime())) return ts
  return d.toLocaleDateString('de-DE')
}

// ── Zahlen & Größen ───────────────────────────────────────────────────────────

/**
 * Formatiert eine Byte-Anzahl als lesbare Dateigröße mit passender Einheit.
 *
 * Wählt automatisch die passende Einheit (B, KB, MB, GB, TB) und rundet
 * auf eine Dezimalstelle. Sonderfälle: null und 0 ergeben "0 B".
 *
 * Beispiele:
 *   0           → "0 B"
 *   1023        → "1023.0 B"
 *   1024        → "1.0 KB"
 *   1572864     → "1.5 MB"
 *   2147483648  → "2.0 GB"
 *
 * @param {number|null} bytes - Dateigröße in Bytes
 * @returns {string} Lesbare Dateigröße mit Einheit
 */
export function formatFileSize(bytes) {
  if (bytes == null || bytes === 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(1024))
  return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${units[i]}`
}

/**
 * Formatiert einen normalisierten Anomalie-Score als Prozentwert.
 *
 * Erwartet einen Wert zwischen 0.0 und 1.0 (IsolationForest-Output).
 * Gibt ganzzahligen Prozentwert zurück (keine Dezimalstellen).
 *
 * Beispiele:
 *   0.73 → "73%"
 *   1.0  → "100%"
 *   0    → "0%"
 *   null → "—"
 *
 * @param {number|null} score - Normierter Score (0.0–1.0)
 * @returns {string} Prozentwert als String oder '—' bei null/undefined
 */
export function formatScore(score) {
  if (score == null) return '—'
  return (score * 100).toFixed(0) + '%'
}

/**
 * Formatiert eine Zeitdauer in Millisekunden als lesbare Zeitangabe.
 *
 * Wählt automatisch die passende Einheit:
 *   < 1000 ms → "Xms"          (z. B. "450ms")
 *   < 60000 ms → "X.Xs"        (z. B. "3.2s")
 *   >= 60000 ms → "Xm Xs"      (z. B. "2m 15s")
 *
 * Nützlich für die Anzeige von Pipeline-Laufzeiten in der Analyse-Übersicht.
 *
 * @param {number} ms - Dauer in Millisekunden
 * @returns {string} Formatierte Zeitangabe
 */
export function formatDuration(ms) {
  if (ms < 1000) return `${ms}ms`
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`
  return `${Math.floor(ms / 60000)}m ${Math.floor((ms % 60000) / 1000)}s`
}

// ── Text-Hilfsfunktionen ──────────────────────────────────────────────────────

/**
 * Kürzt einen Text auf eine maximale Länge und fügt "…" an.
 *
 * Gibt einen leeren String zurück wenn der Eingabewert falsy ist.
 * Texte die kürzer oder gleich `len` sind, werden unverändert zurückgegeben.
 *
 * Nützlich für lange Dateipfade, URLs oder Beschreibungen in der Event-Tabelle.
 *
 * @param {string|null|undefined} str - Der zu kürzende Text
 * @param {number} [len=80] - Maximale Zeichenanzahl vor dem Kürzen
 * @returns {string} Gekürzter Text mit "…" oder Original-String
 *
 * @example
 * truncate('/var/log/auth.log', 15)  // → "/var/log/auth.l..."
 * truncate('kurz', 80)              // → "kurz"
 * truncate(null)                    // → ""
 */
export function truncate(str, len = 80) {
  if (!str) return ''
  return str.length > len ? str.slice(0, len) + '...' : str
}
