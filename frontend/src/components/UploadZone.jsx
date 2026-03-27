/**
 * ============================================================================
 * UPLOADZONE — Datei-Upload mit Drag & Drop
 * ============================================================================
 * Interaktiver Upload-Bereich am unteren Rand der Sidebar. Nimmt forensische
 * Dateien per Drag & Drop oder Klick entgegen und startet die Backend-Analyse.
 *
 * Verhalten je nach Dateianzahl:
 *   - 1 Datei  → direkter Upload (kein Modal)
 *   - ≥2 Dateien → öffnet MultiUploadModal zur Konfiguration (Einzeln oder
 *                  als neuer Fall gruppieren)
 *
 * Erlaubte Dateitypen (ALLOWED_EXTENSIONS):
 *   - Disk-Images: .dd, .raw, .img, .e01, .ewf, .vdi, .vmdk, .vhdx, .qcow2, .aff
 *   - Logs:        .log, .txt, .syslog, .evtx
 *   - Archive:     .zip, .tar, .gz
 *
 * Props: keine (liest submitFile, createCase, addJobToCase aus useApp Context)
 *
 * Abhängigkeiten:
 *   - AppContext (useApp): submitFile, createCase, addJobToCase
 *   - MultiUploadModal: Modal für Konfiguration bei mehreren Dateien
 *
 * @component
 */

import React, { useState, useRef } from 'react'
import { useApp } from '../context/AppContext'
import MultiUploadModal from './MultiUploadModal'
import { FileUp, AlertCircle } from 'lucide-react'

// ── Konstanten ─────────────────────────────────────────────────────────────

/**
 * Erlaubte Dateiendungen für das file-Input-Element.
 * Verhindert, dass der Browser-Picker unpassende Dateien anzeigt.
 * Die eigentliche Typ-Erkennung geschieht im Backend (pipeline.py Stage 1).
 */
const ALLOWED_EXTENSIONS = [
  '.dd', '.raw', '.img', '.e01', '.ewf', '.vdi', '.vmdk', '.vhdx', '.qcow2', '.aff',
  '.log', '.txt', '.syslog', '.evtx',
  '.zip', '.tar', '.gz',
]

// ── Hauptkomponente ────────────────────────────────────────────────────────

export default function UploadZone() {
  const { submitFile, createCase, addJobToCase } = useApp()

  // ── Lokaler State ──────────────────────────────────────────────────────

  /** true während ein Drag-Element über der Zone schwebt (visuelles Feedback). */
  const [isDragging, setIsDragging] = useState(false)

  /** Fehlermeldung des letzten Upload-Versuchs, null wenn kein Fehler. */
  const [error, setError] = useState(null)

  /** true während ein oder mehrere Uploads laufen (deaktiviert die Zone). */
  const [uploading, setUploading] = useState(false)

  /**
   * Puffer für mehrere Dateien: wird gesetzt wenn der Nutzer ≥2 Dateien
   * wählt, öffnet das MultiUploadModal. Nach Abschluss wieder null.
   */
  const [pendingFiles, setPendingFiles] = useState(null)

  /** Ref auf das versteckte file-Input-Element für programmatisches Öffnen. */
  const fileRef = useRef(null)

  // ── Upload-Logik ───────────────────────────────────────────────────────

  /**
   * Lädt eine einzelne Datei direkt hoch und startet die Backend-Analyse.
   * Kein Modal, keine weitere Konfiguration nötig.
   *
   * @param {File} file - Die hochzuladende Datei
   */
  const handleSingleFile = async (file) => {
    if (!file) return
    setError(null)
    setUploading(true)
    try {
      await submitFile(file)
    } catch (err) {
      setError(err.message)
    } finally {
      setUploading(false)
    }
  }

  /**
   * Lädt mehrere Dateien sequenziell hoch und ordnet sie optional einem
   * neu erstellten Fall zu. Wird vom MultiUploadModal nach Bestätigung aufgerufen.
   *
   * @param {File[]}      files    - Array der hochzuladenden Dateien
   * @param {Object|null} caseInfo - Fall-Metadaten (case_name, case_number)
   *                                 oder null wenn kein Fall erstellt werden soll
   */
  const handleMultiUpload = async (files, caseInfo) => {
    setError(null)
    setUploading(true)
    try {
      const jobIds = []
      for (const file of files) {
        const job = await submitFile(file)
        jobIds.push(job.job_id)
      }

      // Fall erstellen und alle Jobs zuordnen
      if (caseInfo) {
        const newCase = await createCase({
          case_name: caseInfo.case_name,
          case_number: caseInfo.case_number || '',
        })
        for (const jobId of jobIds) {
          await addJobToCase(newCase.case_id, jobId)
        }
      }
    } catch (err) {
      setError(err.message)
    } finally {
      setUploading(false)
      setPendingFiles(null)
    }
  }

  /**
   * Verzweigt je nach Dateianzahl in Single-Upload oder Multi-Upload-Modal.
   * FileList wird zu einem echten Array kopiert, da FileList eine
   * Live-Referenz zum DOM ist und leer wird sobald input.value='' gesetzt wird.
   *
   * @param {FileList|null} fileList - Dateien aus Drop-Event oder file-Input
   */
  const handleFiles = (fileList) => {
    if (!fileList || fileList.length === 0) return
    // FileList ist eine Live-Referenz zum DOM — wird leer wenn input.value='' gesetzt wird.
    // Deshalb hier in ein echtes Array kopieren.
    const files = Array.from(fileList)
    if (files.length === 1) {
      handleSingleFile(files[0])
    } else {
      setPendingFiles(files)
    }
  }

  /**
   * Drop-Handler: Verhindert Browser-Standard (Datei öffnen) und
   * leitet die abgelegten Dateien an handleFiles weiter.
   */
  const onDrop = (e) => {
    e.preventDefault()
    setIsDragging(false)
    handleFiles(e.dataTransfer.files)
  }

  // ── Render ─────────────────────────────────────────────────────────────

  return (
    <div className="p-3">
      {/* ── Drop-Bereich (klickbar + drag-sensitiv) ──────────────────── */}
      <div
        onDragOver={(e) => { e.preventDefault(); setIsDragging(true) }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={onDrop}
        onClick={() => fileRef.current?.click()}
        className={`
          relative flex flex-col items-center justify-center gap-2 p-4
          border-2 border-dashed rounded-xl cursor-pointer
          transition-all duration-300
          ${isDragging
            ? 'border-accent-blue bg-accent-blue/10'
            : 'border-white/10 hover:border-white/20 hover:bg-white/[0.02]'
          }
          ${uploading ? 'pointer-events-none opacity-60' : ''}
        `}
      >
        {/* Verstecktes file-Input — wird programmatisch durch Klick ausgelöst */}
        <input
          ref={fileRef}
          type="file"
          className="hidden"
          accept={ALLOWED_EXTENSIONS.join(',')}
          multiple
          onChange={(e) => {
            handleFiles(e.target.files)
            // Input zurücksetzen damit dieselbe Datei erneut gewählt werden kann
            e.target.value = ''
          }}
        />

        {/* Inhalt wechselt zwischen Upload-Icon und Lade-Spinner */}
        {uploading ? (
          <>
            <div className="w-6 h-6 border-2 border-accent-blue border-t-transparent rounded-full animate-spin" />
            <span className="text-xs text-white/40">Uploading...</span>
          </>
        ) : (
          <>
            <FileUp size={20} className={isDragging ? 'text-accent-blue' : 'text-white/30'} />
            <span className="text-xs text-white/40 text-center">
              Drop Forensic Image
            </span>
          </>
        )}
      </div>

      {/* ── Fehleranzeige ──────────────────────────────────────────────── */}
      {error && (
        <div className="flex items-center gap-2 mt-2 p-2 rounded-lg bg-risk-critical/10 text-risk-critical text-xs">
          <AlertCircle size={14} />
          {error}
        </div>
      )}

      {/* ── Multi-Upload Modal (erscheint bei ≥2 Dateien) ─────────────── */}
      {pendingFiles && (
        <MultiUploadModal
          files={pendingFiles}
          onUpload={handleMultiUpload}
          onClose={() => setPendingFiles(null)}
        />
      )}
    </div>
  )
}
