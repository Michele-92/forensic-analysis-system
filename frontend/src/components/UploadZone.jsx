import React, { useState, useRef } from 'react'
import { useApp } from '../context/AppContext'
import MultiUploadModal from './MultiUploadModal'
import { FileUp, AlertCircle } from 'lucide-react'

const ALLOWED_EXTENSIONS = [
  '.dd', '.raw', '.img', '.e01', '.ewf', '.vdi', '.vmdk',
  '.mem', '.dmp', '.dump',
  '.log', '.txt', '.syslog', '.evtx',
  '.pcap', '.pcapng',
  '.zip', '.tar', '.gz',
]

export default function UploadZone() {
  const { submitFile, createCase, addJobToCase } = useApp()
  const [isDragging, setIsDragging] = useState(false)
  const [error, setError] = useState(null)
  const [uploading, setUploading] = useState(false)
  const [pendingFiles, setPendingFiles] = useState(null)
  const fileRef = useRef(null)

  // Einzelne Datei direkt hochladen (wie bisher)
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

  // Mehrere Dateien hochladen (mit optionaler Case-Erstellung)
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
        const newCase = createCase({
          case_name: caseInfo.case_name,
          case_number: caseInfo.case_number || '',
        })
        for (const jobId of jobIds) {
          addJobToCase(newCase.case_id, jobId)
        }
      }
    } catch (err) {
      setError(err.message)
    } finally {
      setUploading(false)
      setPendingFiles(null)
    }
  }

  // Files verarbeiten — 1 Datei: direkt, mehrere: Modal
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

  const onDrop = (e) => {
    e.preventDefault()
    setIsDragging(false)
    handleFiles(e.dataTransfer.files)
  }

  return (
    <div className="p-3">
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
        <input
          ref={fileRef}
          type="file"
          className="hidden"
          accept={ALLOWED_EXTENSIONS.join(',')}
          multiple
          onChange={(e) => {
            handleFiles(e.target.files)
            e.target.value = ''
          }}
        />

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

      {error && (
        <div className="flex items-center gap-2 mt-2 p-2 rounded-lg bg-risk-critical/10 text-risk-critical text-xs">
          <AlertCircle size={14} />
          {error}
        </div>
      )}

      {/* Multi-Upload Modal */}
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
