"""
================================================================================
PROVENANCE ENRICHER — Fundstellen-Nachweis für forensische Anomalien
================================================================================
Erstellt eine strukturierte Fundstellen-Dokumentation (provenance.json) aus
den bereits vorhandenen Analyse-Ergebnissen. Für jede erkannte Anomalie wird
exakt dokumentiert:

    - Aus welchem Asservat (Image-/Log-Datei) der Befund stammt
    - An welcher exakten Stelle im Asservat er gefunden wurde
      (Dateipfad, Inode, Zeilennummer, Partition, Dateisystem)
    - Mit welchem Tool und welcher Methode er extrahiert wurde

Diese Informationen sind gemäß ISO/IEC 27037:2012 und ENFSI Best Practice Manual
(2015) Pflichtbestandteil eines gerichtsverwertbaren forensischen Reports.
Sie ermöglichen es jedem kompetenten Gutachter, jeden Befund 1:1 nachzustellen.

Eingabe (aus output_dir, bereits vorhanden):
    anomalies_detected.json  — Anomalien mit vollständigem metadata-Feld
    analysis_summary.json    — Asservat-Name, Hashes, Analyse-Zeitpunkt

Ausgabe:
    provenance.json          — Pro Anomalie ein strukturierter Fundstellen-Eintrag

Verwendung:
    # Am Ende der Pipeline (Stage 10):
    from modules.provenance_enricher import ProvenanceEnricher
    ProvenanceEnricher.build(output_dir)

    # Ergebnis-Format (eine Zeile pro Anomalie):
    {
      "nr": 1,
      "event_id": "tsk_42",
      "timestamp": "2024-03-05T14:23:15",
      "evidence_file": "Server-Image-2024-03-05.E01",
      "sha256": "e3b0c44298fc...",
      "found_in_file": "/var/log/auth.log",
      "line_number": 42,
      "location_detail": "Partition: Part1_ext4 | Inode: 42",
      "extracted_by": "Sleuth Kit (pytsk3)",
      "anomaly_score": 0.87,
      "description": "Accepted publickey for root from 192.168.1.100"
    }

Abhängigkeiten:
    - json, logging, pathlib (stdlib)

Kontext: LFX Forensic Analysis System — Fundstellen-Dokumentationsschicht
================================================================================
"""

import json
import logging
from pathlib import Path
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


class ProvenanceEnricher:
    """
    Erstellt provenance.json aus bereits vorhandenen Analyse-Output-Dateien.
    Alle Methoden sind statisch — die Klasse hat keinen eigenen Zustand.
    """

    @staticmethod
    def build(output_dir: Path) -> List[Dict]:
        """
        Hauptmethode: Liest Anomalien + Summary und schreibt provenance.json.

        Args:
            output_dir: Pfad zum Job-Output-Verzeichnis (data/outputs/{job_id}/)

        Returns:
            Liste der Provenance-Einträge (auch in provenance.json gespeichert).
            Leere Liste bei Fehler oder fehlenden Eingabedateien.
        """
        output_dir = Path(output_dir)

        # ── Anomalien laden ───────────────────────────────────────────────────
        anomalies_file = output_dir / 'anomalies_detected.json'
        if not anomalies_file.exists():
            logger.warning("⚠ Provenance: anomalies_detected.json nicht gefunden — übersprungen.")
            return []

        raw = json.loads(anomalies_file.read_text(encoding='utf-8'))
        anomalies = raw if isinstance(raw, list) else raw.get('anomalies', [])

        if not anomalies:
            logger.info("⊘ Provenance: Keine Anomalien vorhanden — provenance.json leer.")
            provenance_file = output_dir / 'provenance.json'
            provenance_file.write_text('[]', encoding='utf-8')
            return []

        # ── Analysis-Summary für Asservat-Metadaten laden ─────────────────────
        summary_file = output_dir / 'analysis_summary.json'
        summary: Dict[str, Any] = {}
        if summary_file.exists():
            summary = json.loads(summary_file.read_text(encoding='utf-8'))

        # Asservat-Dateiname aus absolutem Pfad kürzen
        evidence_file = Path(summary.get('input_file', 'Unbekannt')).name
        sha256 = summary.get('sha256_hash', '') or ''
        md5    = summary.get('md5_hash', '')    or ''

        # ── Provenance-Einträge aufbauen ──────────────────────────────────────
        provenance = []
        for i, anomaly in enumerate(anomalies, 1):
            meta   = anomaly.get('metadata', {}) or {}
            source = anomaly.get('source', 'unknown')

            location = _extract_location(meta, source)

            entry = {
                'nr':              i,
                'event_id':        anomaly.get('event_id', f'anomaly_{i}'),
                'timestamp':       anomaly.get('timestamp', ''),
                # Asservat: entweder aus dem Event selbst (wurde in pipeline.py eingetragen)
                # oder aus analysis_summary.json als Fallback
                'evidence_file':   meta.get('evidence_file') or evidence_file,
                # Hashes: gekürzte Darstellung für Lesbarkeit (vollständige Werte in Chain of Custody)
                'sha256_short':    (sha256[:16] + '...') if len(sha256) > 16 else sha256 or 'nicht berechnet',
                'md5_short':       (md5[:16]    + '...') if len(md5)    > 16 else md5    or 'nicht berechnet',
                # Fundstelle
                'found_in_file':   location['file'],
                'line_number':     meta.get('line_number', ''),
                'location_detail': location['detail'],
                'extracted_by':    location['tool'],
                # Befund-Kontext
                'anomaly_score':   round(anomaly.get('anomaly_score', 0), 3),
                'event_type':      anomaly.get('event_type', ''),
                'description':     (anomaly.get('description', '') or '')[:120],
            }
            provenance.append(entry)

        # ── provenance.json schreiben ─────────────────────────────────────────
        provenance_file = output_dir / 'provenance.json'
        provenance_file.write_text(
            json.dumps(provenance, indent=2, ensure_ascii=False, default=str),
            encoding='utf-8',
        )
        logger.info(
            f"✓ Provenance: {len(provenance)} Fundstellen-Einträge dokumentiert "
            f"→ {provenance_file.name}"
        )
        return provenance


# ── Hilfsfunktion (Modul-Ebene, kein Klassenmember) ──────────────────────────

def _extract_location(meta: Dict, source: str) -> Dict[str, str]:
    """
    Extrahiert die präzise Fundstelle aus einem normalisierten Event-Metadata-Dict.

    Berücksichtigt alle Quelltypen des Systems und gibt immer ein vollständiges
    Dict mit 'file', 'detail' und 'tool' zurück — auch bei fehlenden Metadaten.

    Args:
        meta:   metadata-Dict des normalisierten Events (kann leer sein)
        source: Quellbezeichner ('sleuthkit', 'dissect', 'syslog', 'uac', ...)

    Returns:
        {'file': str, 'detail': str, 'tool': str}
    """
    # ── Filesystem-Event (Sleuth Kit / pytsk3) ────────────────────────────────
    if source in ('sleuthkit', 'tsk') or meta.get('filesystem') or meta.get('partition'):
        file_path  = meta.get('name') or meta.get('path') or 'Unbekannt'
        partition  = meta.get('partition', '')
        inode      = meta.get('inode', '')
        fs_type    = meta.get('filesystem', '')
        detail_parts = []
        if partition:
            detail_parts.append(f"Partition: {partition}")
        if inode:
            detail_parts.append(f"Inode: {inode}")
        if fs_type and fs_type not in partition:
            detail_parts.append(f"FS: {fs_type}")
        return {
            'file':   file_path,
            'detail': ' | '.join(detail_parts) or 'Dateisystem-Eintrag',
            'tool':   'Sleuth Kit (pytsk3)',
        }

    # ── Dissect-Artefakt (MFT, Registry, Services, Users) ────────────────────
    if source == 'dissect':
        file_path = meta.get('path') or meta.get('name') or 'Unbekannt'
        plugin    = meta.get('plugin', '')
        return {
            'file':   file_path,
            'detail': f"Dissect-Plugin: {plugin}" if plugin else 'Dissect-Artefakt',
            'tool':   'dissect.target',
        }

    # ── Log-Event (Syslog, Audit, Apache, Firewall, Journal, ...) ────────────
    if source in ('syslog', 'logs', 'webserver', 'audit', 'firewall',
                  'journal', 'apt', 'yum', 'mysql', 'openvpn'):
        source_file = meta.get('source_file', 'Unbekannt')
        line_num    = meta.get('line_number', '')
        hostname    = meta.get('hostname', '')
        detail_parts = []
        if line_num:
            detail_parts.append(f"Zeile: {line_num}")
        if hostname:
            detail_parts.append(f"Host: {hostname}")
        return {
            'file':   source_file,
            'detail': ' | '.join(detail_parts) or 'Text-Log',
            'tool':   'LFX Log-Parser',
        }

    # ── UAC-Dump (Unix Artifact Collector) ────────────────────────────────────
    if source == 'uac':
        return {
            'file':   meta.get('path') or meta.get('source_file', 'UAC-Dump'),
            'detail': f"UAC-Artefakt: {meta.get('artifact_type', '')}".strip(': '),
            'tool':   'UAC (Unix Artifact Collector)',
        }

    # ── Generischer Fallback ──────────────────────────────────────────────────
    file_path = (
        meta.get('name') or meta.get('path') or
        meta.get('source_file') or 'Unbekannt'
    )
    return {
        'file':   file_path,
        'detail': f"Quelle: {source}",
        'tool':   source,
    }
