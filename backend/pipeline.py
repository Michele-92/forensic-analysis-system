import subprocess
import json
import struct
import pandas as pd
from pathlib import Path
import click
import logging
from datetime import datetime

# Optionale Imports — Pipeline läuft auch ohne diese Tools
try:
    from dissect.target import Target
    HAS_DISSECT = True
except ImportError:
    HAS_DISSECT = False

try:
    import pytsk3
    HAS_TSK = True
except ImportError:
    HAS_TSK = False

try:
    import magic
    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False

# ============================================================================
# Logging-Setup
# ============================================================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s.%(msecs)03d | %(levelname)-8s | %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)


class PhaseTracker:
    """Verfolgt Phasen der Analyse mit Zeitstempeln."""
    def __init__(self):
        self.phases = {}
        self.start_time = datetime.now()

    def start_phase(self, phase_name: str):
        self.phases[phase_name] = {'start': datetime.now(), 'end': None}
        elapsed = (datetime.now() - self.start_time).total_seconds()
        logger.info(f"[PHASE START] {phase_name} (T+{elapsed:.1f}s)")

    def end_phase(self, phase_name: str):
        if phase_name in self.phases:
            self.phases[phase_name]['end'] = datetime.now()
            duration = (self.phases[phase_name]['end'] - self.phases[phase_name]['start']).total_seconds()
            elapsed = (datetime.now() - self.start_time).total_seconds()
            logger.info(f"[PHASE END  ] {phase_name} - Dauer: {duration:.1f}s (T+{elapsed:.1f}s)")


# ============================================================================
# Sleuth Kit Hilfsfunktionen (Multi-Partition)
# ============================================================================

# Mapping pytsk3 Dateisystem-Typen → Lesbare Namen
_FS_TYPE_NAMES = {
    pytsk3.TSK_FS_TYPE_EXT2: 'ext2',
    pytsk3.TSK_FS_TYPE_EXT3: 'ext3',
    pytsk3.TSK_FS_TYPE_EXT4: 'ext4',
    pytsk3.TSK_FS_TYPE_XFS: 'xfs',
    pytsk3.TSK_FS_TYPE_BTRFS: 'btrfs',
    pytsk3.TSK_FS_TYPE_NTFS: 'ntfs',
    pytsk3.TSK_FS_TYPE_FAT12: 'fat12',
    pytsk3.TSK_FS_TYPE_FAT16: 'fat16',
    pytsk3.TSK_FS_TYPE_FAT32: 'fat32',
    pytsk3.TSK_FS_TYPE_EXFAT: 'exfat',
    pytsk3.TSK_FS_TYPE_HFS: 'hfs',
    pytsk3.TSK_FS_TYPE_HFS_DETECT: 'hfs+',
    pytsk3.TSK_FS_TYPE_ISO9660: 'iso9660',
    pytsk3.TSK_FS_TYPE_UFS: 'ufs',
    pytsk3.TSK_FS_TYPE_APFS: 'apfs',
} if HAS_TSK else {}


def _get_fs_type_name(ftype) -> str:
    """Gibt den lesbaren Namen eines Dateisystem-Typs zurück."""
    return _FS_TYPE_NAMES.get(ftype, f'unbekannt({ftype})')


def _walk_filesystem(fs, root_path: str, events: list, partition_label: str, max_depth: int = 12):
    """
    Rekursives Traversieren eines Dateisystems.
    Extrahiert Metadaten (Timestamps, Größe, Typ) aller Dateien.

    Args:
        fs:               pytsk3.FS_Info Objekt
        root_path:        Startpfad (z.B. '/')
        events:           Liste zum Anhängen neuer Events
        partition_label:  Bezeichnung der Partition (z.B. 'Part1')
        max_depth:        Maximale Rekursionstiefe (verhindert endlose Symlink-Schleifen)
    """
    def _recurse(directory, path: str, depth: int):
        if depth > max_depth:
            return
        for file_entry in directory:
            try:
                raw_name = file_entry.info.name.name
                if raw_name in [b'.', b'..']:
                    continue
                fname = raw_name.decode('utf-8', errors='replace')
                full_path = path + fname

                stat = file_entry.info
                if stat.meta is None:
                    continue

                is_dir = stat.meta.type == pytsk3.TSK_FS_META_TYPE_DIR
                fs_type = _get_fs_type_name(fs.info.ftype)

                events.append({
                    'inode':       stat.meta.addr,
                    'name':        full_path,
                    'mtime':       stat.meta.mtime,
                    'atime':       stat.meta.atime,
                    'ctime':       stat.meta.ctime,
                    'crtime':      getattr(stat.meta, 'crtime', None),
                    'size':        stat.meta.size,
                    'type':        'dir' if is_dir else 'file',
                    'uid':         stat.meta.uid,
                    'gid':         stat.meta.gid,
                    'mode':        stat.meta.mode,
                    'source':      'sleuthkit',
                    'partition':   partition_label,
                    'filesystem':  fs_type,
                })

                if is_dir:
                    try:
                        sub_dir = fs.open_dir(full_path)
                        _recurse(sub_dir, full_path + '/', depth + 1)
                    except (OSError, RuntimeError):
                        pass
            except Exception as e:
                logger.debug(f"Fehler bei Datei in {path}: {e}")

    try:
        root_dir = fs.open_dir(root_path)
        _recurse(root_dir, root_path, 0)
    except Exception as e:
        logger.error(f"Fehler beim Öffnen von '{root_path}': {e}")


def _analyze_disk_image_multipartition(input_path: Path, output_dir: Path) -> list:
    """
    Analysiert ein Disk-Image mit vollständiger Multi-Partition-Unterstützung.

    Ablauf:
    1. Versuche Partitionstabelle (MBR/GPT) zu lesen via TSK_VS_Info
    2. Iteriere alle allokierten Partitionen
    3. Versuche auf jeder Partition ein Dateisystem zu öffnen (ext2-4, XFS, NTFS, ...)
    4. Falls kein Volume System → direkt als einzelnes Dateisystem mounten
    5. Aggregiere alle Events mit Partitions-Label

    Unterstützte Image-Formate:
    - Raw (.dd, .img, .raw) via pytsk3.Img_Info
    - E01/EWF via pytsk3 (libewf-Backend falls kompiliert)
    - VMDK, VDI, QCOW2 via Dissect (wird separat behandelt)
    """
    if not HAS_TSK:
        logger.warning("pytsk3 nicht installiert → Sleuth Kit-Analyse übersprungen.")
        return []

    all_events = []

    try:
        img_info = pytsk3.Img_Info(str(input_path))
        logger.info(f"Image geöffnet: {input_path.name}")
    except Exception as e:
        logger.error(f"Image konnte nicht geöffnet werden: {e}")
        return []

    try:
        # ── Versuch 1: Partitionstabelle lesen (MBR oder GPT) ─────────────
        vs_info = pytsk3.TSK_VS_Info(img_info)
        block_size = vs_info.block_size
        part_count = vs_info.part_count
        logger.info(f"✓ Partitionstabelle erkannt: {part_count} Einträge, Block-Größe: {block_size} Bytes")

        analyzed_partitions = 0
        for part in vs_info:
            # Nur allokierte Partitionen analysieren (keine Unallocated/Extended)
            if part.flags != pytsk3.TSK_VS_PART_FLAG_ALLOC:
                logger.debug(f"  Partition {part.addr}: übersprungen (flags={part.flags})")
                continue

            try:
                desc = part.desc.decode('utf-8', errors='replace').strip()
            except Exception:
                desc = f"Partition {part.addr}"

            byte_offset = part.start * block_size
            logger.info(f"  Partition {part.addr}: '{desc}' | Offset={byte_offset} Bytes | Sektoren={part.len}")

            try:
                fs = pytsk3.FS_Info(img_info, offset=byte_offset)
                fs_type = _get_fs_type_name(fs.info.ftype)
                partition_label = f"Part{part.addr}_{fs_type}"
                logger.info(f"    ✓ Dateisystem: {fs_type}")

                partition_events = []
                _walk_filesystem(fs, '/', partition_events, partition_label)
                all_events.extend(partition_events)
                analyzed_partitions += 1
                logger.info(f"    → {len(partition_events)} Einträge extrahiert")

            except Exception as fs_err:
                logger.debug(f"    ⊘ Kein Dateisystem auf Partition {part.addr}: {fs_err}")

        if analyzed_partitions == 0:
            logger.warning("⚠ Keine analysierbaren Partitionen gefunden.")

    except Exception as vs_err:
        # ── Fallback: Direktes Dateisystem-Mount (kein Partitions-Layer) ──
        logger.info(f"Kein Volume System ({vs_err}) → versuche direktes Dateisystem-Mount.")
        try:
            fs = pytsk3.FS_Info(img_info)
            fs_type = _get_fs_type_name(fs.info.ftype)
            logger.info(f"✓ Direktes Dateisystem erkannt: {fs_type}")
            _walk_filesystem(fs, '/', all_events, f'Part0_{fs_type}')
        except Exception as direct_err:
            logger.error(f"✗ Kein Dateisystem mountbar: {direct_err}")

    # Sleuth Kit Ergebnisse speichern (Zwischendatei)
    sleuth_file = output_dir / 'sleuth_timeline.csv'
    if all_events:
        pd.DataFrame(all_events).to_csv(sleuth_file, index=False)
        logger.info(f"✓ Sleuth Kit: {len(all_events)} Einträge gespeichert → {sleuth_file.name}")
    else:
        logger.warning("⚠ Sleuth Kit: Keine Einträge extrahiert.")

    return all_events


# ============================================================================
# Haupt-Pipeline — als reguläre Funktion (aufrufbar von API und CLI)
# ============================================================================
def run_pipeline(input_path, output_dir):
    """
    9-stufige Analyse-Pipeline.

    0. File Detection       → Input-Typ erkennen
    1. UAC Runner           → UAC-Artefakte (nur für Dumps/RAM)
    2. Log-Parser           → Text-basierte Logs (syslog, audit, journal, ...)
    3. Dissect Parser       → Artefakte extrahieren (MFT, EventLogs, Registry)
    4. Sleuth Kit           → Multi-Partition Filesystem-Timeline
    5. Data Normalization   → Einheitliches Schema
    6. Anomaly Detection    → ML-basierte Anomalieerkennung (Isolation Forest)
    7. MITRE ATT&CK Mapping → Taktiken + Techniken zuordnen
    8. AI Preprocessing     → Top-1000 Events filtern, IOCs extrahieren
    9. LLM Agent            → KI-Analyse (on-demand via Frontend)
   10. Export               → report.md, timeline.csv, summary
    """
    input_path = Path(input_path)
    output_dir = Path(output_dir)
    output_dir.mkdir(exist_ok=True, parents=True)
    tracker = PhaseTracker()

    # ── 0. File Detection ──────────────────────────────────────────────────
    tracker.start_phase("FILE_DETECTION")
    input_type = detect_input_type(input_path)
    logger.info(f"✓ Input-Typ erkannt: {input_type} (Datei: {input_path.name})")
    tracker.end_phase("FILE_DETECTION")

    artifacts = []
    timeline = []

    # ── 1. UAC Runner ──────────────────────────────────────────────────────
    if input_type in ['uac_dump', 'logs', 'ram_dump']:
        tracker.start_phase("UAC_PROCESSING")
        try:
            uac_cmd = ['./uac', '-p', 'ir_triage', str(input_path), str(output_dir / 'uac_dump')]
            subprocess.run(uac_cmd, check=True, capture_output=True)
            logger.info("✓ UAC-Dump verarbeitet.")
            artifacts.extend(load_uac_artifacts(output_dir / 'uac_dump'))
        except FileNotFoundError:
            logger.warning("⚠ UAC-Tool nicht gefunden. Übersprungen.")
        except Exception as e:
            logger.error(f"✗ UAC-Fehler: {e}")
        tracker.end_phase("UAC_PROCESSING")
    else:
        logger.info("⊘ UAC übersprungen (nicht für diesen Typ geeignet).")

    # ── 2. Log-Parser (Text-basierte Logs) ────────────────────────────────
    # Wird für alle Log-Typen + unbekannte Dateien versucht.
    # Der LogParser erkennt das Format selbst (syslog, audit, apache, journal, ...)
    if input_type in ['logs', 'evtx', 'unknown', 'audit_log', 'journal_log']:
        tracker.start_phase("LOG_PARSING")
        try:
            from modules.log_parser import LogParser
            log_parser = LogParser()
            log_events = log_parser.parse_file(input_path)
            timeline.extend(log_events)
            logger.info(
                f"✓ Log-Parser: {len(log_events)} Events extrahiert "
                f"(Format: {log_parser.format_detected})"
            )
        except Exception as e:
            logger.error(f"✗ Log-Parser-Fehler: {e}")
        tracker.end_phase("LOG_PARSING")

    # ── 3. Dissect Parser ──────────────────────────────────────────────────
    # Für Disk-Images, EVTX und komplexe Artefakt-Extraktion
    if input_type in ['disk_image', 'logs', 'evtx', 'unknown'] and HAS_DISSECT:
        tracker.start_phase("DISSECT_PARSING")
        try:
            target = Target(str(input_path))

            for plugin_name in ['mft', 'evtx', 'registry', 'users', 'services', 'runkeys']:
                try:
                    plugin_func = getattr(target, plugin_name, None)
                    if plugin_func is None:
                        continue
                    for record in plugin_func():
                        artifacts.append({
                            'path':    str(getattr(record, 'path', '')),
                            'mtime':   str(getattr(record, 'mtime', '')) or None,
                            'hash':    getattr(record, 'sha256', None),
                            'source':  'dissect',
                            'plugin':  plugin_name,
                        })
                except Exception as plugin_err:
                    logger.debug(f"Dissect-Plugin '{plugin_name}' fehlgeschlagen: {plugin_err}")

            dissect_file = output_dir / 'dissect_artifacts.json'
            with open(dissect_file, 'w', encoding='utf-8') as f:
                json.dump(artifacts, f, indent=2, default=str)
            logger.info(f"✓ Dissect: {len(artifacts)} Artefakte extrahiert → {dissect_file.name}")
        except Exception as e:
            logger.error(f"✗ Dissect-Fehler: {e} – Fallback zu Sleuth Kit.")
        tracker.end_phase("DISSECT_PARSING")
    elif not HAS_DISSECT and input_type in ['disk_image', 'logs', 'evtx', 'unknown']:
        logger.warning("⊘ dissect.target nicht installiert. Dissect-Phase übersprungen.")

    # ── 4. Sleuth Kit Analyzer (Multi-Partition) ──────────────────────────
    # Vollständige Partitionstabellen-Analyse: MBR/GPT → alle Dateisysteme
    # Unterstützt: ext2/3/4, XFS, btrfs, NTFS, FAT, exFAT, HFS+
    if input_type == 'disk_image' and HAS_TSK:
        tracker.start_phase("SLEUTH_KIT_ANALYSIS")
        sleuth_events = _analyze_disk_image_multipartition(input_path, output_dir)
        timeline.extend(sleuth_events)
        tracker.end_phase("SLEUTH_KIT_ANALYSIS")
    elif input_type == 'disk_image' and not HAS_TSK:
        logger.warning("⊘ pytsk3 nicht installiert. Sleuth-Kit-Phase übersprungen.")

    # ── 5. Data Normalization ──────────────────────────────────────────────
    tracker.start_phase("DATA_NORMALIZATION")
    normalized_timeline = []
    key_indicators = {'ips': [], 'domains': [], 'users': [], 'processes': [], 'files': []}

    try:
        from modules.normalizer import DataNormalizer
        normalizer = DataNormalizer()

        for event in timeline:
            source = event.get('source', 'unknown')
            normalized_event = normalizer.normalize_timeline_event(event, source)
            normalized_timeline.append(normalized_event)

        normalized_artifacts = normalizer.normalize_artifacts({
            'dissect':    [a for a in artifacts if a.get('source') == 'dissect'],
            'sleuthkit':  [a for a in artifacts if a.get('source') == 'sleuthkit'],
            'uac':        [a for a in artifacts if a.get('source') == 'uac'],
        })

        combined = {
            'artifacts': normalized_artifacts,
            'timeline':  normalized_timeline,
            'metadata': {
                'input_type':      input_type,
                'input':           str(input_path),
                'timestamp':       datetime.now().isoformat(),
                'artifact_count':  len(normalized_artifacts),
                'timeline_count':  len(normalized_timeline),
                # Partition-Informationen für Frontend
                'partitions': _get_partition_summary(normalized_timeline),
            },
        }

        normalized_file = output_dir / 'normalized_output.json'
        with open(normalized_file, 'w', encoding='utf-8') as f:
            json.dump(combined, f, indent=2, default=str)
        logger.info(
            f"✓ Normalisierung: {len(normalized_timeline)} Events standardisiert "
            f"→ {normalized_file.name}"
        )
    except Exception as e:
        logger.error(f"✗ Normalisierungs-Fehler: {e}")
        combined = {
            'artifacts': artifacts,
            'timeline':  timeline,
            'metadata': {
                'input_type':     input_type,
                'input':          str(input_path),
                'timestamp':      datetime.now().isoformat(),
                'artifact_count': len(artifacts),
                'timeline_count': len(timeline),
                'partitions':     [],
            },
        }
        normalized_timeline = timeline
    tracker.end_phase("DATA_NORMALIZATION")

    # ── 6. Anomaly Detection ───────────────────────────────────────────────
    tracker.start_phase("ANOMALY_DETECTION")
    try:
        from modules.anomaly_detector import AnomalyDetector
        anomaly_detector = AnomalyDetector(contamination=0.1)
        timeline_with_scores = anomaly_detector.fit_detect(normalized_timeline)

        anomaly_count = sum(1 for e in timeline_with_scores if e.get('is_anomaly', False))
        logger.info(
            f"✓ Anomalieerkennung: {anomaly_count} Anomalien in "
            f"{len(timeline_with_scores)} Events gefunden"
        )

        anomaly_file = output_dir / 'anomalies_detected.json'
        anomalies = [e for e in timeline_with_scores if e.get('is_anomaly', False)]
        with open(anomaly_file, 'w', encoding='utf-8') as f:
            json.dump(anomalies, f, indent=2, default=str)
        logger.info(f"  → {len(anomalies)} anomale Events gespeichert → {anomaly_file.name}")

        normalized_timeline = timeline_with_scores
    except Exception as e:
        logger.error(f"✗ Anomalieerkennung-Fehler: {e}")
        anomaly_file = output_dir / 'anomalies_detected.json'
        with open(anomaly_file, 'w') as f:
            json.dump([], f)
    tracker.end_phase("ANOMALY_DETECTION")

    # ── 7. MITRE ATT&CK Mapping ───────────────────────────────────────────
    tracker.start_phase("MITRE_MAPPING")
    try:
        from modules.mitre_mapper import MitreMapper
        mapper = MitreMapper()
        mapper.enrich_timeline(normalized_timeline)
        anomalies_with_mitre = [e for e in normalized_timeline if e.get('is_anomaly', False)]
        tactic_summary = mapper.get_tactic_summary(anomalies_with_mitre)
        if tactic_summary:
            logger.info(f"✓ MITRE Taktiken: {tactic_summary}")

        # Anomalie-Datei mit MITRE-Daten aktualisieren
        anomaly_file = output_dir / 'anomalies_detected.json'
        with open(anomaly_file, 'w', encoding='utf-8') as f:
            json.dump(anomalies_with_mitre, f, indent=2, default=str)
        logger.info(f"  → Anomalien mit MITRE-Mapping aktualisiert → {anomaly_file.name}")
    except Exception as e:
        logger.error(f"✗ MITRE-Mapping-Fehler: {e}")
    tracker.end_phase("MITRE_MAPPING")

    # ── 8. AI Preprocessing ───────────────────────────────────────────────
    tracker.start_phase("AI_PREPROCESSING")
    filtered_timeline = normalized_timeline
    try:
        from modules.ai_preprocessor import AIPreprocessor
        preprocessor = AIPreprocessor()

        filtered_timeline = preprocessor.prepare_timeline_for_llm(
            normalized_timeline,
            max_events=1000,
            focus='suspicious',
        )

        key_indicators = preprocessor.extract_key_indicators(filtered_timeline)
        logger.info(f"✓ AI Preprocessing: {len(filtered_timeline)} verdächtige Events gefiltert")
        logger.info(
            f"  IPs: {len(key_indicators.get('ips', []))}, "
            f"Domains: {len(key_indicators.get('domains', []))}"
        )

        preprocessed_file = output_dir / 'preprocessed_for_llm.json'
        with open(preprocessed_file, 'w', encoding='utf-8') as f:
            json.dump({'timeline': filtered_timeline, 'indicators': key_indicators}, f, indent=2, default=str)
        logger.info(f"  → Preprocessing-Daten gespeichert → {preprocessed_file.name}")
    except Exception as e:
        logger.error(f"✗ AI Preprocessing-Fehler: {e}")
        preprocessed_file = output_dir / 'preprocessed_for_llm.json'
        with open(preprocessed_file, 'w') as f:
            json.dump({'timeline': [], 'indicators': key_indicators}, f, indent=2, default=str)
    tracker.end_phase("AI_PREPROCESSING")

    # ── 9. LLM Agent Analysis (on-demand) ────────────────────────────────
    tracker.start_phase("LLM_AGENT_ANALYSIS")
    # LLM-Analyse wird NICHT in der Pipeline ausgeführt (zu langsam auf CPU).
    # On-Demand via Frontend-Button → POST /agent-analyze/{job_id}
    logger.info("⊘ LLM-Analyse übersprungen (on-demand via Frontend verfügbar).")

    if not (output_dir / 'report.md').exists():
        with open(output_dir / 'report.md', 'w', encoding='utf-8') as f:
            f.write(
                f"# Forensic Analysis Report\n\n"
                f"**Erstellt:** {datetime.now().isoformat()}\n\n"
                f"## Zusammenfassung\n\n"
                f"- Input: {input_path.name}\n"
                f"- Typ: {input_type}\n"
                f"- Events: {len(normalized_timeline)}\n"
                f"- Anomalien: {sum(1 for e in normalized_timeline if e.get('is_anomaly', False))}\n\n"
                f"*LLM-Analyse noch nicht durchgeführt. Im Frontend 'Analyse starten' klicken.*\n"
            )
    if not (output_dir / 'interpretation.json').exists():
        with open(output_dir / 'interpretation.json', 'w') as f:
            json.dump({
                "summary": "LLM-Analyse ausstehend",
                "hypotheses": "",
                "top_findings": "",
                "raw_response": "",
            }, f, indent=2)
    tracker.end_phase("LLM_AGENT_ANALYSIS")

    # ── 10. Export ──────────────────────────────────────────────────────────
    tracker.start_phase("EXPORT_FINALIZATION")
    try:
        if normalized_timeline:
            timeline_csv_file = output_dir / 'timeline.csv'
            df = pd.DataFrame(normalized_timeline)
            df.to_csv(timeline_csv_file, index=False)
            logger.info(f"✓ Timeline-CSV exportiert → {timeline_csv_file.name} ({len(df)} Einträge)")

        summary = {
            'analysis_timestamp':  datetime.now().isoformat(),
            'input_file':          str(input_path),
            'input_type':          input_type,
            'total_events':        len(normalized_timeline),
            'anomalies_found':     sum(1 for e in normalized_timeline if e.get('is_anomaly', False)),
            'iocs_identified':     len(key_indicators.get('ips', [])) + len(key_indicators.get('domains', [])),
            'partitions_analyzed': len(_get_partition_summary(normalized_timeline)),
            'output_files':        [f.name for f in output_dir.iterdir() if f.is_file()],
        }

        summary_file = output_dir / 'analysis_summary.json'
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, default=str)
        logger.info(f"✓ Analysis-Summary erstellt → {summary_file.name}")

    except Exception as e:
        logger.error(f"✗ Export-Fehler: {e}")
    tracker.end_phase("EXPORT_FINALIZATION")

    total_duration = (datetime.now() - tracker.start_time).total_seconds()
    logger.info("=" * 80)
    logger.info("ANALYSE ABGESCHLOSSEN")
    logger.info(f"    Gesamtdauer: {total_duration:.1f}s")
    logger.info(f"    Output-Verzeichnis: {output_dir}")
    logger.info("=" * 80)

    return combined


# ============================================================================
# Hilfsfunktionen
# ============================================================================

def _get_partition_summary(timeline: list) -> list:
    """
    Erstellt eine Zusammenfassung der analysierten Partitionen aus der Timeline.
    Wird in analysis_summary.json gespeichert und vom Frontend ausgelesen.
    """
    partitions = {}
    for event in timeline:
        part = event.get('partition') or event.get('metadata', {}).get('partition')
        if part:
            if part not in partitions:
                partitions[part] = {
                    'label':      part,
                    'filesystem': event.get('filesystem', 'unbekannt'),
                    'count':      0,
                }
            partitions[part]['count'] += 1
    return list(partitions.values())


# ============================================================================
# Input-Typ-Erkennung
# ============================================================================
def detect_input_type(path: Path) -> str:
    """Erkennt den Input-Typ anhand Extension, MIME-Type und Datei-Inhalt."""
    path = Path(path)
    suffix = path.suffix.lower()
    name_lower = path.name.lower()

    mime = ""
    if HAS_MAGIC:
        try:
            mime = magic.from_file(str(path), mime=True)
            logger.debug(f"MIME-Type: {mime}")
        except Exception as e:
            logger.debug(f"MIME-Erkennung fehlgeschlagen: {e}")

    # ── Disk Images ────────────────────────────────────────────────────────
    if suffix in ['.dd', '.raw', '.img', '.e01', '.ex01', '.ewf', '.vdi', '.vmdk',
                  '.vhd', '.vhdx', '.qcow', '.qcow2', '.iso', '.aff', '.afd']:
        return 'disk_image'

    # ── Windows Event Logs (Binärformat) ──────────────────────────────────
    elif suffix in ['.evtx', '.evt']:
        return 'evtx'

    # ── Linux Audit Log ───────────────────────────────────────────────────
    elif 'audit' in name_lower and suffix in ['.log', '.txt', '']:
        return 'audit_log'

    # ── Systemd Journal (JSON-Export) ─────────────────────────────────────
    elif 'journal' in name_lower or suffix == '.journal':
        return 'journal_log'

    # ── Text-basierte Logs ────────────────────────────────────────────────
    elif suffix in ['.log', '.syslog', '.auth', '.txt', '.access', '.error']:
        return 'logs'

    # ── Memory Dumps ──────────────────────────────────────────────────────
    elif suffix in ['.mem', '.dump', '.dmp'] or 'memory' in mime:
        return 'ram_dump'

    # ── Netzwerk-Captures ─────────────────────────────────────────────────
    elif suffix in ['.pcap', '.pcapng']:
        return 'pcap'

    # ── Archive ───────────────────────────────────────────────────────────
    elif suffix in ['.zip', '.tar', '.gz', '.bz2', '.xz']:
        return 'archive'

    # ── UAC-Dump (Verzeichnis) ────────────────────────────────────────────
    elif path.is_dir():
        try:
            if any(f.suffix in ['.yaml', '.json', '.csv'] for f in path.iterdir()):
                return 'uac_dump'
        except PermissionError:
            pass
        return 'unknown'

    else:
        logger.warning(
            f"Unbekannter Typ für {path}. Versuche Log-Parser als Fallback. (Suffix: {suffix})"
        )
        return 'logs'  # Sichererer Fallback als 'unknown'


def load_uac_artifacts(dump_dir: Path) -> list:
    """Lädt UAC-Artefakte aus Bodyfile."""
    artifacts = []
    try:
        bodyfile_path = dump_dir / 'bodyfile.txt'
        if bodyfile_path.exists():
            df = pd.read_csv(
                bodyfile_path, sep='|',
                names=['md5', 'name', 'inode', 'mode', 'uid', 'gid',
                       'size', 'atime', 'mtime', 'ctime', 'crtime']
            )
            artifacts = df.to_dict('records')
            for art in artifacts:
                art['source'] = 'uac'
            logger.info(f"✓ UAC: {len(artifacts)} Artefakte aus Bodyfile geladen.")
    except Exception as e:
        logger.error(f"✗ Fehler beim Laden von UAC-Artefakten: {e}")
    return artifacts


# ============================================================================
# CLI-Wrapper (für Kommandozeilen-Nutzung)
# ============================================================================
@click.command()
@click.argument('input_path', type=click.Path(exists=True, path_type=Path))
@click.option('--output_dir', default='output', type=click.Path(path_type=Path))
def cli(input_path: Path, output_dir: Path):
    """CLI-Wrapper für die Forensik-Pipeline."""
    run_pipeline(input_path, output_dir)


if __name__ == '__main__':
    cli()
