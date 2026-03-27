"""
================================================================================
PIPELINE — Zentrale 10-Stufen-Analyse-Pipeline
================================================================================
Dieses Modul ist das Herzstück des Systems. Es orchestriert die vollständige
forensische Analyse von einem Eingabe-Artefakt (Disk-Image, Log-Datei,
UAC-Dump) bis hin zu strukturierten Ausgabedateien.

Aufgaben:
    - Eingabe-Typ erkennen (Disk-Image, Logs, UAC-Dump, RAM-Dump)
    - UAC-Artefakte laden (falls vorhanden)
    - Text-Logs parsen (syslog, audit, journal, apache, ...)
    - Artefakte via Dissect extrahieren (MFT, Registry, Dienste, ...)
    - Filesystem-Timeline via Sleuth Kit erstellen (Multi-Partition)
    - Alle Events auf ein einheitliches Schema normalisieren
    - System-Profil (OS, Kernel, Benutzer) automatisch erstellen
    - Anti-Forensics-Hinweise erkennen (Timestomping, Log-Lücken, ...)
    - Anomalien via IsolationForest (ML) erkennen
    - MITRE ATT&CK Taktiken und Techniken zuordnen
    - Daten für LLM-Analyse vorfiltern und IOCs extrahieren
    - Alle Ergebnisse als JSON/CSV in das Output-Verzeichnis exportieren

Verwendung:
    # Als CLI:
    python backend/pipeline.py /pfad/zum/image.dd --output_dir output/

    # Als Python-Funktion (z.B. aus der API):
    from pipeline import run_pipeline
    result = run_pipeline("/pfad/zum/image.dd", "output/job_123")

Abhängigkeiten:
    - subprocess, json, struct, pandas, pathlib, click, logging (stdlib/PyPI)
    - dissect.target (optional) — Artefakt-Extraktion und Filesystem-Timeline
    - pytsk3 (optional) — Sleuth Kit Bindings für Multi-Partition-Analyse
    - python-magic (optional) — MIME-Type-Erkennung

Kontext: LFX Forensic Analysis System — Bachelor-Arbeit Forensik-Tool
"""

import subprocess
import json
import struct
import pandas as pd
from pathlib import Path
import click
import logging
from datetime import datetime

# ── Optionale Abhängigkeiten ───────────────────────────────────────────────────
# Die Pipeline läuft auch ohne diese Tools, überspringt dann aber die
# entsprechenden Analyse-Phasen (Graceful Degradation).
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
    """
    Verfolgt die einzelnen Analyse-Phasen mit Zeitstempeln.

    Gibt zu Beginn und Ende jeder Phase eine Log-Meldung mit der absoluten
    Laufzeit seit Pipeline-Start (T+Xs) und der Phasen-Dauer aus.
    Ermöglicht so eine schnelle Identifikation von Performance-Engpässen.

    Verwendung:
        tracker = PhaseTracker()
        tracker.start_phase("ANOMALY_DETECTION")
        # ... Analyse ...
        tracker.end_phase("ANOMALY_DETECTION")
    """
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
# getattr(..., None) verhindert AttributeError bei älteren pytsk3-Versionen
def _build_fs_type_names():
    if not HAS_TSK:
        return {}
    mapping = [
        ('TSK_FS_TYPE_EXT2',    'ext2'),
        ('TSK_FS_TYPE_EXT3',    'ext3'),
        ('TSK_FS_TYPE_EXT4',    'ext4'),
        ('TSK_FS_TYPE_XFS',     'xfs'),
        ('TSK_FS_TYPE_BTRFS',   'btrfs'),
        ('TSK_FS_TYPE_NTFS',    'ntfs'),
        ('TSK_FS_TYPE_FAT12',   'fat12'),
        ('TSK_FS_TYPE_FAT16',   'fat16'),
        ('TSK_FS_TYPE_FAT32',   'fat32'),
        ('TSK_FS_TYPE_EXFAT',   'exfat'),
        ('TSK_FS_TYPE_HFS',     'hfs'),
        ('TSK_FS_TYPE_HFS_DETECT', 'hfs+'),
        ('TSK_FS_TYPE_ISO9660', 'iso9660'),
        ('TSK_FS_TYPE_UFS',     'ufs'),
        ('TSK_FS_TYPE_APFS',    'apfs'),
    ]
    result = {}
    for attr, name in mapping:
        val = getattr(pytsk3, attr, None)
        if val is not None:
            result[val] = name
    return result

_FS_TYPE_NAMES = _build_fs_type_names()


def _get_fs_type_name(ftype) -> str:
    """Gibt den lesbaren Namen eines Dateisystem-Typs zurück."""
    return _FS_TYPE_NAMES.get(ftype, f'unbekannt({ftype})')


def _walk_filesystem(fs, root_path: str, events: list, partition_label: str, max_depth: int = 12):
    """
    Traversiert rekursiv ein via pytsk3 geöffnetes Dateisystem.

    Extrahiert für jede Datei und jedes Verzeichnis alle verfügbaren
    Metadaten (Timestamps, Größe, Typ, UID/GID, Mode) und hängt sie
    als Dictionary an die `events`-Liste an.

    Args:
        fs:               pytsk3.FS_Info Objekt (geöffnetes Dateisystem)
        root_path:        Startpfad für den Walk, typischerweise '/'
        events:           Ausgabe-Liste — neue Events werden hier angehängt
        partition_label:  Lesbarer Bezeichner der Partition (z.B. 'Part1_ntfs')
        max_depth:        Maximale Rekursionstiefe — verhindert endlose
                          Symlink-Schleifen oder extrem tiefe Verzeichnisbäume
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

    Args:
        input_path: Pfad zum Disk-Image
        output_dir: Ausgabeverzeichnis — sleuth_timeline.csv wird hier erstellt

    Returns:
        Liste aller extrahierten Datei-Events (jedes Event = ein dict)
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
    Führt die vollständige 10-stufige forensische Analyse-Pipeline aus.

    Diese Funktion ist der zentrale Einstiegspunkt für alle Analysen — sowohl
    beim CLI-Aufruf als auch beim Aufruf aus der FastAPI (BackgroundTasks).
    Jede Phase ist in try/except gekapselt, sodass ein Fehler in einer Phase
    nicht die gesamte Pipeline abbricht (Graceful Degradation).

    Pipeline-Stufen:
        0. File Detection       → Input-Typ erkennen
        1. UAC Runner           → UAC-Artefakte (nur für Dumps/RAM)
        2. Log-Parser           → Text-basierte Logs (syslog, audit, journal, ...)
        3. Dissect Parser       → Artefakte extrahieren (MFT, EventLogs, Registry)
        4. Sleuth Kit           → Multi-Partition Filesystem-Timeline
        5. Data Normalization   → Einheitliches Schema
        5b. System Profiling    → OS, Kernel, Hostname, Benutzer, Dienste aus Artefakten
        5c. Anti-Forensics      → Timestomping, Log-Lücken, Wipe-Tool-Spuren erkennen
        6. Anomaly Detection    → ML-basierte Anomalieerkennung (Isolation Forest)
        7. MITRE ATT&CK Mapping → Taktiken + Techniken zuordnen
        8. AI Preprocessing     → Top-1000 Events filtern, IOCs extrahieren
        9. LLM Agent            → KI-Analyse (on-demand via Frontend, hier übersprungen)
       10. Export               → report.md, timeline.csv, analysis_summary.json

    Args:
        input_path: Pfad zur zu analysierenden Datei oder zum Verzeichnis
                    (str oder pathlib.Path)
        output_dir: Ziel-Verzeichnis für alle Ausgabedateien
                    (str oder pathlib.Path, wird bei Bedarf erstellt)

    Returns:
        combined (dict): Normalisiertes Ergebnis-Dict mit Schlüsseln:
            - 'artifacts': Liste normalisierter Artefakte
            - 'timeline': Liste normalisierter Timeline-Events (mit Anomalie-Scores)
            - 'system_profile': Automatisch erkanntes System-Profil
            - 'antiforensics': Anti-Forensics-Befunde
            - 'metadata': Input-Typ, Timestamps, Zählungen, Partitions-Summary
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

    # ── 1. UAC-Artefakte einlesen ──────────────────────────────────────────
    # UAC ist ein Live-Collection-Tool (nicht Teil dieser Pipeline).
    # Das System liest Artefakte ein, die UAC bereits gesammelt hat.
    # Erwartet: Verzeichnis mit bodyfile.txt und/oder artifacts/-Unterordnern.
    if input_type == 'uac_dump':
        tracker.start_phase("UAC_PROCESSING")
        uac_artifacts = load_uac_artifacts(input_path)
        if uac_artifacts:
            artifacts.extend(uac_artifacts)
            logger.info(f"✓ UAC-Artefakte geladen: {len(uac_artifacts)} Eintraege aus {input_path.name}")
        else:
            logger.warning("⚠ UAC-Verzeichnis erkannt, aber keine Artefakte gefunden. "
                           "Erwartet: bodyfile.txt oder artifacts/-Verzeichnis.")
        tracker.end_phase("UAC_PROCESSING")
    else:
        logger.info("⊘ UAC-Verarbeitung uebersprungen (Eingabe ist kein UAC-Dump-Verzeichnis).")

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
            # Quelldatei-Referenz in alle Log-Events eintragen (für Fundstellen-Nachweis).
            # Da der Normalizer alle Felder außer 'mtime/timestamp/event_id' in 'metadata'
            # überführt, landet 'source_file' automatisch in metadata.source_file.
            for e in log_events:
                e['source_file'] = input_path.name
            logger.info(
                f"✓ Log-Parser: {len(log_events)} Events extrahiert "
                f"(Format: {log_parser.format_detected})"
            )
        except Exception as e:
            logger.error(f"✗ Log-Parser-Fehler: {e}")
        tracker.end_phase("LOG_PARSING")

    # ── 3. Dissect Parser + Timeline-Erzeugung ────────────────────────────
    # Dissect wird bevorzugt fuer:
    #   a) Artefakt-Extraktion (mft, users, services, runkeys)
    #   b) Bodyfile-kompatible Filesystem-Timeline (bevorzugt vor TSK)
    #      → Dissect unterstuetzt XFS, Btrfs, ext4, NTFS nativ
    dissect_timeline_events = 0
    if input_type in ['disk_image', 'logs', 'evtx', 'unknown'] and HAS_DISSECT:
        tracker.start_phase("DISSECT_PARSING")
        try:
            target = Target(str(input_path))

            # a) Artefakt-Extraktion (Linux-Fokus: kein evtx/registry)
            for plugin_name in ['mft', 'users', 'services', 'runkeys']:
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

            # b) Filesystem-Timeline via Dissect (Bodyfile-Format)
            if input_type == 'disk_image':
                dissect_events = _generate_dissect_timeline(target, input_path)
                if dissect_events:
                    timeline.extend(dissect_events)
                    dissect_timeline_events = len(dissect_events)
                    logger.info(
                        f"✓ Dissect-Timeline: {dissect_timeline_events} Datei-Events erzeugt "
                        f"(bevorzugt, TSK wird uebersprungen)"
                    )

            dissect_file = output_dir / 'dissect_artifacts.json'
            with open(dissect_file, 'w', encoding='utf-8') as f:
                json.dump(artifacts, f, indent=2, default=str)
            logger.info(f"✓ Dissect-Artefakte: {len(artifacts)} → {dissect_file.name}")
        except Exception as e:
            logger.error(f"✗ Dissect-Fehler: {e} – Fallback zu Sleuth Kit.")
        tracker.end_phase("DISSECT_PARSING")
    elif not HAS_DISSECT and input_type in ['disk_image', 'logs', 'evtx', 'unknown']:
        logger.warning("⊘ dissect.target nicht installiert. Dissect-Phase uebersprungen.")

    # ── 4. Sleuth Kit Analyzer (Multi-Partition) — Fallback ───────────────
    # TSK wird nur eingesetzt wenn Dissect keine Timeline erzeugt hat.
    # Gruende: Dissect nicht verfuegbar, Dateisystem nicht unterstuetzt,
    #          oder Dissect-Timeline-Erzeugung fehlgeschlagen (0 Events).
    if input_type == 'disk_image' and dissect_timeline_events == 0 and HAS_TSK:
        tracker.start_phase("SLEUTH_KIT_ANALYSIS")
        logger.info("Dissect-Timeline leer — verwende Sleuth Kit als Fallback fuer Timeline.")
        sleuth_events = _analyze_disk_image_multipartition(input_path, output_dir)
        timeline.extend(sleuth_events)
        tracker.end_phase("SLEUTH_KIT_ANALYSIS")
    elif input_type == 'disk_image' and dissect_timeline_events == 0 and not HAS_TSK:
        logger.warning("⊘ Weder Dissect-Timeline noch pytsk3 verfuegbar. "
                       "Disk-Image-Timeline konnte nicht erzeugt werden.")

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

        # Asservat-Namen in alle normalisierten Events eintragen.
        # Ermöglicht jedem Event zu wissen aus welchem Image/Logfile es stammt —
        # Pflicht für gerichtsverwertbare Fundstellen-Dokumentation (ISO 27037).
        for e in normalized_timeline:
            e.setdefault('metadata', {})['evidence_file'] = input_path.name

        normalized_artifacts = normalizer.normalize_artifacts({
            'dissect':    [a for a in artifacts if a.get('source') == 'dissect'],
            'sleuthkit':  [a for a in artifacts if a.get('source') == 'sleuthkit'],
            'uac':        [a for a in artifacts if a.get('source') == 'uac'],
        })

        combined = {
            'artifacts':       normalized_artifacts,
            'timeline':        normalized_timeline,
            'system_profile':  {},
            'antiforensics':   {},
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
        # Fallback: Rohdaten ohne Normalisierung weiterverwenden
        combined = {
            'artifacts':      artifacts,
            'timeline':       timeline,
            'system_profile': {},
            'antiforensics':  {},
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

    # ── 5b. System-Profiling ───────────────────────────────────────────────
    # Erstellt ein automatisches Systemprofil (OS, Kernel, Hostname, Benutzer,
    # Dienste, Netzwerk) aus der normalisierten Timeline und den Artefakten.
    # Laeuft vor der Anomalie-Erkennung, damit nachfolgende Schritte den
    # Systemkontext kennen.
    tracker.start_phase("SYSTEM_PROFILING")
    system_profile = {}
    try:
        from modules.system_profiler import SystemProfiler
        profiler = SystemProfiler()
        system_profile = profiler.build_profile(normalized_timeline, artifacts)

        profile_file = output_dir / 'system_profile.json'
        with open(profile_file, 'w', encoding='utf-8') as f:
            json.dump(system_profile, f, indent=2, ensure_ascii=False, default=str)

        logger.info(
            f"✓ System-Profil: OS={system_profile.get('os_type', 'unbekannt')}, "
            f"Distro={system_profile.get('distribution') or '-'}, "
            f"Kernel={system_profile.get('kernel') or '-'}, "
            f"Nutzer={len(system_profile.get('users', []))}, "
            f"Confidence={system_profile.get('confidence', 'low')} "
            f"→ {profile_file.name}"
        )
        combined['system_profile'] = system_profile
    except Exception as e:
        logger.error(f"✗ System-Profiling-Fehler: {e}")
    tracker.end_phase("SYSTEM_PROFILING")

    # ── 5c. Anti-Forensics-Checks ─────────────────────────────────────────
    # Prueft die Timeline auf Hinweise, dass ein Angreifer versucht hat,
    # Spuren zu verwischen: Timestomping, Log-Luecken, Wipe-Tools,
    # Systemzeit-Manipulation, Rootkit-Indikatoren, etc.
    tracker.start_phase("ANTI_FORENSICS_CHECK")
    antiforensics_result = {}
    try:
        from modules.antiforensics_checker import AntiForensicsChecker
        checker = AntiForensicsChecker()
        antiforensics_result = checker.check(
            normalized_timeline, artifacts, system_profile
        )

        af_file = output_dir / 'antiforensics_report.json'
        with open(af_file, 'w', encoding='utf-8') as f:
            json.dump(antiforensics_result, f, indent=2, ensure_ascii=False, default=str)

        findings_count = antiforensics_result.get('findings_count', 0)
        risk_level = antiforensics_result.get('risk_level', 'none')
        logger.info(
            f"✓ Anti-Forensics: {findings_count} Hinweise, "
            f"Risiko={antiforensics_result.get('risk_score', 0)}/100 ({risk_level}) "
            f"→ {af_file.name}"
        )
        combined['antiforensics'] = antiforensics_result
    except Exception as e:
        logger.error(f"✗ Anti-Forensics-Check-Fehler: {e}")
    tracker.end_phase("ANTI_FORENSICS_CHECK")

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

    # Platzhalter-Dateien anlegen, damit das Frontend keine 404-Fehler bekommt
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

        # Zusammenfassung aller Analyse-Ergebnisse für das Frontend-Dashboard
        summary = {
            'analysis_timestamp':  datetime.now().isoformat(),
            'input_file':          str(input_path),
            'input_type':          input_type,
            'total_events':        len(normalized_timeline),
            'anomalies_found':     sum(1 for e in normalized_timeline if e.get('is_anomaly', False)),
            'iocs_identified':     len(key_indicators.get('ips', [])) + len(key_indicators.get('domains', [])),
            'partitions_analyzed': len(_get_partition_summary(normalized_timeline)),
            'output_files':        [f.name for f in output_dir.iterdir() if f.is_file()],
            # System-Profil-Zusammenfassung (aus 5b. System-Profiling)
            'system_profile': {
                'os_type':      system_profile.get('os_type', 'unknown'),
                'distribution': system_profile.get('distribution'),
                'kernel':       system_profile.get('kernel'),
                'hostname':     system_profile.get('hostname'),
                'users':        system_profile.get('users', [])[:5],
                'confidence':   system_profile.get('confidence', 'low'),
                'indicators':   system_profile.get('indicators', []),
            } if system_profile else {},
            # Anti-Forensics-Zusammenfassung (aus 5c. Anti-Forensics-Checks)
            'antiforensics': {
                'findings_count': antiforensics_result.get('findings_count', 0),
                'risk_score':     antiforensics_result.get('risk_score', 0),
                'risk_level':     antiforensics_result.get('risk_level', 'none'),
                'summary':        antiforensics_result.get('summary', ''),
                'categories':     list({
                    f['category'] for f in antiforensics_result.get('findings', [])
                }),
            } if antiforensics_result else {},
        }

        summary_file = output_dir / 'analysis_summary.json'
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, default=str)
        logger.info(f"✓ Analysis-Summary erstellt → {summary_file.name}")

        # Fundstellen-Nachweis generieren (provenance.json)
        # Läuft nach allen anderen Exports, damit anomalies_detected.json vollständig ist.
        try:
            from modules.provenance_enricher import ProvenanceEnricher
            ProvenanceEnricher.build(output_dir)
        except Exception as prov_err:
            logger.warning(f"⚠ Provenance-Enricher fehlgeschlagen: {prov_err}")

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
    Erstellt eine kompakte Zusammenfassung der in der Timeline vorhandenen
    Partitionen — wird in analysis_summary.json gespeichert und vom
    Frontend-Dashboard für die Partitions-Übersicht verwendet.

    Args:
        timeline: Liste normalisierter Timeline-Events

    Returns:
        Liste von Dicts, je Partition: {'label', 'filesystem', 'count'}
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
    """
    Erkennt den Eingabe-Typ einer forensischen Datei.

    Prüft in dieser Reihenfolge: Dateiendung → MIME-Typ → Verzeichnisstruktur.
    Bei unbekannten Dateien wird 'logs' als sichererer Fallback zurückgegeben,
    da der Log-Parser die meisten Text-Formate verarbeiten kann.

    Args:
        path: Pfad zur zu analysierenden Datei oder zum Verzeichnis

    Returns:
        Typ-String: 'disk_image' | 'evtx' | 'audit_log' | 'journal_log' |
                    'logs' | 'archive' | 'uac_dump' | 'unknown'
    """
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


def _generate_dissect_timeline(target, input_path: Path, max_events: int = 500_000) -> list:
    """
    Erzeugt eine Bodyfile-kompatible Datei-Timeline via Dissect.

    Dissect wird als bevorzugter Timeline-Erzeuger eingesetzt, da es:
    - XFS, Btrfs, ext2/3/4, NTFS nativ und zuverlaessig lesen kann
    - Partitionsstruktur (MBR/GPT) automatisch erkennt
    - Kein externes pytsk3 benoetigt

    Args:
        target:     Geöffnetes dissect.target.Target-Objekt
        input_path: Ursprünglicher Image-Pfad (nur für Logging)
        max_events: Maximale Anzahl Events (Schutz vor Memory-Überlauf
                    bei sehr großen Images)

    Returns:
        Liste von normalisierten Timeline-Events (Bodyfile-Format als dict)
        oder leere Liste bei Fehler
    """
    from datetime import timezone as tz_utc

    events = []
    fs_type = 'unknown'

    try:
        # Dateisystem-Typ aus Dissect ermitteln (fuer Annotation)
        if hasattr(target, '_fs'):
            fs_type = type(target._fs).__name__.lower()
        elif hasattr(target, 'volumes'):
            fs_type = 'multi_partition'

        # Filesystem-Walk via Dissect
        walked = 0
        skipped = 0
        for entry in target.fs.scandir('/'):
            if len(events) >= max_events:
                logger.warning(
                    f"Dissect-Timeline: Limit von {max_events} Events erreicht. "
                    f"Weitere Dateien uebersprungen."
                )
                break
            try:
                _walk_dissect_entry(target, entry, events, fs_type, depth=0)
                walked += 1
            except Exception:
                skipped += 1
                continue

        logger.info(
            f"Dissect-Timeline: {len(events)} Events, "
            f"{walked} Verzeichnisse traversiert, {skipped} uebersprungen"
        )
    except AttributeError:
        # target.fs nicht verfuegbar — stille Rueckgabe, TSK uebernimmt
        logger.debug("Dissect: target.fs nicht verfuegbar, Timeline-Erzeugung uebersprungen.")
    except Exception as e:
        logger.warning(f"Dissect-Timeline-Fehler: {e}")

    return events


def _walk_dissect_entry(target, entry, events: list, fs_type: str,
                        depth: int, max_depth: int = 12) -> None:
    """
    Rekursiver Walk eines einzelnen Dissect-Filesystem-Eintrags.

    Liest Metadaten (Timestamps, Größe, Inode, Rechte) aus und hängt
    ein normalisiertes Event an die `events`-Liste an. Bei Verzeichnissen
    wird rekursiv in Unterverzeichnisse abgestiegen.

    Args:
        target:    Dissect Target-Objekt (wird weitergereicht, nicht direkt genutzt)
        entry:     Aktueller Filesystem-Eintrag (Dissect DirEntry)
        events:    Ausgabe-Liste für extrahierte Events
        fs_type:   Dateisystem-Typ als String (z.B. 'ext4', 'ntfs')
        depth:     Aktuelle Rekursionstiefe
        max_depth: Maximale Tiefe — verhindert Endlos-Rekursion bei Symlinks
    """
    if depth > max_depth:
        return

    try:
        path_str = str(entry.path) if hasattr(entry, 'path') else str(entry)
        stat = entry.stat() if hasattr(entry, 'stat') else None
        if stat is None:
            return

        from datetime import datetime, timezone

        def _ts(epoch):
            """Konvertiert Unix-Timestamp in ISO-8601-String (UTC)."""
            if not epoch:
                return None
            try:
                return datetime.fromtimestamp(float(epoch), tz=timezone.utc).isoformat()
            except Exception:
                return None

        mtime_ts = _ts(getattr(stat, 'st_mtime', None))
        if not mtime_ts:
            return  # Kein valider Timestamp → ueberspringen

        events.append({
            'timestamp':   mtime_ts,
            'event_type':  'file_access',
            'source':      'dissect_timeline',
            'path':        path_str,
            'size':        getattr(stat, 'st_size', 0) or 0,
            'mtime':       _ts(getattr(stat, 'st_mtime', None)),
            'atime':       _ts(getattr(stat, 'st_atime', None)),
            'ctime':       _ts(getattr(stat, 'st_ctime', None)),
            'inode':       getattr(stat, 'st_ino', None),
            'mode':        getattr(stat, 'st_mode', None),
            'uid':         getattr(stat, 'st_uid', None),
            'gid':         getattr(stat, 'st_gid', None),
            'fs_type':     fs_type,
            'message':     f"Datei: {path_str} ({getattr(stat, 'st_size', 0)} Bytes)",
        })

        # Rekursiv in Verzeichnisse absteigen
        if hasattr(entry, 'is_dir') and entry.is_dir():
            try:
                for child in entry.scandir():
                    _walk_dissect_entry(target, child, events, fs_type, depth + 1, max_depth)
            except Exception:
                pass
    except Exception:
        pass


def load_uac_artifacts(dump_dir: Path) -> list:
    """
    Laedt UAC-Artefakte aus einem UAC-Dump-Verzeichnis.

    UAC (Unix Artifact Collector) erzeugt beim Live-Collection eine
    Verzeichnisstruktur mit verschiedenen Artefakt-Typen. Diese Funktion
    liest die relevantesten davon ein.

    Unterstuetzt:
    - bodyfile.txt      — Datei-Timeline im Bodyfile-Format (pipe-separated)
    - artifacts/        — UAC-Unterordner mit CSV/JSON-Artefakten
    - live_response/    — UAC Live-Response-Daten (Logs, Configs)

    Args:
        dump_dir: Pfad zum UAC-Dump-Verzeichnis (Wurzelverzeichnis des Dumps)

    Returns:
        Liste aller geladenen Artefakte als Dicts.
        Leere Liste wenn keine erkannten Artefakt-Formate gefunden wurden.
    """
    artifacts = []

    # ── 1. Bodyfile (Datei-Timeline) ──────────────────────────────────────
    bodyfile_path = dump_dir / 'bodyfile.txt'
    if not bodyfile_path.exists():
        # UAC speichert Bodyfile manchmal in Unterverzeichnissen
        candidates = list(dump_dir.rglob('bodyfile.txt'))
        if candidates:
            bodyfile_path = candidates[0]

    if bodyfile_path.exists():
        try:
            df = pd.read_csv(
                bodyfile_path, sep='|',
                names=['md5', 'name', 'inode', 'mode', 'uid', 'gid',
                       'size', 'atime', 'mtime', 'ctime', 'crtime'],
                on_bad_lines='skip',
            )
            body_artifacts = df.to_dict('records')
            for art in body_artifacts:
                art['source'] = 'uac_bodyfile'
            artifacts.extend(body_artifacts)
            logger.info(f"✓ UAC Bodyfile: {len(body_artifacts)} Eintraege aus {bodyfile_path.name}")
        except Exception as e:
            logger.error(f"✗ UAC Bodyfile-Fehler: {e}")

    # ── 2. Artefakt-CSV/JSON aus artifacts/-Verzeichnis ───────────────────
    artifacts_dir = dump_dir / 'artifacts'
    if artifacts_dir.is_dir():
        for csv_file in artifacts_dir.rglob('*.csv'):
            try:
                df = pd.read_csv(csv_file, on_bad_lines='skip')
                for record in df.to_dict('records'):
                    record['source'] = f'uac_artifacts/{csv_file.stem}'
                    artifacts.append(record)
            except Exception as e:
                logger.debug(f"UAC CSV '{csv_file.name}' nicht parsebar: {e}")

    if not artifacts:
        logger.warning(f"UAC-Dump '{dump_dir.name}': Keine Artefakte gefunden "
                       f"(kein bodyfile.txt, kein artifacts/-Verzeichnis).")
    return artifacts


# ============================================================================
# CLI-Wrapper (für Kommandozeilen-Nutzung)
# ============================================================================
@click.command()
@click.argument('input_path', type=click.Path(exists=True, path_type=Path))
@click.option('--output_dir', default='output', type=click.Path(path_type=Path))
def cli(input_path: Path, output_dir: Path):
    """
    CLI-Einstiegspunkt für die Forensik-Pipeline.

    Ermöglicht direkten Aufruf ohne API-Server:
        python backend/pipeline.py /pfad/zum/image.dd --output_dir output/
    """
    run_pipeline(input_path, output_dir)


if __name__ == '__main__':
    cli()
