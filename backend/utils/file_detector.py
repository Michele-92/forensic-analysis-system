"""
================================================================================
FILE_DETECTOR — Robuste Dateityp-Erkennung für forensische Eingaben
================================================================================
Dieses Modul bestimmt den Typ einer forensischen Eingabe-Datei oder eines
Verzeichnisses, bevor die eigentliche Analyse-Pipeline gestartet wird.
Die Erkennung kombiniert vier Methoden, um auch bei fehlenden oder falschen
Dateiendungen einen zuverlässigen Typ zu liefern.

Aufgaben:
    - Dateityp aus Dateiendung bestimmen (schnell, erster Check)
    - MIME-Typ über libmagic ermitteln (zuverlässiger als Extension)
    - Magic Bytes (Datei-Signatur) direkt aus dem Binär-Header lesen
    - Verzeichnisstruktur analysieren (UAC-Dump-Erkennung)
    - Alle vier Methoden nach Priorität zusammenführen (Entscheidungslogik)
    - Detaillierte Datei-Metadaten als Dictionary zurückgeben

Verwendung:
    from utils.file_detector import FileTypeDetector, FileType

    detector = FileTypeDetector()
    file_type = detector.detect(Path("evidence.dd"))
    # → FileType.DISK_IMAGE

    info = detector.get_file_info(Path("evidence.dd"))
    # → {'path': ..., 'size': ..., 'type': 'disk_image', 'mime_type': ..., ...}

    # Oder als Legacy-Convenience-Funktion (gibt String zurück):
    from utils.file_detector import detect_input_type
    typ = detect_input_type(Path("dump/"))  # → 'uac_dump'

Abhängigkeiten:
    - logging, pathlib, typing, enum (stdlib)
    - python-magic (libmagic-Bindings) — optionale Abhängigkeit,
      Modul funktioniert ohne python-magic (MIME-Erkennung deaktiviert)

Kontext: LFX Forensic Analysis System — Bachelor-Arbeit Forensik-Tool
"""

import logging
import magic
from pathlib import Path
from typing import Optional, Dict, Any
from enum import Enum

logger = logging.getLogger(__name__)


# ── Typ-Definitionen ──────────────────────────────────────────────────────────

class FileType(str, Enum):
    """
    Enum aller vom System unterstützten forensischen Eingabe-Typen.

    Erbt von str, damit Werte direkt als Strings verglichen und
    in JSON-Responses serialisiert werden können, ohne .value aufzurufen.
    """
    DISK_IMAGE = "disk_image"   # Raw-Image, E01, VMDK, QCOW2, ...
    LOG_FILE = "log_file"       # Syslog, Auth-Log, EVTX, Audit-Log, ...
    UAC_DUMP = "uac_dump"       # UAC-Verzeichnis (bodyfile.txt / artifacts/)
    ARCHIVE = "archive"         # ZIP, TAR, GZ, ...
    UNKNOWN = "unknown"         # Typ konnte nicht bestimmt werden


# ── Haupt-Klasse ─────────────────────────────────────────────────────────────

class FileTypeDetector:
    """
    Erkennt den Typ forensischer Eingabe-Dateien und Verzeichnisse.

    Kombiniert vier Erkennungsmethoden, die in dieser Reihenfolge
    ausgeführt und mit einer Prioritätslogik zusammengeführt werden:
        1. Directory-Struktur-Analyse (für UAC-Dumps)
        2. Dateiendungs-Check
        3. MIME-Typ via libmagic
        4. Magic Bytes (Datei-Signatur direkt im Binär-Header)

    Verwendung:
        detector = FileTypeDetector()
        file_type = detector.detect(Path("forensic.dd"))
        info = detector.get_file_info(Path("forensic.dd"))
    """

    # ── Statische Erkennungs-Tabellen ──────────────────────────────────────

    # Dateiendungen → FileType.DISK_IMAGE
    DISK_IMAGE_EXTENSIONS = {
        '.dd', '.raw', '.img', '.001',  # Raw Disk Images
        '.e01', '.ex01', '.ewf',        # EnCase Evidence Files
        '.aff', '.afd',                 # Advanced Forensic Format
        '.vdi', '.vmdk', '.vhd', '.vhdx',  # Virtual Disk Images
        '.qcow', '.qcow2',              # QEMU Images
        '.iso',                         # ISO Images
    }

    # Dateiendungen → FileType.LOG_FILE
    LOG_FILE_EXTENSIONS = {
        '.log', '.txt', '.syslog',
        '.auth', '.messages',
        '.evtx', '.evt',                # Windows Event Logs
    }

    # Dateiendungen → FileType.ARCHIVE
    ARCHIVE_EXTENSIONS = {
        '.zip', '.tar', '.gz', '.bz2',
        '.7z', '.rar', '.tgz',
    }

    # MIME-Typen → FileType.DISK_IMAGE
    # 'application/octet-stream' ist generisch (unbekannter Binär-Typ) —
    # wird nur als schwaches Signal verwendet (niedrige Priorität)
    DISK_IMAGE_MIMES = {
        'application/x-raw-disk-image',
        'application/octet-stream',  # Generic (kann alles sein)
    }

    # Magic Bytes (Datei-Signaturen) → FileType
    # Werden gegen die ersten 512 Bytes der Datei geprüft.
    MAGIC_BYTES = {
        # EnCase Evidence File
        b'EVF': FileType.DISK_IMAGE,
        # VMware VMDK
        b'# Disk DescriptorFile': FileType.DISK_IMAGE,
    }

    def __init__(self):
        """
        Initialisiert den Detector und prüft ob python-magic verfügbar ist.

        Falls python-magic/libmagic nicht installiert ist, wird die
        MIME-Erkennung automatisch deaktiviert (self.magic_available = False).
        Alle anderen Erkennungsmethoden bleiben weiterhin aktiv.
        """
        try:
            # Test ob python-magic verfügbar ist
            magic.from_buffer(b'test', mime=True)
            self.magic_available = True
        except Exception as e:
            logger.warning(f"python-magic nicht verfügbar: {e}")
            self.magic_available = False

    # ── Hauptmethode ───────────────────────────────────────────────────────

    def detect(self, path: Path) -> FileType:
        """
        Hauptmethode zur Dateityp-Erkennung.

        Führt alle vier Erkennungsmethoden aus und kombiniert deren
        Ergebnisse via _resolve_detection() nach Priorität.

        Args:
            path: Pfad zur zu prüfenden Datei oder zum Verzeichnis

        Returns:
            Erkannter FileType-Enum-Wert.
            FileType.UNKNOWN wenn kein Typ bestimmt werden konnte.
        """
        if not path.exists():
            logger.error(f"Pfad existiert nicht: {path}")
            return FileType.UNKNOWN

        # 1. Directory-Check (UAC-Dumps werden als Verzeichnisse übergeben)
        if path.is_dir():
            return self._detect_directory(path)

        # 2. Extension-Check
        ext_type = self._detect_by_extension(path)
        if ext_type != FileType.UNKNOWN:
            logger.debug(f"Typ via Extension erkannt: {ext_type}")

        # 3. MIME-Type-Check
        mime_type = self._detect_by_mime(path)
        if mime_type != FileType.UNKNOWN:
            logger.debug(f"Typ via MIME erkannt: {mime_type}")

        # 4. Magic-Bytes-Check
        magic_type = self._detect_by_magic_bytes(path)
        if magic_type != FileType.UNKNOWN:
            logger.debug(f"Typ via Magic Bytes erkannt: {magic_type}")

        # 5. Entscheidungslogik (Priorität)
        result = self._resolve_detection(ext_type, mime_type, magic_type, path)

        logger.info(f"Dateityp erkannt: {path.name} -> {result}")
        return result

    # ── Private Erkennungsmethoden ─────────────────────────────────────────

    def _detect_by_extension(self, path: Path) -> FileType:
        """
        Erkennt den Dateityp anhand der Dateiendung.

        Schnellste Methode, aber fehleranfällig wenn Dateien falsch
        benannt wurden (z.B. ein Disk-Image mit .txt-Endung).

        Args:
            path: Pfad zur Datei

        Returns:
            Erkannter FileType oder FileType.UNKNOWN
        """
        suffix = path.suffix.lower()

        if suffix in self.DISK_IMAGE_EXTENSIONS:
            return FileType.DISK_IMAGE
        elif suffix in self.LOG_FILE_EXTENSIONS:
            return FileType.LOG_FILE
        elif suffix in self.ARCHIVE_EXTENSIONS:
            return FileType.ARCHIVE

        return FileType.UNKNOWN

    def _detect_by_mime(self, path: Path) -> FileType:
        """
        Erkennt den Dateityp via MIME-Typ (libmagic).

        Analysiert den Dateiinhalt statt der Endung — daher zuverlässiger
        bei falsch benannten Dateien. Setzt python-magic voraus.

        Args:
            path: Pfad zur Datei

        Returns:
            Erkannter FileType oder FileType.UNKNOWN (auch wenn magic nicht verfügbar)
        """
        if not self.magic_available:
            return FileType.UNKNOWN

        try:
            mime = magic.from_file(str(path), mime=True)
            logger.debug(f"MIME-Type: {mime}")

            if mime in self.DISK_IMAGE_MIMES:
                return FileType.DISK_IMAGE
            elif 'text' in mime:
                return FileType.LOG_FILE
            elif 'compressed' in mime or 'zip' in mime or 'tar' in mime:
                return FileType.ARCHIVE

        except Exception as e:
            logger.debug(f"MIME-Detection fehlgeschlagen: {e}")

        return FileType.UNKNOWN

    def _detect_by_magic_bytes(self, path: Path) -> FileType:
        """
        Erkennt den Dateityp anhand der Datei-Signatur (Magic Bytes).

        Liest die ersten 512 Bytes der Datei und vergleicht sie mit
        bekannten Datei-Signaturen aus MAGIC_BYTES. Diese Methode hat
        die höchste Erkennungszuverlässigkeit und höchste Priorität
        in _resolve_detection().

        Args:
            path: Pfad zur Datei

        Returns:
            Erkannter FileType oder FileType.UNKNOWN
        """
        try:
            with open(path, 'rb') as f:
                header = f.read(512)  # Erste 512 Bytes

            for signature, file_type in self.MAGIC_BYTES.items():
                if header.startswith(signature):
                    return file_type

        except Exception as e:
            logger.debug(f"Magic-Bytes-Detection fehlgeschlagen: {e}")

        return FileType.UNKNOWN

    def _detect_directory(self, path: Path) -> FileType:
        """
        Analysiert die Verzeichnisstruktur zur Typ-Bestimmung.

        UAC-Dumps haben eine charakteristische Struktur mit bekannten
        Dateien/Unterordnern (bodyfile.txt, live_response/, artifacts/).
        Verzeichnisse die nur Log-Dateien enthalten werden als LOG_FILE erkannt.

        Args:
            path: Pfad zum zu analysierenden Verzeichnis

        Returns:
            FileType.UAC_DUMP | FileType.LOG_FILE | FileType.UNKNOWN
        """
        # Charakteristische Dateien/Ordner in UAC-Dump-Verzeichnissen
        uac_indicators = ['bodyfile.txt', 'live_response', 'artifacts']

        try:
            files = [f.name for f in path.iterdir()]

            # Check für UAC-Dump
            if any(indicator in files for indicator in uac_indicators):
                return FileType.UAC_DUMP

            # Check für Log-Sammlung (alle Dateien haben Log-Endungen)
            if all(f.suffix.lower() in self.LOG_FILE_EXTENSIONS for f in path.glob('*') if f.is_file()):
                return FileType.LOG_FILE

        except Exception as e:
            logger.debug(f"Directory-Analysis fehlgeschlagen: {e}")

        return FileType.UNKNOWN

    def _resolve_detection(self,
                          ext_type: FileType,
                          mime_type: FileType,
                          magic_type: FileType,
                          path: Path) -> FileType:
        """
        Kombiniert die Ergebnisse aller vier Erkennungsmethoden nach Priorität.

        Prioritätsreihenfolge (höchste zuerst):
        1. Magic Bytes — höchste Genauigkeit, manipulationssicher
        2. Extension + MIME stimmen überein — starkes kombiniertes Signal
        3. Extension allein — schnell, aber unsicher
        4. MIME allein — ohne Extension-Bestätigung
        5. Heuristik (Dateigröße + Binär-Analyse) — letzter Ausweg

        Args:
            ext_type:   Ergebnis aus _detect_by_extension()
            mime_type:  Ergebnis aus _detect_by_mime()
            magic_type: Ergebnis aus _detect_by_magic_bytes()
            path:       Pfad zur Datei (für Heuristik-Fallback)

        Returns:
            FileType mit der höchsten Konfidenz
        """
        # Magic Bytes haben höchste Priorität
        if magic_type != FileType.UNKNOWN:
            return magic_type

        # Extension + MIME stimmen überein
        if ext_type == mime_type and ext_type != FileType.UNKNOWN:
            return ext_type

        # Extension allein
        if ext_type != FileType.UNKNOWN:
            return ext_type

        # MIME allein
        if mime_type != FileType.UNKNOWN:
            return mime_type

        # Heuristik basierend auf Dateigröße und Binär-Anteil
        try:
            size = path.stat().st_size

            # Sehr große Dateien (>1GB) sind wahrscheinlich Images/Dumps
            if size > 1_000_000_000:
                # Check ob binär
                with open(path, 'rb') as f:
                    sample = f.read(8192)

                # Wenn >50% non-ASCII → wahrscheinlich Binär-Image
                non_ascii = sum(1 for b in sample if b > 127 or b < 32)
                if non_ascii / len(sample) > 0.5:
                    return FileType.DISK_IMAGE

            # Kleine Dateien (<10MB) die als UTF-8 dekodierbar sind → Log-Datei
            elif size < 10_000_000:
                with open(path, 'rb') as f:
                    sample = f.read(1024)

                try:
                    sample.decode('utf-8')
                    return FileType.LOG_FILE
                except:
                    pass

        except Exception as e:
            logger.debug(f"Heuristik fehlgeschlagen: {e}")

        return FileType.UNKNOWN

    # ── Öffentliche Utility-Methode ────────────────────────────────────────

    def get_file_info(self, path: Path) -> Dict[str, Any]:
        """
        Sammelt alle verfügbaren Metadaten einer Datei in einem Dict.

        Kombiniert Typ-Erkennung mit Datei-Metadaten (Größe, MIME-Typ,
        Lesbarkeit). Wird von der API für den /file-info-Endpunkt verwendet.

        Args:
            path: Pfad zur Datei oder zum Verzeichnis

        Returns:
            Dictionary mit: path, name, size, type, extension,
            mime_type (optional), is_readable, is_directory
        """
        info = {
            'path': str(path),
            'name': path.name,
            'size': path.stat().st_size if path.exists() else 0,
            'type': self.detect(path).value,
            'extension': path.suffix.lower(),
        }

        # MIME-Type
        if self.magic_available:
            try:
                info['mime_type'] = magic.from_file(str(path), mime=True)
            except:
                info['mime_type'] = None

        # Ist lesbar?
        info['is_readable'] = path.exists() and path.is_file()

        # Ist Directory?
        info['is_directory'] = path.is_dir()

        return info


# ── Convenience-Funktion (Legacy-Kompatibilität) ──────────────────────────────

def detect_input_type(path: Path) -> str:
    """
    Legacy-Wrapper um FileTypeDetector.detect() der einen String zurückgibt.

    Wird von pipeline.py und anderen Modulen genutzt, die noch den alten
    String-basierten Typ erwarten (vor Einführung des FileType-Enums).
    Für neuen Code wird die direkte Nutzung von FileTypeDetector empfohlen.

    Args:
        path: Pfad zur Datei oder zum Verzeichnis

    Returns:
        Typ als String: 'disk_image' | 'logs' | 'uac_dump' | 'archive' | 'unknown'
    """
    detector = FileTypeDetector()
    file_type = detector.detect(path)

    # Mapping von FileType-Enum auf die in der Pipeline verwendeten String-Werte
    type_mapping = {
        FileType.DISK_IMAGE: 'disk_image',
        FileType.LOG_FILE: 'logs',
        FileType.UAC_DUMP: 'uac_dump',
        FileType.ARCHIVE: 'archive',
        FileType.UNKNOWN: 'unknown',
    }

    return type_mapping.get(file_type, 'unknown')


# ── Direkt-Ausführung (manuelle Tests) ───────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    detector = FileTypeDetector()

    # Test-Pfade (anpassen!)
    test_files = [
        Path("test.dd"),
        Path("test.log"),
        Path("uac_dump/"),
    ]

    for file in test_files:
        if file.exists():
            file_type = detector.detect(file)
            info = detector.get_file_info(file)
            print(f"\n{file}: {file_type}")
            print(f"Info: {info}")
