"""
File Type Detector.
Robuste Erkennung von Dateitypen für forensische Analyse.
"""

import logging
import magic
from pathlib import Path
from typing import Optional, Dict, Any
from enum import Enum

logger = logging.getLogger(__name__)


class FileType(str, Enum):
    """Unterstützte Dateitypen."""
    DISK_IMAGE = "disk_image"
    MEMORY_DUMP = "memory_dump"
    LOG_FILE = "log_file"
    UAC_DUMP = "uac_dump"
    ARCHIVE = "archive"
    PCAP = "pcap"
    UNKNOWN = "unknown"


class FileTypeDetector:
    """
    Erweiterte Dateityp-Erkennung.
    
    Kombiniert:
    - Extension-Check
    - MIME-Type (libmagic)
    - File-Signature (Magic Bytes)
    - Directory-Structure-Analysis
    """
    
    # Extension-Mappings
    DISK_IMAGE_EXTENSIONS = {
        '.dd', '.raw', '.img', '.001',  # Raw Disk Images
        '.e01', '.ex01', '.ewf',        # EnCase Evidence Files
        '.aff', '.afd',                 # Advanced Forensic Format
        '.vdi', '.vmdk', '.vhd', '.vhdx',  # Virtual Disk Images
        '.qcow', '.qcow2',              # QEMU Images
        '.iso',                         # ISO Images
    }
    
    MEMORY_DUMP_EXTENSIONS = {
        '.mem', '.dmp', '.dump',        # Memory Dumps
        '.vmem',                        # VMware Memory
        '.raw', '.bin',                 # Raw Memory (ambiguous)
    }
    
    LOG_FILE_EXTENSIONS = {
        '.log', '.txt', '.syslog',
        '.auth', '.messages',
        '.evtx', '.evt',                # Windows Event Logs
    }
    
    ARCHIVE_EXTENSIONS = {
        '.zip', '.tar', '.gz', '.bz2',
        '.7z', '.rar', '.tgz',
    }
    
    PCAP_EXTENSIONS = {
        '.pcap', '.pcapng', '.cap',
    }
    
    # MIME-Type-Mappings
    DISK_IMAGE_MIMES = {
        'application/x-raw-disk-image',
        'application/octet-stream',  # Generic (kann alles sein)
    }
    
    MEMORY_DUMP_MIMES = {
        'application/x-dmp',
        'application/octet-stream',
    }
    
    # Magic Bytes (File Signatures)
    MAGIC_BYTES = {
        # EnCase Evidence File
        b'EVF': FileType.DISK_IMAGE,
        # VMware VMDK
        b'# Disk DescriptorFile': FileType.DISK_IMAGE,
        # Windows Memory Dump
        b'PAGEDUMP': FileType.MEMORY_DUMP,
        b'PAGE': FileType.MEMORY_DUMP,
        # PCAP
        b'\xa1\xb2\xc3\xd4': FileType.PCAP,
        b'\xd4\xc3\xb2\xa1': FileType.PCAP,
    }
    
    def __init__(self):
        """Initialisiert Detector."""
        try:
            # Test ob python-magic verfügbar ist
            magic.from_buffer(b'test', mime=True)
            self.magic_available = True
        except Exception as e:
            logger.warning(f"python-magic nicht verfügbar: {e}")
            self.magic_available = False
    
    def detect(self, path: Path) -> FileType:
        """
        Hauptmethode zur Dateityp-Erkennung.
        
        Args:
            path: Pfad zur Datei/Verzeichnis
        
        Returns:
            Erkannter FileType
        """
        if not path.exists():
            logger.error(f"Pfad existiert nicht: {path}")
            return FileType.UNKNOWN
        
        # 1. Directory-Check (UAC-Dumps)
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
    
    def _detect_by_extension(self, path: Path) -> FileType:
        """Erkennt Typ via Extension."""
        suffix = path.suffix.lower()
        
        if suffix in self.DISK_IMAGE_EXTENSIONS:
            return FileType.DISK_IMAGE
        elif suffix in self.MEMORY_DUMP_EXTENSIONS:
            return FileType.MEMORY_DUMP
        elif suffix in self.LOG_FILE_EXTENSIONS:
            return FileType.LOG_FILE
        elif suffix in self.ARCHIVE_EXTENSIONS:
            return FileType.ARCHIVE
        elif suffix in self.PCAP_EXTENSIONS:
            return FileType.PCAP
        
        return FileType.UNKNOWN
    
    def _detect_by_mime(self, path: Path) -> FileType:
        """Erkennt Typ via MIME-Type."""
        if not self.magic_available:
            return FileType.UNKNOWN
        
        try:
            mime = magic.from_file(str(path), mime=True)
            logger.debug(f"MIME-Type: {mime}")
            
            if mime in self.DISK_IMAGE_MIMES:
                return FileType.DISK_IMAGE
            elif mime in self.MEMORY_DUMP_MIMES:
                return FileType.MEMORY_DUMP
            elif 'text' in mime:
                return FileType.LOG_FILE
            elif 'application/x-pcap' in mime:
                return FileType.PCAP
            elif 'compressed' in mime or 'zip' in mime or 'tar' in mime:
                return FileType.ARCHIVE
        
        except Exception as e:
            logger.debug(f"MIME-Detection fehlgeschlagen: {e}")
        
        return FileType.UNKNOWN
    
    def _detect_by_magic_bytes(self, path: Path) -> FileType:
        """Erkennt Typ via Magic Bytes (File Signature)."""
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
        """Analysiert Directory-Struktur (z.B. UAC-Dump)."""
        # UAC-Dumps haben typische Struktur
        uac_indicators = ['bodyfile.txt', 'live_response', 'artifacts']
        
        try:
            files = [f.name for f in path.iterdir()]
            
            # Check für UAC-Dump
            if any(indicator in files for indicator in uac_indicators):
                return FileType.UAC_DUMP
            
            # Check für Log-Sammlung
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
        Kombiniert verschiedene Detektionsmethoden.
        
        Priorität:
        1. Magic Bytes (höchste Genauigkeit)
        2. Extension + MIME (Übereinstimmung)
        3. Extension allein
        4. Heuristik (Dateigröße, etc.)
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
        
        # Heuristik basierend auf Dateigröße
        try:
            size = path.stat().st_size
            
            # Sehr große Dateien (>1GB) sind wahrscheinlich Images/Dumps
            if size > 1_000_000_000:
                # Check ob binär
                with open(path, 'rb') as f:
                    sample = f.read(8192)
                
                # Wenn >50% non-ASCII -> wahrscheinlich Binary
                non_ascii = sum(1 for b in sample if b > 127 or b < 32)
                if non_ascii / len(sample) > 0.5:
                    return FileType.DISK_IMAGE
            
            # Kleine Dateien (<10MB) mit Text -> wahrscheinlich Logs
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
    
    def get_file_info(self, path: Path) -> Dict[str, Any]:
        """
        Sammelt detaillierte Datei-Informationen.
        
        Returns:
            Dict mit allen Infos
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


# Convenience-Funktion (backward compatibility)
def detect_input_type(path: Path) -> str:
    """
    Legacy-Funktion für detect_input_type.
    
    Args:
        path: Pfad zur Datei
    
    Returns:
        Typ als String
    """
    detector = FileTypeDetector()
    file_type = detector.detect(path)
    
    # Mapping zu alten String-Values
    type_mapping = {
        FileType.DISK_IMAGE: 'disk_image',
        FileType.MEMORY_DUMP: 'ram_dump',
        FileType.LOG_FILE: 'logs',
        FileType.UAC_DUMP: 'uac_dump',
        FileType.ARCHIVE: 'archive',
        FileType.PCAP: 'pcap',
        FileType.UNKNOWN: 'unknown',
    }
    
    return type_mapping.get(file_type, 'unknown')


# Beispiel-Usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    
    detector = FileTypeDetector()
    
    # Test-Pfade (anpassen!)
    test_files = [
        Path("test.dd"),
        Path("test.mem"),
        Path("test.log"),
        Path("uac_dump/"),
    ]
    
    for file in test_files:
        if file.exists():
            file_type = detector.detect(file)
            info = detector.get_file_info(file)
            print(f"\n{file}: {file_type}")
            print(f"Info: {info}")