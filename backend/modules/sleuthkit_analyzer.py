"""
Sleuth Kit (TSK) Analyzer.
Verwendet pytsk3 für Dateisystem-Timeline-Analyse.
"""

import logging
from pathlib import Path
from typing import List, Dict, Optional
import pytsk3

logger = logging.getLogger(__name__)


class SleuthKitAnalyzer:
    """Wrapper für Sleuth Kit (pytsk3)."""
    
    def __init__(self):
        self.img_info: Optional[pytsk3.Img_Info] = None
        self.fs_info: Optional[pytsk3.FS_Info] = None
    
    def load_image(self, image_path: Path, offset: int = 0) -> bool:
        """
        Lädt Disk-Image.
        
        Args:
            image_path: Pfad zum Image
            offset: Partition-Offset in Bytes (für Multi-Partition)
        
        Returns:
            True bei Erfolg
        """
        try:
            logger.info(f"Lade TSK-Image: {image_path}")
            self.img_info = pytsk3.Img_Info(str(image_path))
            self.fs_info = pytsk3.FS_Info(self.img_info, offset=offset)
            logger.info("TSK-Image erfolgreich geladen")
            return True
        except Exception as e:
            logger.error(f"Fehler beim Laden des Images: {e}")
            return False
    
    def walk_directory(self, 
                      path: str = "/",
                      recursive: bool = True,
                      max_depth: int = 10) -> List[Dict]:
        """
        Durchläuft Verzeichnisstruktur.
        
        Args:
            path: Start-Pfad
            recursive: Rekursiv durchlaufen
            max_depth: Max. Rekursionstiefe
        
        Returns:
            Liste von Datei-Metadaten
        """
        if not self.fs_info:
            logger.error("Filesystem nicht geladen")
            return []
        
        entries = []
        
        def _walk(current_path: str, depth: int = 0):
            if depth > max_depth:
                return
            
            try:
                directory = self.fs_info.open_dir(current_path)
                
                for entry in directory:
                    # Skip . und ..
                    if entry.info.name.name in [b'.', b'..']:
                        continue
                    
                    try:
                        stat = entry.info
                        entry_path = current_path.rstrip('/') + '/' + entry.info.name.name.decode('utf-8', errors='ignore')
                        
                        file_entry = {
                            'inode': stat.meta.addr,
                            'name': entry.info.name.name.decode('utf-8', errors='ignore'),
                            'path': entry_path,
                            'size': stat.meta.size,
                            'mtime': stat.meta.mtime,
                            'atime': stat.meta.atime,
                            'ctime': stat.meta.ctime,
                            'crtime': stat.meta.crtime if hasattr(stat.meta, 'crtime') else None,
                            'type': self._get_file_type(stat.meta.type),
                            'mode': stat.meta.mode,
                            'uid': stat.meta.uid,
                            'gid': stat.meta.gid
                        }
                        
                        entries.append(file_entry)
                        
                        # Rekursiv in Unterverzeichnisse
                        if recursive and stat.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                            _walk(entry_path, depth + 1)
                    
                    except Exception as e:
                        logger.debug(f"Fehler bei Entry: {e}")
                        continue
            
            except Exception as e:
                logger.debug(f"Fehler bei Verzeichnis {current_path}: {e}")
        
        _walk(path)
        logger.info(f"Dateisystem durchlaufen: {len(entries)} Einträge")
        return entries
    
    def _get_file_type(self, type_code: int) -> str:
        """Konvertiert TSK-Type-Code zu String."""
        type_map = {
            pytsk3.TSK_FS_META_TYPE_REG: 'file',
            pytsk3.TSK_FS_META_TYPE_DIR: 'dir',
            pytsk3.TSK_FS_META_TYPE_LNK: 'symlink',
            pytsk3.TSK_FS_META_TYPE_CHR: 'char_device',
            pytsk3.TSK_FS_META_TYPE_BLK: 'block_device',
            pytsk3.TSK_FS_META_TYPE_FIFO: 'fifo',
            pytsk3.TSK_FS_META_TYPE_SOCK: 'socket'
        }
        return type_map.get(type_code, 'unknown')
    
    def create_timeline(self, 
                       entries: List[Dict] = None,
                       sort_by: str = 'mtime') -> List[Dict]:
        """
        Erstellt sortierte Timeline.
        
        Args:
            entries: Datei-Einträge (None = neue Analyse)
            sort_by: Sortier-Feld (mtime, atime, ctime)
        
        Returns:
            Sortierte Timeline
        """
        if entries is None:
            entries = self.walk_directory()
        
        # Sortiere nach Zeitstempel
        timeline = sorted(
            entries,
            key=lambda x: x.get(sort_by, 0),
            reverse=True  # Neueste zuerst
        )
        
        logger.info(f"Timeline erstellt: {len(timeline)} Events")
        return timeline
    
    def find_suspicious_files(self, entries: List[Dict]) -> List[Dict]:
        """
        Findet verdächtige Dateien (Heuristik).
        
        Args:
            entries: Datei-Einträge
        
        Returns:
            Liste verdächtiger Dateien
        """
        suspicious = []
        
        suspicious_paths = [
            '/tmp/', '/var/tmp/', '/dev/shm/',
            '\\Temp\\', '\\AppData\\Local\\Temp\\',
            '/root/.ssh/', '/home/*/.ssh/'
        ]
        
        suspicious_extensions = [
            '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.sh'
        ]
        
        for entry in entries:
            path = entry['path'].lower()
            
            # Verdächtige Pfade
            if any(sp in path for sp in suspicious_paths):
                suspicious.append({
                    **entry,
                    'reason': 'suspicious_path'
                })
                continue
            
            # Verdächtige Extensions
            if any(path.endswith(ext) for ext in suspicious_extensions):
                suspicious.append({
                    **entry,
                    'reason': 'suspicious_extension'
                })
                continue
            
            # Hidden Files in ungewöhnlichen Orten
            if entry['name'].startswith('.') and '/home/' not in path and '/root/' not in path:
                suspicious.append({
                    **entry,
                    'reason': 'hidden_file'
                })
        
        logger.info(f"Verdächtige Dateien gefunden: {len(suspicious)}")
        return suspicious
    
    def extract_deleted_files(self) -> List[Dict]:
        """
        Findet gelöschte Dateien.
        
        Returns:
            Liste gelöschter Dateien
        """
        if not self.fs_info:
            return []
        
        deleted = []
        
        try:
            for entry in self.walk_directory():
                # TSK markiert gelöschte Dateien mit Flag
                # (Vereinfachte Implementierung)
                if entry['name'].startswith('$OrphanFiles'):
                    deleted.append(entry)
            
            logger.info(f"Gelöschte Dateien gefunden: {len(deleted)}")
            return deleted
        except Exception as e:
            logger.error(f"Fehler beim Suchen gelöschter Dateien: {e}")
            return []