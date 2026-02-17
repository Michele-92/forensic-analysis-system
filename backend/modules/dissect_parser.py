"""
Dissect Parser Wrapper.
Verwendet Dissect-Framework für Disk-Image-Analyse.
"""

import logging
from pathlib import Path
from typing import List, Dict, Optional
from dissect.target import Target
from dissect.target.exceptions import TargetError

logger = logging.getLogger(__name__)


class DissectParser:
    """Wrapper für Dissect-Framework."""
    
    def __init__(self):
        self.target: Optional[Target] = None
    
    def load_target(self, image_path: Path) -> bool:
        """
        Lädt Disk-Image als Target.
        
        Args:
            image_path: Pfad zum Image
        
        Returns:
            True bei Erfolg
        """
        try:
            logger.info(f"Lade Dissect-Target: {image_path}")
            self.target = Target.open(str(image_path))
            logger.info(f"Target geladen: {self.target.os}")
            return True
        except TargetError as e:
            logger.error(f"Fehler beim Laden des Targets: {e}")
            return False
        except Exception as e:
            logger.error(f"Unerwarteter Fehler: {e}")
            return False
    
    def query_mft(self, limit: Optional[int] = None) -> List[Dict]:
        """
        Extrahiert MFT-Einträge (NTFS Master File Table).
        
        Args:
            limit: Max. Anzahl Einträge (None = alle)
        
        Returns:
            Liste von MFT-Einträgen
        """
        if not self.target:
            logger.error("Target nicht geladen")
            return []
        
        artifacts = []
        count = 0
        
        try:
            for record in self.target.mft():
                artifacts.append({
                    'path': str(record.path),
                    'mtime': str(record.mtime) if record.mtime else None,
                    'atime': str(record.atime) if record.atime else None,
                    'ctime': str(record.ctime) if record.ctime else None,
                    'size': record.size,
                    'hash': getattr(record, 'sha256', None),
                    'resident': record.resident,
                    'attributes': list(record.attributes.keys()) if hasattr(record, 'attributes') else []
                })
                
                count += 1
                if limit and count >= limit:
                    break
            
            logger.info(f"MFT-Einträge extrahiert: {len(artifacts)}")
            return artifacts
            
        except Exception as e:
            logger.error(f"Fehler beim MFT-Query: {e}")
            return artifacts
    
    def query_eventlogs(self) -> List[Dict]:
        """
        Extrahiert Windows Event Logs.
        
        Returns:
            Liste von Event-Log-Einträgen
        """
        if not self.target:
            logger.error("Target nicht geladen")
            return []
        
        events = []
        
        try:
            for record in self.target.evtx():
                events.append({
                    'timestamp': str(record.timestamp),
                    'event_id': record.event_id,
                    'provider': record.provider,
                    'channel': record.channel,
                    'computer': record.computer,
                    'user': record.user,
                    'message': record.message
                })
            
            logger.info(f"Event-Logs extrahiert: {len(events)}")
            return events
            
        except Exception as e:
            logger.error(f"Fehler beim EventLog-Query: {e}")
            return []
    
    def query_users(self) -> List[Dict]:
        """
        Extrahiert User-Accounts.
        
        Returns:
            Liste von User-Informationen
        """
        if not self.target:
            logger.error("Target nicht geladen")
            return []
        
        users = []
        
        try:
            for user in self.target.users():
                users.append({
                    'username': user.name,
                    'uid': user.sid if hasattr(user, 'sid') else user.uid,
                    'home': str(user.home) if user.home else None,
                    'shell': str(user.shell) if hasattr(user, 'shell') else None
                })
            
            logger.info(f"Users extrahiert: {len(users)}")
            return users
            
        except Exception as e:
            logger.error(f"Fehler beim User-Query: {e}")
            return []
    
    def query_registry(self, hive: str = 'HKEY_LOCAL_MACHINE') -> List[Dict]:
        """
        Extrahiert Registry-Keys (Windows).
        
        Args:
            hive: Registry-Hive
        
        Returns:
            Liste von Registry-Einträgen
        """
        if not self.target:
            logger.error("Target nicht geladen")
            return []
        
        registry = []
        
        try:
            for key in self.target.registry().keys(hive):
                registry.append({
                    'path': str(key.path),
                    'values': {v.name: str(v.value) for v in key.values()}
                })
            
            logger.info(f"Registry-Keys extrahiert: {len(registry)}")
            return registry
            
        except Exception as e:
            logger.error(f"Fehler beim Registry-Query: {e}")
            return []
    
    def query_all(self, limit_per_query: Optional[int] = 1000) -> Dict[str, List[Dict]]:
        """
        Führt alle Queries aus.
        
        Args:
            limit_per_query: Limit pro Query
        
        Returns:
            Dict mit allen Artefakten
        """
        if not self.target:
            logger.error("Target nicht geladen")
            return {}
        
        logger.info("Starte umfassende Dissect-Analyse")
        
        return {
            'mft': self.query_mft(limit=limit_per_query),
            'eventlogs': self.query_eventlogs(),
            'users': self.query_users(),
            'registry': self.query_registry()
        }
    
    def close(self):
        """Schließt Target."""
        if self.target:
            self.target.close()
            self.target = None
            logger.info("Target geschlossen")