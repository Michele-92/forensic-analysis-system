"""
Data Normalizer.
Normalisiert verschiedene Datenquellen zu einheitlichem Format.
"""

import logging
from typing import Dict, List, Any
from datetime import datetime
import pandas as pd

logger = logging.getLogger(__name__)


class DataNormalizer:
    """Normalisiert forensische Daten zu einheitlichem Schema."""
    
    @staticmethod
    def normalize_timeline_event(event: Dict, source: str) -> Dict:
        """
        Normalisiert Timeline-Event zu Standard-Schema.
        
        Standard-Schema:
        {
            'event_id': str,
            'timestamp': ISO-8601,
            'event_type': str,
            'source': str,
            'description': str,
            'metadata': dict
        }
        
        Args:
            event: Original-Event
            source: Datenquelle (uac, dissect, tsk)
        
        Returns:
            Normalisiertes Event
        """
        normalized = {
            'event_id': f"{source}_{event.get('inode', hash(str(event)))}",
            'timestamp': DataNormalizer._normalize_timestamp(
                event.get('mtime') or event.get('timestamp')
            ),
            'event_type': DataNormalizer._infer_event_type(event),
            'source': source,
            'description': DataNormalizer._create_description(event),
            'metadata': {
                k: v for k, v in event.items()
                if k not in ['mtime', 'timestamp', 'event_id']
            }
        }
        
        return normalized
    
    @staticmethod
    def _normalize_timestamp(ts: Any) -> str:
        """Konvertiert verschiedene Timestamp-Formate zu ISO-8601."""
        if ts is None:
            return datetime.now().isoformat()
        
        if isinstance(ts, str):
            return ts
        
        if isinstance(ts, (int, float)):
            # Unix-Timestamp
            return datetime.fromtimestamp(ts).isoformat()
        
        if isinstance(ts, datetime):
            return ts.isoformat()
        
        return str(ts)
    
    @staticmethod
    def _infer_event_type(event: Dict) -> str:
        """Leitet Event-Typ ab."""
        if 'event_id' in event:
            return 'windows_event'
        elif 'inode' in event:
            return 'file_system'
        elif 'provider' in event:
            return 'log_entry'
        else:
            return 'unknown'
    
    @staticmethod
    def _create_description(event: Dict) -> str:
        """Erstellt lesbare Beschreibung."""
        if 'message' in event:
            return event['message']
        
        if 'path' in event and 'type' in event:
            return f"{event['type']}: {event['path']}"
        
        if 'name' in event:
            return f"File: {event['name']}"
        
        return str(event)
    
    @staticmethod
    def normalize_artifacts(artifacts: Dict[str, List[Dict]]) -> List[Dict]:
        """
        Normalisiert alle Artefakte aus verschiedenen Quellen.
        
        Args:
            artifacts: Dict mit Artefakten pro Quelle
                {
                    'uac': [...],
                    'dissect': [...],
                    'tsk': [...]
                }
        
        Returns:
            Liste normalisierter Artefakte
        """
        normalized = []
        
        for source, events in artifacts.items():
            for event in events:
                try:
                    normalized.append(
                        DataNormalizer.normalize_timeline_event(event, source)
                    )
                except Exception as e:
                    logger.warning(f"Fehler beim Normalisieren von {source}-Event: {e}")
        
        logger.info(f"Artefakte normalisiert: {len(normalized)}")
        return normalized
    
    @staticmethod
    def deduplicate_events(events: List[Dict]) -> List[Dict]:
        """
        Entfernt Duplikate basierend auf Timestamp + Description.
        
        Args:
            events: Liste von Events
        
        Returns:
            Deduplizierte Liste
        """
        seen = set()
        unique = []
        
        for event in events:
            key = (event['timestamp'], event['description'])
            if key not in seen:
                seen.add(key)
                unique.append(event)
        
        removed = len(events) - len(unique)
        logger.info(f"Duplikate entfernt: {removed}")
        return unique
    
    @staticmethod
    def enrich_with_context(events: List[Dict], 
                           context: Dict[str, Any]) -> List[Dict]:
        """
        Reichert Events mit Kontext an.
        
        Args:
            events: Liste von Events
            context: Zusätzlicher Kontext (z.B. System-Info, IOCs)
        
        Returns:
            Angereicherte Events
        """
        for event in events:
            event['context'] = context
        
        return events
    
    @staticmethod
    def to_dataframe(events: List[Dict]) -> pd.DataFrame:
        """
        Konvertiert Events zu Pandas DataFrame.
        
        Args:
            events: Liste von Events
        
        Returns:
            DataFrame
        """
        df = pd.DataFrame(events)
        
        # Konvertiere Timestamp zu datetime
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        return df