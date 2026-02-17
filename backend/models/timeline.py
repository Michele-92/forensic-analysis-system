"""
Timeline Data Models.
Pydantic-Models für forensische Timelines.
"""

from pydantic import BaseModel, Field, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class EventType(str, Enum):
    """Event-Typen."""
    FILE_SYSTEM = "file_system"
    REGISTRY = "registry"
    NETWORK = "network"
    PROCESS = "process"
    USER_LOGIN = "user_login"
    SYSTEM_EVENT = "system_event"
    APPLICATION = "application"
    SECURITY = "security"
    CUSTOM = "custom"


class EventSeverity(str, Enum):
    """Event-Schweregrade."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TimelineEvent(BaseModel):
    """
    Einzelnes Timeline-Event.
    
    Beispiel:
        {
            "event_id": "evt_001",
            "timestamp": "2026-02-15T10:30:00",
            "event_type": "file_system",
            "severity": "medium",
            "source": "tsk",
            "description": "File created: /tmp/malware.exe",
            "actor": "root",
            "target": "/tmp/malware.exe",
            "metadata": {"size": 1024000, "hash": "..."}
        }
    """
    
    event_id: str = Field(..., description="Eindeutige Event-ID")
    timestamp: datetime = Field(..., description="Event-Zeitstempel")
    
    event_type: EventType = Field(..., description="Typ des Events")
    severity: EventSeverity = Field(default=EventSeverity.INFO, description="Schweregrad")
    
    source: str = Field(..., description="Datenquelle (uac, dissect, tsk, etc.)")
    description: str = Field(..., description="Event-Beschreibung")
    
    actor: Optional[str] = Field(None, description="Wer? (User, Process, IP)")
    action: Optional[str] = Field(None, description="Was? (created, deleted, executed)")
    target: Optional[str] = Field(None, description="Womit? (File, Registry-Key, etc.)")
    
    host: Optional[str] = Field(None, description="Hostname/System")
    
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Zusätzliche Daten")
    
    is_anomaly: bool = Field(False, description="Als Anomalie markiert")
    anomaly_score: Optional[float] = Field(None, description="Anomalie-Score (0-1)", ge=0, le=1)
    
    tags: List[str] = Field(default_factory=list, description="Tags")
    related_events: List[str] = Field(default_factory=list, description="IDs verwandter Events")
    
    class Config:
        use_enum_values = True
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
    
    @validator('timestamp', pre=True)
    def parse_timestamp(cls, v):
        """Parst Timestamp."""
        if isinstance(v, datetime):
            return v
        if isinstance(v, str):
            try:
                return datetime.fromisoformat(v.replace('Z', '+00:00'))
            except:
                return datetime.now()
        if isinstance(v, (int, float)):
            return datetime.fromtimestamp(v)
        return datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Konvertiert zu Dictionary."""
        return self.dict(exclude_none=True)
    
    def mark_anomaly(self, score: float, reason: str = None):
        """Markiert als Anomalie."""
        self.is_anomaly = True
        self.anomaly_score = score
        if reason:
            self.metadata['anomaly_reason'] = reason


class Timeline(BaseModel):
    """
    Forensische Timeline mit Events.
    
    Beispiel:
        {
            "timeline_id": "tl_001",
            "name": "Investigation Timeline",
            "created_at": "2026-02-15T10:00:00",
            "time_range": {
                "start": "2026-02-14T00:00:00",
                "end": "2026-02-15T23:59:59"
            },
            "events": [...],
            "statistics": {"total": 1000, "anomalies": 15}
        }
    """
    
    timeline_id: str = Field(..., description="Eindeutige Timeline-ID")
    name: str = Field(..., description="Name der Timeline")
    description: Optional[str] = Field(None, description="Beschreibung")
    
    created_at: datetime = Field(default_factory=datetime.now, description="Erstellungszeitpunkt")
    updated_at: Optional[datetime] = Field(None, description="Letztes Update")
    
    time_range: Optional[Dict[str, datetime]] = Field(None, description="Zeitbereich (start, end)")
    
    events: List[TimelineEvent] = Field(default_factory=list, description="Timeline-Events")
    
    statistics: Dict[str, Any] = Field(default_factory=dict, description="Statistiken")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Metadaten")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
    
    def add_event(self, event: TimelineEvent):
        """Fügt Event hinzu."""
        self.events.append(event)
        self.updated_at = datetime.now()
        self._update_statistics()
        self._update_time_range(event.timestamp)
    
    def add_events(self, events: List[TimelineEvent]):
        """Fügt mehrere Events hinzu."""
        self.events.extend(events)
        self.updated_at = datetime.now()
        self._update_statistics()
        for event in events:
            self._update_time_range(event.timestamp)
    
    def get_by_type(self, event_type: EventType) -> List[TimelineEvent]:
        """Filtert Events nach Typ."""
        return [e for e in self.events if e.event_type == event_type]
    
    def get_by_severity(self, severity: EventSeverity) -> List[TimelineEvent]:
        """Filtert Events nach Schweregrad."""
        return [e for e in self.events if e.severity == severity]
    
    def get_anomalies(self) -> List[TimelineEvent]:
        """Gibt alle Anomalien zurück."""
        return [e for e in self.events if e.is_anomaly]
    
    def get_by_timerange(self, start: datetime, end: datetime) -> List[TimelineEvent]:
        """Filtert Events nach Zeitbereich."""
        return [e for e in self.events if start <= e.timestamp <= end]
    
    def get_by_actor(self, actor: str) -> List[TimelineEvent]:
        """Filtert Events nach Actor."""
        return [e for e in self.events if e.actor and actor.lower() in e.actor.lower()]
    
    def search(self, query: str) -> List[TimelineEvent]:
        """Volltextsuche in Description."""
        query_lower = query.lower()
        return [e for e in self.events if query_lower in e.description.lower()]
    
    def sort_by_time(self, reverse: bool = False):
        """Sortiert Events chronologisch."""
        self.events.sort(key=lambda e: e.timestamp, reverse=reverse)
    
    def _update_statistics(self):
        """Aktualisiert Statistiken."""
        self.statistics = {
            'total_events': len(self.events),
            'anomalies': len(self.get_anomalies()),
            'by_type': {
                event_type.value: len(self.get_by_type(event_type))
                for event_type in EventType
            },
            'by_severity': {
                severity.value: len(self.get_by_severity(severity))
                for severity in EventSeverity
            },
            'sources': list(set(e.source for e in self.events)),
            'actors': list(set(e.actor for e in self.events if e.actor)),
        }
    
    def _update_time_range(self, timestamp: datetime):
        """Aktualisiert Zeitbereich."""
        if self.time_range is None:
            self.time_range = {'start': timestamp, 'end': timestamp}
        else:
            if timestamp < self.time_range['start']:
                self.time_range['start'] = timestamp
            if timestamp > self.time_range['end']:
                self.time_range['end'] = timestamp
    
    def to_dict(self) -> Dict[str, Any]:
        """Konvertiert zu Dictionary."""
        return self.dict(exclude_none=True)
    
    def to_dataframe(self):
        """Konvertiert zu Pandas DataFrame."""
        import pandas as pd
        return pd.DataFrame([e.dict() for e in self.events])
    
    def export_json(self, filepath: str):
        """Exportiert als JSON."""
        import json
        with open(filepath, 'w') as f:
            json.dump(self.to_dict(), f, indent=2, default=str)
    
    def export_csv(self, filepath: str):
        """Exportiert als CSV."""
        df = self.to_dataframe()
        df.to_csv(filepath, index=False)
    
    @classmethod
    def from_json(cls, filepath: str) -> 'Timeline':
        """Lädt aus JSON."""
        import json
        with open(filepath) as f:
            data = json.load(f)
        return cls(**data)


# Beispiel-Usage
if __name__ == "__main__":
    # Erstelle Event
    event = TimelineEvent(
        event_id="evt_001",
        timestamp=datetime.now(),
        event_type=EventType.FILE_SYSTEM,
        severity=EventSeverity.HIGH,
        source="tsk",
        description="Suspicious file created",
        actor="root",
        action="created",
        target="/tmp/malware.exe",
        metadata={"size": 1024000}
    )
    
    event.mark_anomaly(score=0.85, reason="Created in /tmp by root at unusual time")
    print(event.json(indent=2))
    
    # Erstelle Timeline
    timeline = Timeline(
        timeline_id="tl_001",
        name="Incident Investigation",
        description="Timeline for security incident on 2026-02-15"
    )
    
    timeline.add_event(event)
    timeline.sort_by_time(reverse=True)
    
    print(f"\nStatistics: {timeline.statistics}")