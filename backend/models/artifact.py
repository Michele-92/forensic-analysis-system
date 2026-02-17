"""
Artifact Data Models.
Pydantic-Models für forensische Artefakte.
"""

from pydantic import BaseModel, Field, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class ArtifactType(str, Enum):
    """Artefakt-Typen."""
    FILE = "file"
    REGISTRY = "registry"
    LOG = "log"
    MEMORY = "memory"
    NETWORK = "network"
    PROCESS = "process"
    USER = "user"
    EVENTLOG = "eventlog"
    OTHER = "other"


class ArtifactSource(str, Enum):
    """Datenquellen."""
    UAC = "uac"
    DISSECT = "dissect"
    TSK = "tsk"
    VOLATILITY = "volatility"
    MANUAL = "manual"
    OTHER = "other"


class Artifact(BaseModel):
    """
    Einzelnes forensisches Artefakt.
    
    Beispiel:
        {
            "artifact_id": "art_001",
            "artifact_type": "file",
            "source": "tsk",
            "name": "malware.exe",
            "path": "/tmp/malware.exe",
            "timestamp": "2026-02-15T10:30:00",
            "size": 1024000,
            "hash_md5": "5d41402abc4b2a76b9719d911017c592",
            "hash_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "metadata": {"permissions": "755", "owner": "root"}
        }
    """
    
    artifact_id: str = Field(..., description="Eindeutige ID")
    artifact_type: ArtifactType = Field(..., description="Typ des Artefakts")
    source: ArtifactSource = Field(..., description="Datenquelle")
    
    name: str = Field(..., description="Name/Bezeichnung")
    path: Optional[str] = Field(None, description="Dateisystem-Pfad")
    
    timestamp: Optional[datetime] = Field(None, description="Hauptzeitstempel")
    mtime: Optional[datetime] = Field(None, description="Modified Time")
    atime: Optional[datetime] = Field(None, description="Access Time")
    ctime: Optional[datetime] = Field(None, description="Change Time")
    crtime: Optional[datetime] = Field(None, description="Creation Time")
    
    size: Optional[int] = Field(None, description="Größe in Bytes", ge=0)
    
    hash_md5: Optional[str] = Field(None, description="MD5-Hash", min_length=32, max_length=32)
    hash_sha1: Optional[str] = Field(None, description="SHA1-Hash", min_length=40, max_length=40)
    hash_sha256: Optional[str] = Field(None, description="SHA256-Hash", min_length=64, max_length=64)
    
    content: Optional[str] = Field(None, description="Inhalt (bei kleinen Dateien/Logs)")
    
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Zusätzliche Metadaten")
    
    tags: List[str] = Field(default_factory=list, description="Tags für Kategorisierung")
    is_suspicious: bool = Field(False, description="Als verdächtig markiert")
    
    class Config:
        use_enum_values = True
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
    
    @validator('hash_md5', 'hash_sha1', 'hash_sha256')
    def validate_hash(cls, v):
        """Validiert Hash-Strings (nur Hex-Zeichen)."""
        if v is not None:
            if not all(c in '0123456789abcdefABCDEF' for c in v):
                raise ValueError("Hash muss nur Hex-Zeichen enthalten")
        return v.lower() if v else v
    
    @validator('timestamp', 'mtime', 'atime', 'ctime', 'crtime', pre=True)
    def parse_timestamp(cls, v):
        """Parst verschiedene Timestamp-Formate."""
        if v is None:
            return None
        if isinstance(v, datetime):
            return v
        if isinstance(v, str):
            try:
                return datetime.fromisoformat(v.replace('Z', '+00:00'))
            except:
                pass
        if isinstance(v, (int, float)):
            return datetime.fromtimestamp(v)
        return v
    
    def to_dict(self) -> Dict[str, Any]:
        """Konvertiert zu Dictionary (JSON-serialisierbar)."""
        return self.dict(exclude_none=True)
    
    def add_tag(self, tag: str):
        """Fügt Tag hinzu."""
        if tag not in self.tags:
            self.tags.append(tag)
    
    def mark_suspicious(self, reason: str = None):
        """Markiert Artefakt als verdächtig."""
        self.is_suspicious = True
        if reason:
            self.metadata['suspicious_reason'] = reason


class ArtifactCollection(BaseModel):
    """
    Sammlung von Artefakten mit Metadaten.
    
    Beispiel:
        {
            "collection_id": "col_001",
            "name": "Disk Analysis 2026-02-15",
            "created_at": "2026-02-15T10:00:00",
            "source_path": "/mnt/evidence/disk.dd",
            "artifacts": [...],
            "statistics": {"total": 1000, "suspicious": 15}
        }
    """
    
    collection_id: str = Field(..., description="Eindeutige Collection-ID")
    name: str = Field(..., description="Name der Sammlung")
    description: Optional[str] = Field(None, description="Beschreibung")
    
    created_at: datetime = Field(default_factory=datetime.now, description="Erstellungszeitpunkt")
    updated_at: Optional[datetime] = Field(None, description="Letztes Update")
    
    source_path: Optional[str] = Field(None, description="Quell-Pfad (Image/Dump)")
    source_type: Optional[str] = Field(None, description="Quell-Typ (disk_image, logs, etc.)")
    
    artifacts: List[Artifact] = Field(default_factory=list, description="Liste von Artefakten")
    
    statistics: Dict[str, Any] = Field(default_factory=dict, description="Statistiken")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Zusätzliche Metadaten")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
    
    def add_artifact(self, artifact: Artifact):
        """Fügt Artefakt hinzu."""
        self.artifacts.append(artifact)
        self.updated_at = datetime.now()
        self._update_statistics()
    
    def add_artifacts(self, artifacts: List[Artifact]):
        """Fügt mehrere Artefakte hinzu."""
        self.artifacts.extend(artifacts)
        self.updated_at = datetime.now()
        self._update_statistics()
    
    def get_by_type(self, artifact_type: ArtifactType) -> List[Artifact]:
        """Filtert Artefakte nach Typ."""
        return [a for a in self.artifacts if a.artifact_type == artifact_type]
    
    def get_suspicious(self) -> List[Artifact]:
        """Gibt alle verdächtigen Artefakte zurück."""
        return [a for a in self.artifacts if a.is_suspicious]
    
    def get_by_source(self, source: ArtifactSource) -> List[Artifact]:
        """Filtert Artefakte nach Quelle."""
        return [a for a in self.artifacts if a.source == source]
    
    def search(self, query: str) -> List[Artifact]:
        """Sucht in Name und Pfad."""
        query_lower = query.lower()
        return [
            a for a in self.artifacts
            if query_lower in a.name.lower() or (a.path and query_lower in a.path.lower())
        ]
    
    def _update_statistics(self):
        """Aktualisiert Statistiken."""
        self.statistics = {
            'total': len(self.artifacts),
            'suspicious': len(self.get_suspicious()),
            'by_type': {
                artifact_type.value: len(self.get_by_type(artifact_type))
                for artifact_type in ArtifactType
            },
            'by_source': {
                source.value: len(self.get_by_source(source))
                for source in ArtifactSource
            },
            'size_total_bytes': sum(a.size for a in self.artifacts if a.size),
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Konvertiert zu Dictionary."""
        return self.dict(exclude_none=True)
    
    def to_dataframe(self):
        """Konvertiert zu Pandas DataFrame."""
        import pandas as pd
        return pd.DataFrame([a.dict() for a in self.artifacts])
    
    def export_json(self, filepath: str):
        """Exportiert als JSON-Datei."""
        import json
        with open(filepath, 'w') as f:
            json.dump(self.to_dict(), f, indent=2, default=str)
    
    @classmethod
    def from_json(cls, filepath: str) -> 'ArtifactCollection':
        """Lädt aus JSON-Datei."""
        import json
        with open(filepath) as f:
            data = json.load(f)
        return cls(**data)


# Beispiel-Usage
if __name__ == "__main__":
    # Erstelle Artefakt
    artifact = Artifact(
        artifact_id="art_001",
        artifact_type=ArtifactType.FILE,
        source=ArtifactSource.TSK,
        name="suspicious.exe",
        path="/tmp/suspicious.exe",
        timestamp=datetime.now(),
        size=1024000,
        hash_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        metadata={"owner": "root"}
    )
    
    artifact.mark_suspicious("Found in /tmp directory")
    print(artifact.json(indent=2))
    
    # Erstelle Collection
    collection = ArtifactCollection(
        collection_id="col_001",
        name="Test Analysis",
        source_path="/evidence/disk.dd"
    )
    
    collection.add_artifact(artifact)
    print(f"Statistics: {collection.statistics}")