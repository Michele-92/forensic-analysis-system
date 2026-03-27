"""
================================================================================
DATA NORMALIZER — Vereinheitlichung forensischer Event-Daten
================================================================================
Konvertiert heterogene Rohdaten aus verschiedenen forensischen Quellen in ein
einheitliches Event-Schema für die nachgelagerte Anomalie-Erkennung und
LLM-Analyse.

Unterstützte Quellformate:
    - UAC (Unix Artifact Collector) — Linux/macOS Artifact-Dumps
    - Dissect               — Disk-Image Parser (MFT, EventLogs, Registry)
    - Sleuth Kit (tsk)      — Filesystem-Timeline aus Disk-Images
    - Log-Parser            — Syslog, Apache, Audit, Firewall, etc.

Verwendung:
    artifacts = {
        'dissect': [{'path': '/etc/passwd', 'mtime': 1700000000, ...}],
        'tsk':     [{'inode': 42, 'name': 'evil.exe', 'size': 8192, ...}],
        'uac':     [{'message': 'Failed login', 'timestamp': '2024-01-01T03:00'}],
    }
    events = DataNormalizer.normalize_artifacts(artifacts)
    # events: Liste von dicts mit einheitlichem Schema

Ausgabe-Schema (jedes Event):
    {
        'event_id':    str,   # Eindeutige ID (z.B. "dissect_42" oder Hash)
        'timestamp':   str,   # ISO 8601 (z.B. "2024-01-01T03:14:00")
        'event_type':  str,   # z.B. 'file_system', 'auth_event', 'windows_event'
        'source':      str,   # 'dissect' | 'uac' | 'tsk' | 'logs'
        'description': str,   # Menschenlesbare Beschreibung des Events
        'metadata':    dict,  # Quellenspezifische Zusatzdaten (Pfad, Größe, etc.)
        'anomaly_score': float  # 0.0–1.0 (wird in Pipeline Stage 6 gesetzt)
    }

Abhängigkeiten:
    - Standard-Library (datetime)
    - pandas (für Timestamp-Konvertierung im DataFrame)

Kontext: LFX Forensic Analysis System — Pipeline Stage 5 (Normalisierung)
"""

import logging
from typing import Dict, List, Any
from datetime import datetime
import pandas as pd

# ── Modul-Logger ───────────────────────────────────────────────────────────────
# Nutzt den Python-Standard-Logging-Mechanismus; Ausgabe wird vom Root-Logger
# in pipeline.py / api.py konfiguriert (Level, Format, Handler).
logger = logging.getLogger(__name__)


# ── Haupt-Klasse ───────────────────────────────────────────────────────────────

class DataNormalizer:
    """
    Normalisiert forensische Daten aus verschiedenen Quellen zu einem
    einheitlichen Schema.

    Alle Methoden sind als @staticmethod implementiert, da die Klasse
    keinen internen Zustand verwaltet — sie dient lediglich als
    Namensraum für verwandte Transformations-Funktionen.

    Typischer Aufruf-Pfad in der Pipeline:
        normalize_artifacts() → normalize_timeline_event() → _normalize_timestamp()
                                                           → _infer_event_type()
                                                           → _create_description()
    """

    @staticmethod
    def normalize_timeline_event(event: Dict, source: str) -> Dict:
        """
        Normalisiert ein einzelnes Timeline-Event in das Standard-Schema.

        Liest die relevanten Felder aus dem quellenspezifischen Rohformat
        und befüllt das vereinheitlichte Schema. Felder, die nicht Teil
        des Kern-Schemas sind, werden in 'metadata' übernommen.

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
            event:  Original-Event-Dict aus einer forensischen Quelle.
            source: Bezeichner der Datenquelle ('uac', 'dissect', 'tsk', etc.)

        Returns:
            Normalisiertes Event-Dict im einheitlichen Schema.
        """
        normalized = {
            # Eindeutige ID: Quelle + Inode (falls vorhanden) oder Hash des Events
            'event_id': f"{source}_{event.get('inode', hash(str(event)))}",
            # Zeitstempel: aus 'mtime' (Filesystem) oder 'timestamp' (Logs), dann zu ISO-8601
            'timestamp': DataNormalizer._normalize_timestamp(
                event.get('mtime') or event.get('timestamp')
            ),
            # Event-Typ: wird heuristisch aus den vorhandenen Feldern abgeleitet
            'event_type': DataNormalizer._infer_event_type(event),
            'source': source,
            # Menschenlesbare Beschreibung für LLM und UI
            'description': DataNormalizer._create_description(event),
            # Alle übrigen Felder als Rohdaten aufbewahren (für spätere Anreicherung)
            'metadata': {
                k: v for k, v in event.items()
                if k not in ['mtime', 'timestamp', 'event_id']
            }
        }

        return normalized

    @staticmethod
    def _normalize_timestamp(ts: Any) -> str:
        """
        Konvertiert verschiedene Timestamp-Formate zu ISO-8601-String.

        Behandelt die in forensischen Tools üblichen Formate:
        - None         → aktueller Zeitstempel (Fallback)
        - str          → unverändert übernommen (bereits formatiert)
        - int / float  → Unix-Epoch-Sekunden (z.B. aus Sleuth Kit / MFT)
        - datetime     → direkte .isoformat()-Konvertierung

        Args:
            ts: Roher Zeitstempel in beliebigem Format.

        Returns:
            ISO-8601-String (z.B. "2024-01-15T03:14:07.123456").
        """
        if ts is None:
            return datetime.now().isoformat()

        if isinstance(ts, str):
            return ts

        if isinstance(ts, (int, float)):
            # Unix-Timestamp
            return datetime.fromtimestamp(ts).isoformat()

        if isinstance(ts, datetime):
            return ts.isoformat()

        # Letzter Ausweg: String-Konvertierung
        return str(ts)

    @staticmethod
    def _infer_event_type(event: Dict) -> str:
        """
        Leitet den Event-Typ heuristisch aus den vorhandenen Feldern ab.

        Priorität (von hoch nach niedrig):
        1. Vorhandenes 'event_type'-Feld (z.B. vom LogParser gesetzt, sofern
           nicht Platzhalterwert wie 'unknown' oder 'log_entry')
        2. 'event_id'-Feld → Windows Event Log
        3. 'inode'-Feld   → Filesystem-Event (Sleuth Kit / Dissect)
        4. 'provider'-Feld → generischer Log-Eintrag
        5. Fallback       → 'unknown'

        Args:
            event: Rohes Event-Dict.

        Returns:
            Event-Typ-String, kompatibel mit EVENT_TYPE_SCORES in anomaly_detector.py.
        """
        # LogParser setzt bereits spezifische event_types (auth_failure, ssh_event, etc.)
        if 'event_type' in event and event['event_type'] not in ('unknown', 'log_entry', ''):
            return event['event_type']
        elif 'event_id' in event:
            return 'windows_event'
        elif 'inode' in event:
            return 'file_system'
        elif 'provider' in event:
            return 'log_entry'
        else:
            return 'unknown'

    @staticmethod
    def _create_description(event: Dict) -> str:
        """
        Erstellt eine menschenlesbare Kurzbeschreibung für das Event.

        Wird als Primärtext in der UI und als Eingabe für den LLM verwendet.
        Greift auf die aussagekräftigsten verfügbaren Felder zurück.

        Args:
            event: Rohes Event-Dict.

        Returns:
            Beschreibungsstring (z.B. "regular: /etc/passwd" oder "File: evil.exe").
        """
        if 'message' in event:
            return event['message']

        if 'path' in event and 'type' in event:
            return f"{event['type']}: {event['path']}"

        if 'name' in event:
            return f"File: {event['name']}"

        # Letzter Ausweg: vollständige Dict-Darstellung
        return str(event)

    @staticmethod
    def normalize_artifacts(artifacts: Dict[str, List[Dict]]) -> List[Dict]:
        """
        Normalisiert alle Artefakte aus mehreren Quellen in einer Batch-Operation.

        Iteriert über alle Quellen (uac, dissect, tsk, ...) und deren Events.
        Fehler bei einzelnen Events werden geloggt, aber nicht abgebrochen —
        robuste Verarbeitung auch bei heterogenen/fehlerhaften Eingaben.

        Args:
            artifacts: Dict mit Artefakten pro Quelle:
                {
                    'uac':     [event_dict, ...],
                    'dissect': [event_dict, ...],
                    'tsk':     [event_dict, ...]
                }

        Returns:
            Flache Liste normalisierter Event-Dicts im einheitlichen Schema.
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
        Entfernt doppelte Events aus der Timeline.

        Ein Duplikat wird erkannt, wenn Timestamp UND Beschreibung identisch
        sind. Dies verhindert, dass das gleiche Ereignis durch mehrere
        Quellen (z.B. Dissect + Log-Parser) doppelt gezählt wird.

        Args:
            events: Liste von normalisierten Events.

        Returns:
            Deduplizierte Liste (Reihenfolge bleibt erhalten).
        """
        seen = set()
        unique = []

        for event in events:
            # Schlüssel: Kombination aus Zeitpunkt und Inhalt
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
        Reichert alle Events mit einem gemeinsamen Kontext-Dict an.

        Der Kontext kann z.B. System-Informationen, erkannte IOCs oder
        Metadaten über die Analysesitzung enthalten. Das Feld 'context'
        wird an jedes Event angehängt und steht dem LLM bei der Analyse
        zur Verfügung.

        Args:
            events:  Liste von normalisierten Events.
            context: Zusätzlicher Kontext (z.B. System-Info, IOC-Liste).

        Returns:
            Events mit 'context'-Feld (in-place modifiziert + zurückgegeben).
        """
        for event in events:
            event['context'] = context

        return events

    @staticmethod
    def to_dataframe(events: List[Dict]) -> pd.DataFrame:
        """
        Konvertiert die Event-Liste in einen Pandas DataFrame.

        Nützlich für explorative Analyse, CSV-Export und die Feature-
        Extraktion im AnomalyDetector. Der Timestamp wird automatisch
        von String zu datetime64 konvertiert.

        Args:
            events: Liste von normalisierten Events.

        Returns:
            pandas.DataFrame mit einer Zeile pro Event.
            Spalten entsprechen den Schlüsseln des Event-Schemas.
        """
        df = pd.DataFrame(events)

        # Konvertiere Timestamp zu datetime für Zeitreihen-Analysen
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])

        return df
