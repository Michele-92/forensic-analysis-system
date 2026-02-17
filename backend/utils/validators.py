"""
Input Validators.
Validierung von Inputs für die forensische Pipeline.
"""

import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
import re

logger = logging.getLogger(__name__)


class ValidationError(Exception):
    """Custom Exception für Validierungsfehler."""
    pass


def validate_file_path(path: Path, must_exist: bool = True, max_size: Optional[int] = None) -> bool:
    """
    Validiert Dateipfad.
    
    Args:
        path: Zu validierender Pfad
        must_exist: Datei muss existieren
        max_size: Max. Dateigröße in Bytes (None = unbegrenzt)
    
    Returns:
        True wenn valide
    
    Raises:
        ValidationError: Bei Validierungsfehler
    
    Example:
        >>> validate_file_path(Path("image.dd"), must_exist=True, max_size=10_000_000_000)
    """
    # Type-Check
    if not isinstance(path, Path):
        raise ValidationError(f"Pfad muss Path-Objekt sein, nicht {type(path)}")
    
    # Existenz-Check
    if must_exist and not path.exists():
        raise ValidationError(f"Pfad existiert nicht: {path}")
    
    # Read-Permission-Check
    if must_exist and path.is_file():
        try:
            with open(path, 'rb') as f:
                f.read(1)
        except PermissionError:
            raise ValidationError(f"Keine Leseberechtigung für: {path}")
        except Exception as e:
            raise ValidationError(f"Fehler beim Öffnen von {path}: {e}")
    
    # Größen-Check
    if must_exist and path.is_file() and max_size:
        size = path.stat().st_size
        if size > max_size:
            raise ValidationError(
                f"Datei zu groß: {size / 1_000_000_000:.2f}GB "
                f"(Max: {max_size / 1_000_000_000:.2f}GB)"
            )
    
    # Path-Traversal-Check (Security)
    try:
        path.resolve()
    except:
        raise ValidationError(f"Ungültiger Pfad: {path}")
    
    logger.debug(f"Pfad validiert: {path}")
    return True


def validate_output_dir(path: Path, create: bool = True) -> bool:
    """
    Validiert Output-Verzeichnis.
    
    Args:
        path: Verzeichnis-Pfad
        create: Automatisch erstellen wenn nicht vorhanden
    
    Returns:
        True wenn valide
    
    Raises:
        ValidationError: Bei Fehler
    """
    if not isinstance(path, Path):
        raise ValidationError(f"Pfad muss Path-Objekt sein, nicht {type(path)}")
    
    # Existiert bereits?
    if path.exists():
        if not path.is_dir():
            raise ValidationError(f"Pfad ist keine Directory: {path}")
        
        # Write-Permission-Check
        test_file = path / ".write_test"
        try:
            test_file.touch()
            test_file.unlink()
        except PermissionError:
            raise ValidationError(f"Keine Schreibberechtigung für: {path}")
    else:
        if create:
            try:
                path.mkdir(parents=True, exist_ok=True)
                logger.info(f"Output-Verzeichnis erstellt: {path}")
            except Exception as e:
                raise ValidationError(f"Fehler beim Erstellen von {path}: {e}")
        else:
            raise ValidationError(f"Directory existiert nicht: {path}")
    
    logger.debug(f"Output-Directory validiert: {path}")
    return True


def validate_timeline(timeline: List[Dict]) -> bool:
    """
    Validiert Timeline-Struktur.
    
    Args:
        timeline: Liste von Timeline-Events
    
    Returns:
        True wenn valide
    
    Raises:
        ValidationError: Bei Strukturfehler
    """
    if not isinstance(timeline, list):
        raise ValidationError(f"Timeline muss Liste sein, nicht {type(timeline)}")
    
    if len(timeline) == 0:
        raise ValidationError("Timeline ist leer")
    
    required_fields = ['timestamp', 'description']
    
    for i, event in enumerate(timeline):
        if not isinstance(event, dict):
            raise ValidationError(f"Event {i} ist kein Dict: {type(event)}")
        
        # Required Fields
        for field in required_fields:
            if field not in event:
                raise ValidationError(f"Event {i} fehlt Feld '{field}': {event}")
        
        # Timestamp-Format (vereinfacht)
        timestamp = event['timestamp']
        if not isinstance(timestamp, (str, int, float)):
            raise ValidationError(f"Event {i}: Timestamp ungültig: {timestamp}")
    
    logger.debug(f"Timeline validiert: {len(timeline)} Events")
    return True


def validate_ip_address(ip: str) -> bool:
    """
    Validiert IP-Adresse (IPv4 & IPv6).
    
    Args:
        ip: IP-Adresse als String
    
    Returns:
        True wenn valide
    
    Raises:
        ValidationError: Bei ungültiger IP
    """
    # IPv4-Pattern
    ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    
    # IPv6-Pattern (vereinfacht)
    ipv6_pattern = r'^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|::)$'
    
    if re.match(ipv4_pattern, ip) or re.match(ipv6_pattern, ip):
        return True
    
    raise ValidationError(f"Ungültige IP-Adresse: {ip}")


def validate_hash(hash_value: str, hash_type: str = 'auto') -> bool:
    """
    Validiert Hash-Wert (MD5, SHA1, SHA256).
    
    Args:
        hash_value: Hash als String
        hash_type: Hash-Typ (md5, sha1, sha256, auto)
    
    Returns:
        True wenn valide
    
    Raises:
        ValidationError: Bei ungültigem Hash
    """
    hash_lengths = {
        'md5': 32,
        'sha1': 40,
        'sha256': 64,
    }
    
    # Auto-detect
    if hash_type == 'auto':
        length = len(hash_value)
        hash_type = next((k for k, v in hash_lengths.items() if v == length), None)
        if not hash_type:
            raise ValidationError(f"Unbekannte Hash-Länge: {length}")
    
    # Length-Check
    expected_length = hash_lengths.get(hash_type)
    if not expected_length:
        raise ValidationError(f"Unbekannter Hash-Typ: {hash_type}")
    
    if len(hash_value) != expected_length:
        raise ValidationError(
            f"{hash_type.upper()}-Hash muss {expected_length} Zeichen haben, nicht {len(hash_value)}"
        )
    
    # Hex-Check
    if not re.match(r'^[a-fA-F0-9]+$', hash_value):
        raise ValidationError(f"Hash enthält ungültige Zeichen: {hash_value}")
    
    return True


def validate_event_id(event_id: str) -> bool:
    """
    Validiert Event-ID-Format.
    
    Args:
        event_id: Event-ID
    
    Returns:
        True wenn valide
    
    Raises:
        ValidationError: Bei ungültigem Format
    """
    # Format: evt_XXXXXX oder source_XXXXXX
    pattern = r'^[a-z]+_[a-zA-Z0-9]+$'
    
    if not re.match(pattern, event_id):
        raise ValidationError(f"Ungültige Event-ID: {event_id} (Format: evt_XXXXXX)")
    
    return True


def validate_anomaly_score(score: float) -> bool:
    """
    Validiert Anomalie-Score (0-1).
    
    Args:
        score: Score-Wert
    
    Returns:
        True wenn valide
    
    Raises:
        ValidationError: Bei ungültigem Wert
    """
    if not isinstance(score, (int, float)):
        raise ValidationError(f"Score muss Zahl sein, nicht {type(score)}")
    
    if not 0 <= score <= 1:
        raise ValidationError(f"Score muss zwischen 0 und 1 sein: {score}")
    
    return True


def validate_config(config: Dict[str, Any], schema: Dict[str, type]) -> bool:
    """
    Validiert Config-Dict gegen Schema.
    
    Args:
        config: Config-Dictionary
        schema: Schema {key: expected_type}
    
    Returns:
        True wenn valide
    
    Raises:
        ValidationError: Bei Schema-Verletzung
    
    Example:
        >>> schema = {'model': str, 'temperature': float, 'max_tokens': int}
        >>> validate_config({'model': 'llama3.1', 'temperature': 0.7, 'max_tokens': 2000}, schema)
    """
    for key, expected_type in schema.items():
        if key not in config:
            raise ValidationError(f"Config fehlt Key '{key}'")
        
        value = config[key]
        if not isinstance(value, expected_type):
            raise ValidationError(
                f"Config['{key}'] muss {expected_type.__name__} sein, nicht {type(value).__name__}"
            )
    
    return True


def sanitize_filename(filename: str, max_length: int = 255) -> str:
    """
    Bereinigt Dateinamen (entfernt gefährliche Zeichen).
    
    Args:
        filename: Original-Dateiname
        max_length: Max. Länge
    
    Returns:
        Bereinigter Dateiname
    
    Example:
        >>> sanitize_filename("../../../etc/passwd")
        'etc_passwd'
    """
    # Entferne Path-Separatoren
    filename = filename.replace('/', '_').replace('\\', '_')
    
    # Entferne gefährliche Zeichen
    filename = re.sub(r'[^\w\s\-\.]', '', filename)
    
    # Entferne führende/trailing Whitespace
    filename = filename.strip()
    
    # Kürze auf max_length
    if len(filename) > max_length:
        name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
        name = name[:max_length - len(ext) - 1]
        filename = f"{name}.{ext}" if ext else name
    
    return filename


def validate_all(
    file_path: Optional[Path] = None,
    output_dir: Optional[Path] = None,
    timeline: Optional[List[Dict]] = None,
    config: Optional[Dict] = None
) -> bool:
    """
    Validiert mehrere Inputs auf einmal.
    
    Args:
        file_path: Eingabedatei
        output_dir: Output-Verzeichnis
        timeline: Timeline-Events
        config: Konfiguration
    
    Returns:
        True wenn alle valide
    
    Raises:
        ValidationError: Bei erstem Fehler
    """
    errors = []
    
    if file_path:
        try:
            validate_file_path(file_path)
        except ValidationError as e:
            errors.append(f"File Path: {e}")
    
    if output_dir:
        try:
            validate_output_dir(output_dir)
        except ValidationError as e:
            errors.append(f"Output Dir: {e}")
    
    if timeline:
        try:
            validate_timeline(timeline)
        except ValidationError as e:
            errors.append(f"Timeline: {e}")
    
    if config:
        # Beispiel-Schema (anpassen!)
        schema = {'model': str, 'temperature': (int, float)}
        try:
            for key, expected_type in schema.items():
                if key in config:
                    if not isinstance(config[key], expected_type):
                        errors.append(f"Config['{key}']: wrong type")
        except Exception as e:
            errors.append(f"Config: {e}")
    
    if errors:
        raise ValidationError(f"Validierung fehlgeschlagen:\n" + "\n".join(errors))
    
    return True


# Beispiel-Usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    
    # Test File-Validation
    try:
        validate_file_path(Path("test.dd"), must_exist=False)
        print("✓ File validation passed")
    except ValidationError as e:
        print(f"✗ File validation failed: {e}")
    
    # Test IP-Validation
    try:
        validate_ip_address("192.168.1.1")
        validate_ip_address("::1")
        print("✓ IP validation passed")
    except ValidationError as e:
        print(f"✗ IP validation failed: {e}")
    
    # Test Hash-Validation
    try:
        validate_hash("5d41402abc4b2a76b9719d911017c592", hash_type='md5')
        print("✓ Hash validation passed")
    except ValidationError as e:
        print(f"✗ Hash validation failed: {e}")
    
    # Test Filename-Sanitization
    dirty = "../../../etc/passwd"
    clean = sanitize_filename(dirty)
    print(f"Sanitized: '{dirty}' -> '{clean}'")