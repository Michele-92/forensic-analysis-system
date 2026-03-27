"""
================================================================================
LOGGER — Zentralisierte Logging-Konfiguration
================================================================================
Stellt alle benötigten Logging-Komponenten für das Backend bereit.
Anstatt in jedem Modul `logging.basicConfig()` aufzurufen, wird hier
eine einheitliche Konfiguration definiert, die über `setup_logger()`
oder `setup_default_logging()` aktiviert wird.

Aufgaben:
    - Strukturierte JSON-Logs für Produktions-Umgebungen (Log-Aggregatoren)
    - Farbige Konsolen-Logs für den Development-Betrieb
    - Konfigurierbare Log-Level pro Logger-Instanz
    - Context-Manager für temporäre Level-Änderungen (z.B. in Tests)
    - Decorator-Utilities zum automatischen Loggen von Funktionsaufrufen
      und Ausführungszeiten

Verwendung:
    # Einmalig beim Start des Backends:
    from utils.logger import setup_default_logging
    setup_default_logging(base_dir=BASE_DIR)

    # In jedem Modul:
    from utils.logger import get_logger
    logger = get_logger(__name__)
    logger.info("Analyse gestartet")

Abhängigkeiten:
    - logging, sys, pathlib, datetime, json (stdlib)

Kontext: LFX Forensic Analysis System — Bachelor-Arbeit Forensik-Tool
"""

import logging
import sys
from pathlib import Path
from typing import Optional
from datetime import datetime
import json


# ── Formatter-Klassen ─────────────────────────────────────────────────────────

class JSONFormatter(logging.Formatter):
    """
    Formatiert Log-Einträge als JSON-Objekte.

    Geeignet für Produktions-Deployments, bei denen Logs in einen
    zentralen Log-Aggregator (z.B. ELK-Stack, Grafana Loki) geleitet
    werden und maschinell durchsucht werden müssen.

    Jede Zeile im Log ist ein vollständiges, valides JSON-Objekt mit
    Timestamp, Level, Logger-Name, Nachricht, Modul, Funktion und Zeile.
    Exception-Tracebacks und beliebige Extra-Felder werden ebenfalls
    ins JSON eingebettet.
    """

    def format(self, record: logging.LogRecord) -> str:
        """
        Serialisiert einen LogRecord als JSON-String.

        Args:
            record: Standard Python LogRecord-Objekt

        Returns:
            JSON-String (eine Zeile) mit allen Pflicht- und optionalen Feldern
        """
        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
        }

        # Exception-Info
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)

        # Extra-Fields
        if hasattr(record, 'extra'):
            log_data['extra'] = record.extra

        return json.dumps(log_data)


class ColoredFormatter(logging.Formatter):
    """
    Formatter der Log-Level farbig in der Konsole hervorhebt.

    Verwendet ANSI-Escape-Codes. Funktioniert in allen Standard-Terminals
    (Linux, macOS, Windows Terminal). In klassischen Windows-CMD-Fenstern
    ohne ANSI-Unterstützung erscheinen die Escape-Codes als Sonderzeichen —
    in diesem Fall `colored=False` in setup_logger() setzen.
    """

    # ANSI-Color-Codes
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
    }
    RESET = '\033[0m'

    def format(self, record: logging.LogRecord) -> str:
        """
        Fügt ANSI-Farbcode um den Level-Namen ein und delegiert
        die restliche Formatierung an den Parent-Formatter.

        Args:
            record: Standard Python LogRecord-Objekt

        Returns:
            Formatierter String mit Farb-Codes um den Level-Namen
        """
        color = self.COLORS.get(record.levelname, self.RESET)
        record.levelname = f"{color}{record.levelname}{self.RESET}"
        return super().format(record)


# ── Kern-Funktion: Logger erstellen ──────────────────────────────────────────

def setup_logger(
    name: str = None,
    level: str = "INFO",
    log_file: Optional[Path] = None,
    console: bool = True,
    json_format: bool = False,
    colored: bool = True
) -> logging.Logger:
    """
    Erstellt und konfiguriert eine Logger-Instanz mit den gewünschten Optionen.

    Unterstützt gleichzeitig Konsolen- und Datei-Ausgabe mit unabhängigen
    Formatierern. Bestehende Handler werden beim Aufruf entfernt, um
    doppelte Log-Ausgaben bei wiederholtem Aufruf zu vermeiden.

    Args:
        name:        Logger-Name. None → Root-Logger (alle Namespaces erben davon).
                     Empfehlung: __name__ des aufrufenden Moduls verwenden.
        level:       Log-Level als String: 'DEBUG' | 'INFO' | 'WARNING' | 'ERROR' | 'CRITICAL'
        log_file:    Optionaler Pfad zur Log-Datei. Das Eltern-Verzeichnis wird
                     automatisch erstellt. None → kein File-Logging.
        console:     True = Logs werden auf stdout ausgegeben
        json_format: True = File-Logs im JSON-Format (für Produktions-Deployment)
                     False = File-Logs im lesbaren Text-Format (für Development)
        colored:     True = Level-Namen in der Konsole farbig hervorheben

    Returns:
        Konfigurierter logging.Logger

    Beispiel:
        >>> logger = setup_logger('forensic', level='DEBUG', log_file=Path('logs/forensic.log'))
        >>> logger.info("Analysis started")
    """
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper()))

    # Remove existing handlers
    logger.handlers.clear()

    # Console-Handler
    if console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(getattr(logging, level.upper()))

        if colored:
            console_formatter = ColoredFormatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
        else:
            console_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )

        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)

    # File-Handler
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(getattr(logging, level.upper()))

        if json_format:
            file_formatter = JSONFormatter()
        else:
            file_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(module)s:%(funcName)s:%(lineno)d - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )

        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

    # Verhindere Propagation zum Root-Logger um doppelte Ausgaben zu vermeiden,
    # wenn dieser Logger eigene Handler hat
    logger.propagate = False

    return logger


# ── Convenience-Funktion ─────────────────────────────────────────────────────

def get_logger(name: str) -> logging.Logger:
    """
    Gibt eine bestehende Logger-Instanz zurück (oder erstellt eine neue,
    falls noch keine für diesen Namen existiert).

    Dies ist die bevorzugte Methode, um in einzelnen Modulen einen Logger
    zu erhalten — ohne Konfiguration, nur Referenz auf den zentralen Logger.

    Args:
        name: Logger-Name, typischerweise __name__ des aufrufenden Moduls

    Returns:
        logging.Logger-Instanz (ggf. noch unkonfiguriert — erbt dann von Root)

    Beispiel:
        >>> logger = get_logger(__name__)
        >>> logger.info("Test message")
    """
    return logging.getLogger(name)


# ── Utilities ─────────────────────────────────────────────────────────────────

class LoggerContext:
    """
    Context-Manager zum temporären Ändern des Log-Levels eines Loggers.

    Nützlich in Tests, wenn für einen bestimmten Code-Block ein
    niedrigerer Level (DEBUG) benötigt wird, ohne den restlichen
    Output zu überfüllen.

    Beispiel:
        >>> logger = get_logger(__name__)
        >>> with LoggerContext(logger, level='DEBUG'):
        ...     logger.debug("This will be logged")
    """

    def __init__(self, logger: logging.Logger, level: str):
        self.logger = logger
        self.new_level = getattr(logging, level.upper())
        self.old_level = logger.level

    def __enter__(self):
        self.logger.setLevel(self.new_level)
        return self.logger

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Level immer zurücksetzen — auch bei Exceptions im with-Block
        self.logger.setLevel(self.old_level)


def log_function_call(logger: logging.Logger):
    """
    Decorator-Factory: Loggt Aufruf und Rückgabewert einer Funktion auf DEBUG-Level.

    Bei Exceptions wird der Fehler auf ERROR geloggt und die Exception
    erneut geworfen (kein Schlucken von Fehlern).

    Args:
        logger: Logger-Instanz, die für die Ausgabe verwendet wird

    Beispiel:
        >>> logger = get_logger(__name__)
        >>> @log_function_call(logger)
        ... def my_function(x, y):
        ...     return x + y
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            logger.debug(f"Calling {func.__name__} with args={args}, kwargs={kwargs}")
            try:
                result = func(*args, **kwargs)
                logger.debug(f"{func.__name__} returned {result}")
                return result
            except Exception as e:
                logger.error(f"{func.__name__} raised {type(e).__name__}: {e}")
                raise
        return wrapper
    return decorator


def log_execution_time(logger: logging.Logger):
    """
    Decorator-Factory: Misst und loggt die Ausführungszeit einer Funktion.

    Die Laufzeit wird nach Abschluss der Funktion auf INFO-Level ausgegeben.
    Exceptions unterbrechen die Zeitmessung und werden nicht abgefangen.

    Args:
        logger: Logger-Instanz, die für die Ausgabe verwendet wird

    Beispiel:
        >>> logger = get_logger(__name__)
        >>> @log_execution_time(logger)
        ... def slow_function():
        ...     import time
        ...     time.sleep(1)
    """
    import time

    def decorator(func):
        def wrapper(*args, **kwargs):
            start = time.time()
            result = func(*args, **kwargs)
            elapsed = time.time() - start
            logger.info(f"{func.__name__} took {elapsed:.3f}s")
            return result
        return wrapper
    return decorator


# ── Standard-Setup für das gesamte Backend ───────────────────────────────────

def setup_default_logging(base_dir: Path = None):
    """
    Initialisiert das Standard-Logging für alle Backend-Komponenten.

    Richtet einen Root-Logger (INFO, Konsole + Datei) und pro Backend-Modul
    einen dedizierten Logger (DEBUG, JSON-Datei) ein. Sollte einmalig beim
    Start des FastAPI-Servers oder der CLI-Pipeline aufgerufen werden.

    Erzeugte Log-Dateien (im logs/-Verzeichnis):
        forensic.log    — Aggregierter Root-Log (text)
        pipeline.log    — Pipeline-Events (JSON)
        api.log         — HTTP-Request-Events (JSON)
        llm_agent.log   — LLM-Kommunikation (JSON)
        modules.log     — Normalizer, Anomaly-Detector etc. (JSON)

    Args:
        base_dir: Projekt-Wurzelverzeichnis. None → aktuelles Arbeitsverzeichnis.
    """
    if base_dir is None:
        base_dir = Path.cwd()

    log_dir = base_dir / "logs"
    log_dir.mkdir(exist_ok=True)

    # Root-Logger: INFO auf Konsole + in forensic.log (text)
    setup_logger(
        name=None,
        level="INFO",
        log_file=log_dir / "forensic.log",
        console=True,
        colored=True
    )

    # Module-spezifische Logger: DEBUG, kein Konsolen-Output, JSON-Format.
    # Jedes Modul bekommt eine eigene Log-Datei für gezielte Fehlersuche.
    modules = [
        'backend.pipeline',
        'backend.api',
        'backend.llm_agent',
        'backend.modules',
    ]

    for module in modules:
        setup_logger(
            name=module,
            level="DEBUG",
            log_file=log_dir / f"{module.split('.')[-1]}.log",
            console=False,
            json_format=True
        )


# ── Direkt-Ausführung (manuelle Tests) ───────────────────────────────────────
if __name__ == "__main__":
    # Setup
    setup_default_logging()

    # Test verschiedene Logger
    logger = get_logger(__name__)

    logger.debug("Debug message")
    logger.info("Info message")
    logger.warning("Warning message")
    logger.error("Error message")

    # Test mit Context
    with LoggerContext(logger, level='DEBUG'):
        logger.debug("This is visible in DEBUG context")

    # Test mit Decorator
    @log_execution_time(logger)
    def test_function():
        import time
        time.sleep(0.1)
        return "done"

    test_function()
