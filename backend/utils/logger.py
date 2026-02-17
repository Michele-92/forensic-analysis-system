"""
Logging Configuration.
Zentralisierte Logging-Konfiguration für das gesamte System.
"""

import logging
import sys
from pathlib import Path
from typing import Optional
from datetime import datetime
import json


class JSONFormatter(logging.Formatter):
    """Custom JSON-Formatter für strukturierte Logs."""
    
    def format(self, record: logging.LogRecord) -> str:
        """Formatiert Log-Record als JSON."""
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
    """Formatter mit Farben für Console-Output."""
    
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
        """Formatiert mit Farbe."""
        color = self.COLORS.get(record.levelname, self.RESET)
        record.levelname = f"{color}{record.levelname}{self.RESET}"
        return super().format(record)


def setup_logger(
    name: str = None,
    level: str = "INFO",
    log_file: Optional[Path] = None,
    console: bool = True,
    json_format: bool = False,
    colored: bool = True
) -> logging.Logger:
    """
    Konfiguriert Logger mit verschiedenen Optionen.
    
    Args:
        name: Logger-Name (None = Root-Logger)
        level: Log-Level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Pfad zur Log-Datei (optional)
        console: Console-Logging aktivieren
        json_format: JSON-Format für File-Logs
        colored: Farbige Console-Logs
    
    Returns:
        Konfigurierter Logger
    
    Example:
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
    
    # Verhindere Propagation zum Root-Logger
    logger.propagate = False
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Gibt existierenden Logger zurück oder erstellt neuen.
    
    Args:
        name: Logger-Name
    
    Returns:
        Logger-Instanz
    
    Example:
        >>> logger = get_logger(__name__)
        >>> logger.info("Test message")
    """
    return logging.getLogger(name)


class LoggerContext:
    """
    Context-Manager für temporäres Logging-Level.
    
    Example:
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
        self.logger.setLevel(self.old_level)


def log_function_call(logger: logging.Logger):
    """
    Decorator zum Loggen von Funktionsaufrufen.
    
    Example:
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
    Decorator zum Messen der Ausführungszeit.
    
    Example:
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


# Default Logger-Setup für das gesamte Backend
def setup_default_logging(base_dir: Path = None):
    """
    Initialisiert Standard-Logging für das Backend.
    
    Args:
        base_dir: Basis-Verzeichnis (default: aktuelles Verzeichnis)
    """
    if base_dir is None:
        base_dir = Path.cwd()
    
    log_dir = base_dir / "logs"
    log_dir.mkdir(exist_ok=True)
    
    # Root-Logger
    setup_logger(
        name=None,
        level="INFO",
        log_file=log_dir / "forensic.log",
        console=True,
        colored=True
    )
    
    # Module-spezifische Logger
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


# Beispiel-Usage
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