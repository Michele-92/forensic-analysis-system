"""
Evidence Tracker — Chain of Custody / Beweismittel-Integritaet.

Berechnet SHA256-Hashes fuer hochgeladene Dateien, fuehrt einen Audit-Trail
und ermoeglicht spaetere Verifikation der Datei-Integritaet.
"""

import hashlib
import logging
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)

CHUNK_SIZE = 8192  # 8 KB


class EvidenceTracker:
    """Statische Methoden fuer Beweismittel-Integritaet."""

    @staticmethod
    def compute_hash(file_path: Path) -> str:
        """Berechnet SHA256-Hash einer Datei in Chunks."""
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(CHUNK_SIZE):
                sha256.update(chunk)
        file_hash = sha256.hexdigest()
        logger.info(f"SHA256 berechnet: {file_hash[:16]}... ({file_path.name})")
        return file_hash

    @staticmethod
    def verify_hash(file_path: Path, expected_hash: str) -> bool:
        """Verifiziert ob eine Datei noch dem erwarteten Hash entspricht."""
        current_hash = EvidenceTracker.compute_hash(file_path)
        verified = current_hash == expected_hash
        if verified:
            logger.info(f"Hash-Verifikation BESTANDEN: {file_path.name}")
        else:
            logger.warning(
                f"Hash-Verifikation FEHLGESCHLAGEN: {file_path.name} "
                f"(erwartet={expected_hash[:16]}..., aktuell={current_hash[:16]}...)"
            )
        return verified

    @staticmethod
    def create_audit_entry(event: str, details: dict = None) -> dict:
        """Erstellt einen Audit-Trail-Eintrag."""
        return {
            "timestamp": datetime.now().isoformat(),
            "event": event,
            "details": details or {},
        }
