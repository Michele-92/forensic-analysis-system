"""
================================================================================
EVIDENCE TRACKER — Chain of Custody / Beweismittel-Integrität
================================================================================
Stellt kryptografische Werkzeuge zur Sicherstellung der Beweismittel-Integrität
in digitalen forensischen Analysen bereit.

Kernfunktionen:
    - Berechnung von MD5- und SHA256-Prüfsummen für Beweisdateien
    - Verifikation von Hashes gegen gespeicherte Referenzwerte
    - Erstellung strukturierter Audit-Trail-Einträge

Chain of Custody Bedeutung:
    In gerichtlichen Verfahren muss nachgewiesen werden, dass Beweismittel
    unverändert geblieben sind. Durch Hashdokumentation bei Eingang,
    Verarbeitung und Ausgabe lässt sich jede unbeabsichtigte oder absichtliche
    Veränderung einer Datei lückenlos nachweisen.

Dual-Hash-Strategie:
    MD5    — Schnell, weit verbreitet, kompatibel mit forensischen Tools
             (Autopsy, FTK, EnCase). Nicht mehr kollisionssicher, aber für
             Integritätsprüfung im forensischen Kontext ausreichend.
    SHA256 — Kryptografisch sicher, gerichtsfest. Gilt als moderner Standard
             für forensische Hash-Dokumentation.

Verwendung:
    tracker = EvidenceTracker()

    # Hashes bei Eingang berechnen und speichern
    hashes = EvidenceTracker.compute_dual_hash(Path("/evidence/disk.dd"))
    # → {"md5": "d41d8cd98f00b204e9800998ecf8427e", "sha256": "e3b0c44298fc..."}

    # Nach Verarbeitung: Integrität prüfen
    result = EvidenceTracker.verify_dual_hash(Path("/evidence/disk.dd"), hashes)
    # → {"md5_verified": True, "sha256_verified": True, "overall": True, ...}

    # Audit-Trail-Eintrag anlegen
    entry = EvidenceTracker.create_audit_entry("upload", {"job_id": "abc-123"})
    # → {"timestamp": "2024-01-15T03:14:07", "event": "upload", "details": {...}}

Abhängigkeiten:
    - Standard-Library (hashlib, pathlib, datetime)

Kontext: LFX Forensic Analysis System — Querschnittsmodul (Integrität)
         Wird in pipeline.py bei Datei-Eingang und -Export aufgerufen.
"""

import hashlib
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict

# ── Modul-Logger ───────────────────────────────────────────────────────────────
logger = logging.getLogger(__name__)

# ── Konstanten ─────────────────────────────────────────────────────────────────
# Chunk-Größe für das blockweise Einlesen großer Dateien.
# 8 KB ist ein guter Kompromiss zwischen Speichernutzung und I/O-Effizienz.
# Ermöglicht das Hashen von Disk-Images (mehrere GB) ohne Speicherprobleme.
CHUNK_SIZE = 8192  # 8 KB


# ── Haupt-Klasse ───────────────────────────────────────────────────────────────

class EvidenceTracker:
    """
    Stellt statische Methoden für forensische Beweismittel-Integrität bereit.

    Alle Methoden sind als @staticMethod implementiert — die Klasse dient
    als Namensraum für verwandte Integritätsfunktionen ohne eigenen Zustand.

    Typischer Anwendungsfall in der Pipeline:
        1. Datei-Upload:   compute_dual_hash() → Hashes in Job-Metadaten speichern
        2. Nach Analyse:   verify_dual_hash()  → Integrität bestätigen
        3. Jeder Schritt:  create_audit_entry() → Audit-Trail fortschreiben
    """

    @staticmethod
    def compute_dual_hash(file_path: Path) -> Dict[str, str]:
        """
        Berechnet MD5- und SHA256-Hash einer Datei in einem einzigen Lesedurchlauf.

        Liest die Datei blockweise (CHUNK_SIZE = 8 KB), um auch sehr große
        Disk-Images (mehrere GB) effizient zu verarbeiten, ohne sie vollständig
        in den Arbeitsspeicher zu laden.

        Args:
            file_path: Absoluter Pfad zur zu hashenden Datei (pathlib.Path).

        Returns:
            Dict mit beiden Hashwerten als Hex-Strings:
            {"md5": "<32-char-hex>", "sha256": "<64-char-hex>"}
        """
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(CHUNK_SIZE):
                md5.update(chunk)
                sha256.update(chunk)
        hashes = {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}
        logger.info(
            f"Hashes berechnet: MD5={hashes['md5'][:12]}...  "
            f"SHA256={hashes['sha256'][:12]}...  ({file_path.name})"
        )
        return hashes

    @staticmethod
    def compute_hash(file_path: Path) -> str:
        """
        Berechnet ausschließlich den SHA256-Hash einer Datei.

        Dient der Rückwärtskompatibilität mit älterem Pipeline-Code,
        der nur einen einzelnen Hash erwartet. Intern wird compute_dual_hash()
        aufgerufen und nur der SHA256-Wert zurückgegeben.

        Args:
            file_path: Absoluter Pfad zur zu hashenden Datei.

        Returns:
            SHA256-Hashwert als 64-stelliger Hex-String.
        """
        return EvidenceTracker.compute_dual_hash(file_path)["sha256"]

    @staticmethod
    def verify_dual_hash(file_path: Path, expected: Dict[str, str]) -> Dict[str, bool]:
        """
        Verifiziert MD5- und SHA256-Hash einer Datei gegen gespeicherte Referenzwerte.

        Berechnet die aktuellen Hashes der Datei und vergleicht sie mit
        den bei Eingang gespeicherten Werten. Beide Hashes müssen übereinstimmen
        für eine vollständige Integritätsbescheinigung (overall=True).

        Wird ein Hash-Mismatch erkannt, loggt die Methode eine Warnung —
        dies kann auf Datenverfälschung, versehentliche Änderung oder
        einen Übertragungsfehler hinweisen.

        Args:
            file_path: Absoluter Pfad zur zu prüfenden Datei.
            expected:  Dict mit Referenz-Hashes, üblicherweise von
                       compute_dual_hash() bei Datei-Eingang erstellt:
                       {"md5": "<hex>", "sha256": "<hex>"}

        Returns:
            Verifikations-Ergebnis-Dict:
            {
                "md5_verified":     bool,  # True wenn MD5 übereinstimmt
                "sha256_verified":  bool,  # True wenn SHA256 übereinstimmt
                "overall":          bool,  # True wenn BEIDE übereinstimmen
                "current_md5":      str,   # Aktuell berechneter MD5
                "current_sha256":   str    # Aktuell berechneter SHA256
            }
        """
        current = EvidenceTracker.compute_dual_hash(file_path)
        md5_ok = current["md5"] == expected.get("md5", "")
        sha256_ok = current["sha256"] == expected.get("sha256", "")
        # Beide Hashes müssen übereinstimmen für vollständige Integrität
        overall = md5_ok and sha256_ok

        if overall:
            logger.info(f"Hash-Verifikation BESTANDEN (MD5+SHA256): {file_path.name}")
        else:
            if not md5_ok:
                logger.warning(f"MD5-Verifikation FEHLGESCHLAGEN: {file_path.name}")
            if not sha256_ok:
                logger.warning(f"SHA256-Verifikation FEHLGESCHLAGEN: {file_path.name}")

        return {
            "md5_verified": md5_ok,
            "sha256_verified": sha256_ok,
            "overall": overall,
            "current_md5": current["md5"],
            "current_sha256": current["sha256"],
        }

    @staticmethod
    def verify_hash(file_path: Path, expected_hash: str) -> bool:
        """
        Verifiziert ausschließlich den SHA256-Hash einer Datei.

        Rückwärtskompatible Vereinfachung von verify_dual_hash() für Code,
        der nur einen einzelnen SHA256-Vergleich benötigt.

        Args:
            file_path:     Absoluter Pfad zur zu prüfenden Datei.
            expected_hash: Erwarteter SHA256-Hashwert als Hex-String.

        Returns:
            True wenn der aktuelle SHA256 dem erwarteten Wert entspricht.
        """
        current = EvidenceTracker.compute_dual_hash(file_path)["sha256"]
        verified = current == expected_hash
        if not verified:
            logger.warning(f"Hash-Verifikation FEHLGESCHLAGEN: {file_path.name}")
        return verified

    @staticmethod
    def create_audit_entry(event: str, details: dict = None) -> dict:
        """
        Erstellt einen strukturierten Audit-Trail-Eintrag.

        Audit-Einträge dokumentieren jeden relevanten Schritt in der
        Beweismittelkette (Chain of Custody): Datei-Upload, Analyse-Start,
        Hash-Berechnung, Export, etc. Sie werden in Job-Metadaten gespeichert
        und können bei Bedarf als forensisches Protokoll exportiert werden.

        Args:
            event:   Bezeichner des protokollierten Ereignisses
                     (z.B. "upload", "analysis_start", "hash_computed").
            details: Optionales Dict mit ereignisspezifischen Zusatzdaten
                     (z.B. {"job_id": "abc-123", "file_size": 4096}).

        Returns:
            Audit-Eintrag als Dict:
            {
                "timestamp": "2024-01-15T03:14:07.123456",  # ISO 8601
                "event":     "upload",
                "details":   {"job_id": "abc-123", ...}
            }
        """
        return {
            "timestamp": datetime.now().isoformat(),
            "event": event,
            "details": details or {},
        }
