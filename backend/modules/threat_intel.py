"""
Threat Intelligence Lookup.

Gleicht IOCs gegen eine lokale Knowledge-Base (rag/knowledge_base/iocs.json)
und optional gegen die AbuseIPDB API ab.
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Lokale Knowledge-Base
KB_PATH = Path(__file__).resolve().parent.parent.parent / "rag" / "knowledge_base" / "iocs.json"

# IOC-Typ-Mapping (Frontend-Kategorie → KB-Typ)
TYPE_MAP = {
    "ips": "ip",
    "domains": "domain",
    "files": "file_path",
    "users": "user",
    "processes": "process",
    "hostnames": "hostname",
}


class ThreatIntelLookup:
    """Threat-Intelligence-Abgleich fuer forensische IOCs."""

    def __init__(self):
        self.kb = self._load_kb()
        self.abuseipdb_key = self._get_api_key()

    def _load_kb(self) -> List[Dict]:
        """Laedt die lokale IOC Knowledge-Base."""
        if not KB_PATH.exists():
            logger.warning(f"IOC-KB nicht gefunden: {KB_PATH}")
            return []
        try:
            data = json.loads(KB_PATH.read_text(encoding="utf-8"))
            logger.info(f"IOC-KB geladen: {len(data)} Eintraege aus {KB_PATH.name}")
            return data
        except Exception as e:
            logger.error(f"Fehler beim Laden der IOC-KB: {e}")
            return []

    @staticmethod
    def _get_api_key() -> str:
        """Laedt AbuseIPDB API-Key aus Config oder Environment."""
        import os
        key = os.getenv("ABUSEIPDB_API_KEY", "")
        if not key:
            try:
                from backend.config import ABUSEIPDB_API_KEY
                key = ABUSEIPDB_API_KEY
            except ImportError:
                try:
                    from config import ABUSEIPDB_API_KEY
                    key = ABUSEIPDB_API_KEY
                except (ImportError, AttributeError):
                    pass
        return key

    def lookup(self, ioc_value: str, ioc_type: str) -> Dict:
        """
        Einzelnen IOC gegen alle verfuegbaren Quellen abgleichen.

        Returns:
            {value, type, verdict, confidence, sources: [...]}
            verdict: "malicious" | "suspicious" | "clean" | "unknown"
        """
        sources = []

        # 1) Lokale Knowledge-Base
        kb_result = self._lookup_local(ioc_value, ioc_type)
        if kb_result:
            sources.append(kb_result)

        # 2) AbuseIPDB (nur fuer IPs)
        if ioc_type == "ip" and self.abuseipdb_key:
            abuse_result = self._lookup_abuseipdb(ioc_value)
            if abuse_result:
                sources.append(abuse_result)

        # Verdict bestimmen
        verdict = self._determine_verdict(sources)

        # Confidence bestimmen
        confidence = "unknown"
        if sources:
            conf_values = [s.get("confidence", "unknown") for s in sources]
            if "high" in conf_values:
                confidence = "high"
            elif "medium" in conf_values:
                confidence = "medium"
            else:
                confidence = "low"

        return {
            "value": ioc_value,
            "type": ioc_type,
            "verdict": verdict,
            "confidence": confidence,
            "sources": sources,
        }

    def lookup_batch(self, indicators: Dict[str, List]) -> List[Dict]:
        """
        Mehrere IOC-Kategorien auf einmal abgleichen.

        Args:
            indicators: {"ips": [...], "domains": [...], ...}
        Returns:
            Liste von Lookup-Ergebnissen
        """
        results = []
        for category, values in indicators.items():
            ioc_type = TYPE_MAP.get(category, category)
            for value in (values or []):
                result = self.lookup(str(value), ioc_type)
                results.append(result)
        return results

    def _lookup_local(self, value: str, ioc_type: str) -> Optional[Dict]:
        """Sucht in der lokalen Knowledge-Base."""
        value_lower = value.lower().strip()
        for entry in self.kb:
            if entry.get("value", "").lower().strip() == value_lower:
                return {
                    "source": "local_kb",
                    "threat": entry.get("threat", ""),
                    "confidence": entry.get("confidence", "medium"),
                    "tags": entry.get("tags", []),
                    "first_seen": entry.get("first_seen", ""),
                    "original_source": entry.get("source", ""),
                }
        return None

    def _lookup_abuseipdb(self, ip: str) -> Optional[Dict]:
        """Fragt AbuseIPDB API ab (nur fuer IPs)."""
        import requests

        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": self.abuseipdb_key, "Accept": "application/json"},
                timeout=10,
            )

            if resp.status_code != 200:
                logger.warning(f"AbuseIPDB Fehler fuer {ip}: HTTP {resp.status_code}")
                return None

            data = resp.json().get("data", {})
            abuse_score = data.get("abuseConfidenceScore", 0)

            return {
                "source": "abuseipdb",
                "abuse_score": abuse_score,
                "is_malicious": abuse_score >= 50,
                "country": data.get("countryCode", ""),
                "isp": data.get("isp", ""),
                "total_reports": data.get("totalReports", 0),
                "confidence": "high" if abuse_score >= 75 else ("medium" if abuse_score >= 25 else "low"),
            }
        except requests.RequestException as e:
            logger.warning(f"AbuseIPDB Anfrage fehlgeschlagen fuer {ip}: {e}")
            return None

    @staticmethod
    def _determine_verdict(sources: List[Dict]) -> str:
        """Bestimmt das Gesamturteil basierend auf allen Quellen."""
        if not sources:
            return "unknown"

        for src in sources:
            # AbuseIPDB
            if src.get("source") == "abuseipdb":
                if src.get("abuse_score", 0) >= 50:
                    return "malicious"
                if src.get("abuse_score", 0) >= 25:
                    return "suspicious"
            # Lokale KB
            if src.get("source") == "local_kb":
                conf = src.get("confidence", "")
                if conf == "high":
                    return "malicious"
                if conf == "medium":
                    return "suspicious"
                return "suspicious"

        return "clean"
