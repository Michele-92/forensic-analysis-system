"""RAG (Retrieval-Augmented Generation) Handler."""
import json
from pathlib import Path
from typing import List, Dict
import logging

logger = logging.getLogger(__name__)

RAG_DIR = Path(__file__).parent.parent.parent / "rag"


class RAGHandler:
    """Verwaltet Knowledge Base für RAG."""

    def __init__(self):
        self.knowledge_base = self._load_knowledge_base()

    def _load_knowledge_base(self) -> Dict:
        """Lädt alle Wissensquellen mit Error-Handling."""
        kb = {}
        kb_dir = RAG_DIR / "knowledge_base"

        if not kb_dir.exists():
            logger.warning(f"Knowledge-Base-Verzeichnis nicht gefunden: {kb_dir}")
            return kb

        for file in kb_dir.glob("*.json"):
            try:
                with open(file, encoding="utf-8") as f:
                    kb[file.stem] = json.load(f)
            except json.JSONDecodeError as e:
                logger.warning(f"Ungültiges JSON in {file.name}: {e}")
            except OSError as e:
                logger.warning(f"Datei nicht lesbar {file.name}: {e}")

        logger.info(f"Knowledge Base geladen: {list(kb.keys())}")
        return kb

    def get_relevant_context(self, timeline: List[Dict]) -> str:
        """Findet relevanten Kontext aus Knowledge Base."""
        context_parts = []

        iocs = self.knowledge_base.get("iocs", [])
        if not isinstance(iocs, list):
            logger.warning("IOCs in Knowledge Base sind kein Array, überspringe")
            return ""

        for event in timeline[:50]:
            try:
                event_str = json.dumps(event, default=str).lower()
            except (TypeError, ValueError):
                continue

            for ioc in iocs:
                if not isinstance(ioc, dict):
                    continue

                value = ioc.get("value", "")
                ioc_type = ioc.get("type", "unknown")
                threat = ioc.get("threat", "unknown")

                if value and value.lower() in event_str:
                    context_parts.append(
                        f"Bekannter IOC gefunden: {value} "
                        f"(Typ: {ioc_type}, Threat: {threat})"
                    )

        return "\n".join(context_parts[:5])

    def get_mitre_techniques(self, timeline: List[Dict]) -> str:
        """Matched Timeline-Events zu MITRE ATT&CK Techniques."""
        techniques = set()

        for event in timeline[:50]:
            try:
                event_str = json.dumps(event, default=str).lower()
            except (TypeError, ValueError):
                continue

            if "cron" in event_str or "scheduled" in event_str:
                techniques.add("T1053 - Scheduled Task/Job (Persistence)")

            if "ssh" in event_str and "root" in event_str:
                techniques.add("T1021.004 - Remote Services: SSH (Lateral Movement)")

            if "powershell" in event_str or "cmd.exe" in event_str:
                techniques.add("T1059 - Command and Scripting Interpreter (Execution)")

            if "registry" in event_str and ("run" in event_str or "startup" in event_str):
                techniques.add("T1547.001 - Registry Run Keys (Persistence)")

            if "mimikatz" in event_str or "lsass" in event_str:
                techniques.add("T1003 - OS Credential Dumping (Credential Access)")

        result = list(techniques)[:5]
        return "\n".join(result)
