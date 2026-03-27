"""
================================================================================
RAG HANDLER — Retrieval-Augmented Generation für forensischen Kontext
================================================================================
Stellt eine lokale Knowledge-Base für die LLM-Agenten bereit. Lädt beim Start
bekannte IOCs und MITRE ATT&CK Referenzdaten aus dem rag/-Verzeichnis und
ermöglicht kontextbezogene Abfragen zur Anreicherung der LLM-Prompts.

RAG-Prinzip (Retrieval-Augmented Generation):
    Statt dem LLM alle Informationen im System-Prompt mitzugeben, werden
    nur die für die aktuelle Analyse relevanten Informationen dynamisch
    abgerufen und in den Prompt eingefügt. Das verbessert die Präzision
    und reduziert unnötigen Kontext-Verbrauch (Tokens).

Aufgaben:
    - Laden der JSON-Wissensquellen aus rag/knowledge_base/*.json beim Start
    - get_relevant_context(): Matched Timeline-Events gegen bekannte IOCs
    - get_mitre_techniques(): Keyword-basiertes Mapping auf MITRE ATT&CK IDs

Verwendung:
    rag = RAGHandler()

    # Bekannte IOCs in der Timeline finden:
    context = rag.get_relevant_context(timeline_events)

    # Passende MITRE ATT&CK Techniken identifizieren:
    techniques = rag.get_mitre_techniques(timeline_events)

Knowledge-Base-Verzeichnis: <repo-root>/rag/knowledge_base/
Erwartete Dateien:
    - iocs.json     → Liste von IOC-Objekten {value, type, threat}
    - (weitere .json-Dateien werden automatisch geladen)

Abhängigkeiten:
    - json, pathlib (Datei-Laden)

Kontext: LFX Forensic Analysis System — LLM-Integrations-Schicht
================================================================================
"""
import json
from pathlib import Path
from typing import List, Dict
import logging

logger = logging.getLogger(__name__)

# Absoluter Pfad zum rag/-Verzeichnis (zwei Ebenen über diesem Modul:
# backend/llm_agent/rag_handler.py → backend/ → repo-root/ → rag/)
RAG_DIR = Path(__file__).parent.parent.parent / "rag"


# ── Hauptklasse ───────────────────────────────────────────────────────────────

class RAGHandler:
    """
    Verwaltet die lokale forensische Knowledge-Base für RAG-Anreicherung.

    Wird von ForensicLLMAgent verwendet um LLM-Prompts mit relevantem
    Kontext anzureichern — bekannte Bedrohungs-Indikatoren und MITRE-Techniken
    werden dynamisch aus der Knowledge-Base abgerufen statt statisch im
    System-Prompt hartcodiert zu sein.

    Die Knowledge-Base wird einmalig beim Initialisieren geladen.
    Änderungen an den JSON-Dateien erfordern einen Neustart.

    Beispiel:
        rag = RAGHandler()
        context_str = rag.get_relevant_context(events)    # für Prompt-Anreicherung
        mitre_str   = rag.get_mitre_techniques(events)    # für MITRE-Kontext
    """

    def __init__(self):
        # Knowledge-Base wird beim Start geladen; self.knowledge_base ist ein Dict
        # mit dem Datei-Stammname als Key (z.B. "iocs") und dem JSON-Inhalt als Value.
        self.knowledge_base = self._load_knowledge_base()

    # ── Knowledge-Base laden ──────────────────────────────────────────────────

    def _load_knowledge_base(self) -> Dict:
        """
        Lädt alle JSON-Dateien aus rag/knowledge_base/ in ein Dictionary.

        Der Datei-Stammname (ohne .json) wird als Key verwendet, der
        deserialisierte JSON-Inhalt als Value. Ungültige oder unlesbare
        Dateien werden mit Warning übersprungen.

        Returns:
            Dict mit Dateinamen als Keys und geparsten JSON-Inhalten als Values.
            Leeres Dict wenn das Verzeichnis nicht existiert.
        """
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

    # ── Kontext-Abfragen ──────────────────────────────────────────────────────

    def get_relevant_context(self, timeline: List[Dict]) -> str:
        """
        Matched Timeline-Events gegen bekannte IOCs aus der Knowledge-Base.

        Durchsucht die ersten 50 Events der Timeline nach bekannten IOC-Werten
        (IP-Adressen, Domains, Hashes etc.) aus iocs.json. Trifft ein bekannter
        IOC auf einen Event zu, wird ein Kontext-String für den LLM-Prompt
        erzeugt. Maximal 5 Treffer werden zurückgegeben.

        Der zurückgegebene Text wird in den LLM-Prompt eingefügt um das Modell
        darauf hinzuweisen, dass bestimmte Werte in der Timeline als bekannte
        Bedrohungs-Indikatoren klassifiziert sind.

        Args:
            timeline: Liste normalisierter Timeline-Events (Dicts aus DataNormalizer)

        Returns:
            Mehrzeiliger String mit Treffern im Format:
            "Bekannter IOC gefunden: <value> (Typ: <type>, Threat: <threat>)"
            Leerer String wenn keine IOCs in der Knowledge-Base oder keine Treffer.
        """
        context_parts = []

        iocs = self.knowledge_base.get("iocs", [])
        if not isinstance(iocs, list):
            logger.warning("IOCs in Knowledge Base sind kein Array, überspringe")
            return ""

        # Nur die ersten 50 Events prüfen um die Laufzeit zu begrenzen.
        # Bei größeren Timelines werden unwichtigere Events (niedrige Scores)
        # durch den AIPreprocessor bereits herausgefiltert.
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

                # Case-insensitiver Substring-Match: IOC-Wert irgendwo im Event
                if value and value.lower() in event_str:
                    context_parts.append(
                        f"Bekannter IOC gefunden: {value} "
                        f"(Typ: {ioc_type}, Threat: {threat})"
                    )

        # Auf 5 Treffer begrenzen um den Prompt nicht zu überladen
        return "\n".join(context_parts[:5])

    def get_mitre_techniques(self, timeline: List[Dict]) -> str:
        """
        Keyword-basiertes Mapping von Timeline-Events auf MITRE ATT&CK Techniken.

        Durchsucht die ersten 50 Events nach charakteristischen Keywords und
        ordnet ihnen bekannte MITRE ATT&CK Technique-IDs zu. Diese einfache
        regelbasierte Erkennung ergänzt das ML-basierte Anomalie-Scoring
        um konkrete Angriffs-Klassifikationen.

        Erkannte Muster:
            - cron/scheduled → T1053 (Scheduled Task/Job, Persistence)
            - ssh + root      → T1021.004 (Remote Services: SSH)
            - powershell/cmd  → T1059 (Command and Scripting Interpreter)
            - registry + run  → T1547.001 (Registry Run Keys, Persistence)
            - mimikatz/lsass  → T1003 (OS Credential Dumping)

        Args:
            timeline: Liste normalisierter Timeline-Events (Dicts aus DataNormalizer)

        Returns:
            Zeilenweise MITRE ATT&CK Technique-Strings, maximal 5.
            Leerer String wenn keine Muster erkannt.
        """
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

        # Auf 5 Techniken begrenzen; set() garantiert keine Duplikate
        result = list(techniques)[:5]
        return "\n".join(result)
