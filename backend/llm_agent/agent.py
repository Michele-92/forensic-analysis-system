"""
================================================================================
FORENSIC LLM AGENT — Haupt-LLM-Agent für forensische Analyse
================================================================================
Kapselt die drei klassischen LLM-Analyse-Schritte der Forensik-Pipeline in
einer einzelnen Klasse. Dient als vereinfachte Alternative zum Multi-Agent-
Orchestrator (multi_agent.py) für den Fall dass kein mehrstufiger Agenten-
Workflow benötigt wird.

Aufgaben:
    - Anomalie-Erkennung: LLM klassifiziert vorselektierte Timeline-Events
    - Timeline-Interpretation: LLM rekonstruiert Angriffskette mit MITRE ATT&CK
    - Report-Generierung: LLM erstellt Executive Report in Markdown
    - RAG-Anreicherung: Bekannte IOCs und MITRE-Techniken aus Knowledge-Base
      werden automatisch in die Prompts eingebettet
    - Report-Persistenz: save_report() speichert den Report als .md-Datei

Verwendung:
    agent = ForensicLLMAgent(model='llama3.1', use_rag=True)
    report = agent.analyze(timeline_events, indicators)

    # Report speichern:
    agent.save_report(report, output_path=Path('data/outputs/job_123/'))

Verhältnis zu multi_agent.py:
    Dieser Agent ist der einfachere Einzel-Agent. multi_agent.py orchestriert
    3 spezialisierte Agenten (Triage → DFIR-Analyst → Reporter) sequentiell
    mit eigenem Kontext-Passing und SSE-Streaming. Für die Hauptpipeline
    (pipeline.py) wird multi_agent.py verwendet.

Abhängigkeiten:
    - .prompts (PromptManager)
    - .ollama_client (OllamaClient)
    - .rag_handler (RAGHandler)
    - backend.config (DEFAULT_LLM_MODEL)

Kontext: LFX Forensic Analysis System — LLM-Integrations-Schicht
================================================================================
"""
from typing import Dict, List
import logging
from pathlib import Path
from .prompts import PromptManager
from .ollama_client import OllamaClient
from .rag_handler import RAGHandler

logger = logging.getLogger(__name__)

# ── Konfiguration laden (mit mehrstufigem Fallback) ───────────────────────────
# Identisches Import-Muster wie in ollama_client.py: Unterstützt Aufruf
# aus API-Kontext (backend.config), Pipeline-Kontext (config) und Tests.
try:
    from backend.config import DEFAULT_LLM_MODEL
except ImportError:
    try:
        from config import DEFAULT_LLM_MODEL
    except ImportError:
        DEFAULT_LLM_MODEL = "llama3.1:8b"


# ── Hauptklasse ───────────────────────────────────────────────────────────────

class ForensicLLMAgent:
    """
    Einzelner LLM-Agent für den klassischen 3-Schritte Forensik-Workflow.

    Orchestriert intern PromptManager, OllamaClient und RAGHandler für
    einen vollständigen Analyse-Durchlauf. Jeder der drei Schritte erzeugt
    einen eigenen Ollama-API-Aufruf mit dediziertem Prompt.

    Features:
        - Anomalieerkennung mit LLM (blockierender Aufruf)
        - Timeline-Interpretation mit MITRE ATT&CK Mapping
        - Executive Report-Generierung in Markdown
        - Optionale RAG-Anreicherung (bekannte IOCs, MITRE-Kontext)

    Analyse-Modi:
        Dieser Agent unterstützt ausschließlich den Standard-Modus
        (Opfer-Perspektive). Für den Täterinfrastruktur-Modus
        (analysis_mode='attacker_infra') ist MultiAgentOrchestrator
        aus multi_agent.py zu verwenden.

    Beispiel:
        agent = ForensicLLMAgent(model='llama3.1', use_rag=True)
        section = agent._extract_section(report_md, "Befunde")
        agent.save_report(report_md, Path('data/outputs/abc123/'))
    """

    def __init__(self,
                 model: str = None,
                 use_rag: bool = True):
        self.model = model or DEFAULT_LLM_MODEL
        self.prompt_manager = PromptManager()
        self.ollama = OllamaClient(model=self.model)
        # RAGHandler nur initialisieren wenn RAG aktiviert ist, da er die
        # Knowledge-Base beim Start lädt (Dateisystemzugriff)
        self.rag = RAGHandler() if use_rag else None
        logger.info(f"ForensicLLMAgent initialisiert (Model: {self.model}, RAG: {use_rag})")

    # ── Hilfsmethoden ─────────────────────────────────────────────────────────

    def _extract_section(self, markdown: str, section: str) -> str:
        """
        Extrahiert einen benannten Abschnitt aus einem Markdown-Report.

        Sucht nach einem ## <section>-Header und gibt den Text bis zum
        nächsten ## -Header zurück. Wird verwendet um einzelne Abschnitte
        (z.B. "Befunde", "Empfehlungen") aus dem vollständigen Report
        zu extrahieren ohne den gesamten Report zu parsen.

        REPARATUR #52: Verbesserte Section-Extraktion mit Error-Handling.

        Args:
            markdown: Vollständiger Markdown-Report-Text
            section:  Name des gesuchten Abschnitts (ohne ##-Präfix)

        Returns:
            Gefundener Abschnittstext inklusive Header, oder leerer String
            wenn der Abschnitt nicht existiert.
        """
        try:
            start = markdown.find(f"## {section}")
            if start == -1:
                logger.debug(f"⚠ Section nicht gefunden: {section}")
                return ""

            # Nächsten ## -Header suchen um Abschnittsende zu bestimmen.
            # Falls kein weiterer Header folgt, bis zum Ende des Textes.
            end = markdown.find("##", start + 1)
            if end == -1:
                return markdown[start:].strip()

            return markdown[start:end].strip()
        except Exception as e:
            logger.debug(f"Fehler bei Section-Extraktion: {e}")
            return ""

    # ── Report-Persistenz ─────────────────────────────────────────────────────

    def save_report(self, report: str, output_path: Path, filename: str = "report.md") -> Path:
        """
        Speichert den generierten LLM-Report als Markdown-Datei.

        Erstellt das Ausgabe-Verzeichnis falls es noch nicht existiert.
        Wird von pipeline.py aufgerufen um den Report im Job-Ausgabeverzeichnis
        (data/outputs/<job_id>/report.md) abzulegen.

        REPARATUR #53: NEUE METHODE - Report als Datei speichern.

        Args:
            report:      Vollständiger Report-Text in Markdown
            output_path: Zielverzeichnis (wird mit parents=True erstellt)
            filename:    Dateiname im Zielverzeichnis (Standard: "report.md")

        Returns:
            Absoluter Path zur gespeicherten Datei

        Raises:
            OSError: Verzeichnis konnte nicht erstellt oder Datei nicht
                     geschrieben werden (z.B. Berechtigungsfehler)
        """
        try:
            output_path.mkdir(parents=True, exist_ok=True)
            report_file = output_path / filename

            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(report)

            logger.info(f"✓ Report gespeichert: {report_file} ({len(report)} Zeichen)")
            return report_file
        except Exception as e:
            logger.error(f"✗ Fehler beim Speichern des Reports: {e}")
            raise
