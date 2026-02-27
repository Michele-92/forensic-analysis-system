"""
Haupt-LLM-Agent für forensische Analyse.
"""
from typing import Dict, List
import logging
from pathlib import Path
from .prompts import PromptManager
from .ollama_client import OllamaClient
from .rag_handler import RAGHandler

logger = logging.getLogger(__name__)

# Modell-Name aus config.py laden (mit Fallback)
try:
    from backend.config import DEFAULT_LLM_MODEL
except ImportError:
    try:
        from config import DEFAULT_LLM_MODEL
    except ImportError:
        DEFAULT_LLM_MODEL = "llama3.1:8b"


class ForensicLLMAgent:
    """
    Hauptklasse für LLM-basierte forensische Analyse.

    Features:
    - Anomalieerkennung mit LLM
    - Timeline-Interpretation
    - Executive Report-Generierung
    - RAG (Retrieval-Augmented Generation) Integration
    """

    def __init__(self,
                 model: str = None,
                 use_rag: bool = True):
        self.model = model or DEFAULT_LLM_MODEL
        self.prompt_manager = PromptManager()
        self.ollama = OllamaClient(model=self.model)
        self.rag = RAGHandler() if use_rag else None
        logger.info(f"ForensicLLMAgent initialisiert (Model: {self.model}, RAG: {use_rag})")
        
    def _extract_section(self, markdown: str, section: str) -> str:
        """
        REPARATUR #52: Verbesserte Section-Extraktion mit Error-Handling.
        """
        try:
            start = markdown.find(f"## {section}")
            if start == -1:
                logger.debug(f"⚠ Section nicht gefunden: {section}")
                return ""
            
            end = markdown.find("##", start + 1)
            if end == -1:
                return markdown[start:].strip()
            
            return markdown[start:end].strip()
        except Exception as e:
            logger.debug(f"Fehler bei Section-Extraktion: {e}")
            return ""
    
    def save_report(self, report: str, output_path: Path, filename: str = "report.md") -> Path:
        """
        REPARATUR #53: NEUE METHODE - Report als Datei speichern.
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