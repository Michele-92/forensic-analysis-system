"""
REPARATUR #45: Haupt-LLM-Agent für forensische Analyse mit besserem Logging.
"""
import json
from typing import Dict, List, Optional
import logging
from pathlib import Path
from datetime import datetime
from .prompts import PromptManager
from .ollama_client import OllamaClient
from .rag_handler import RAGHandler

# REPARATUR #46: Besseres Logging für Agent
logger = logging.getLogger(__name__)

class ForensicLLMAgent:
    """
    REPARATUR #47: Verbesserte Hauptklasse für LLM-basierte forensische Analyse.
    
    Features:
    - Anomalieerkennung mit LLM
    - Timeline-Interpretation
    - Executive Report-Generierung
    - RAG (Retrieval-Augmented Generation) Integration
    """
    
    def __init__(self, 
                 model: str = "llama3.1",
                 use_rag: bool = True):
        self.model = model
        self.prompt_manager = PromptManager()
        self.ollama = OllamaClient(model=model)
        self.rag = RAGHandler() if use_rag else None
        logger.info(f"✓ ForensicLLMAgent initialisiert (Model: {model}, RAG: {use_rag})")
        
    def detect_anomalies(self, timeline: List[Dict]) -> List[Dict]:
        """
        REPARATUR #48: Anomalieerkennung mit besserem Logging.
        
        Erkennt Anomalien in Timeline-Events unter Nutzung von RAG-Kontext.
        
        Returns:
            Liste von Anomalien mit Scores und Erklärungen
        """
        logger.info(f"→ Starte KI-Anomalieerkennung für {len(timeline)} Events")
        
        try:
            # Hole System-Prompt
            system_prompt = self.prompt_manager.get_system_prompt("forensic_expert")
            
            # Erstelle Analyse-Prompt
            user_prompt = self.prompt_manager.get_anomaly_detection_prompt(timeline)
            
            # RAG: Füge relevanten Kontext hinzu
            if self.rag:
                rag_context = self.rag.get_relevant_context(timeline)
                if rag_context:
                    user_prompt += f"\n\nRelevanter Kontext aus Knowledge Base:\n{rag_context}"
                    logger.debug("✓ RAG-Kontext hinzugefügt")
            
            # LLM-Call
            logger.debug("→ Sende Query an LLM...")
            response = self.ollama.generate(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                temperature=0.3  # Niedrig für faktische Analyse
            )
            
            # Parse JSON-Response
            try:
                anomalies = json.loads(response)
                logger.info(f"✓ LLM-Anomalieerkennung: {len(anomalies)} Anomalien erkannt")
                return anomalies
            except json.JSONDecodeError as e:
                logger.warning(f"⚠ Konnte JSON nicht parsen: {e}. Nutze rohe Response.")
                return [{"raw": response}]
        except Exception as e:
            logger.error(f"✗ Anomalieerkennung fehlgeschlagen: {e}")
            return []
    
    def interpret_timeline(self, 
                          timeline: List[Dict],
                          iocs: Optional[List[str]] = None) -> Dict:
        """
        REPARATUR #49: Timeline-Interpretation mit KI & besserem Logging.
        
        Interpretiert Timeline und generiert Hypothesen mit MITRE ATT&CK Mapping.
        
        Returns:
            Dict mit Zusammenfassung, Hypothesen und Top-Findings
        """
        logger.info(f"→ Starte Timeline-Interpretation ({len(timeline)} Events)")
        
        try:
            system_prompt = self.prompt_manager.get_system_prompt("forensic_expert")
            user_prompt = self.prompt_manager.get_timeline_interpretation_prompt(
                timeline, iocs
            )
            
            # RAG: MITRE ATT&CK Techniques
            if self.rag:
                mitre_context = self.rag.get_mitre_techniques(timeline)
                if mitre_context:
                    user_prompt += f"\n\nRelevante MITRE ATT&CK Techniques:\n{mitre_context}"
                    logger.debug("✓ MITRE ATT&CK Techniques hinzugefügt")
            
            logger.debug("→ Sende Query an LLM...")
            response = self.ollama.generate(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                temperature=0.5  # Etwas höher für kreative Hypothesen
            )
            
            interpretation = {
                "summary": self._extract_section(response, "Zusammenfassung"),
                "hypotheses": self._extract_section(response, "Hypothesen"),
                "top_findings": self._extract_section(response, "Top-Findings"),
                "raw_response": response
            }
            
            logger.info("✓ Timeline-Interpretation abgeschlossen")
            return interpretation
        except Exception as e:
            logger.error(f"✗ Timeline-Interpretation fehlgeschlagen: {e}")
            return {
                "summary": "Fehler bei Interpretation",
                "hypotheses": str(e),
                "top_findings": "N/A",
                "raw_response": str(e)
            }
    
    def generate_report(self, 
                       findings: List[Dict],
                       risk_scores: List[float]) -> str:
        """
        REPARATUR #50: Executive Report-Generierung mit besserem Logging.
        
        Generiert Markdown-formatiert Report für Stakeholder.
        
        Returns:
            Markdown-formatierter Report
        """
        logger.info("→ Generiere Executive Report")
        
        try:
            system_prompt = self.prompt_manager.get_system_prompt("forensic_expert")
            user_prompt = self.prompt_manager.get_report_generation_prompt(
                findings, risk_scores
            )
            
            logger.debug("→ Sende Query an LLM...")
            report = self.ollama.generate(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                temperature=0.4
            )
            
            logger.info(f"✓ Report generiert ({len(report)} Zeichen)")
            return report
        except Exception as e:
            logger.error(f"✗ Report-Generierung fehlgeschlagen: {e}")
            # REPARATUR #51: Fallback-Report bei Fehler
            fallback_report = f"""# Forensic Analysis Report
            
**Generated:** {datetime.now().isoformat()}
**Status:** Error during AI report generation

## Error
{str(e)}

## Findings Summary
- Total findings: {len(findings)}
- Files: {len([f for f in findings if 'file' in str(f).lower()])}
- Risk Level: Unknown (AI failed)

---
*This is a fallback report generated due to LLM failure. Please review raw JSON outputs.*
"""
            return fallback_report
    
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