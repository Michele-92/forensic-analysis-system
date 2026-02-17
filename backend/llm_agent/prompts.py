"""Zentrale Prompt-Verwaltung für LLM-Agent."""
from pathlib import Path
from typing import Dict, List
import json

PROMPTS_DIR = Path(__file__).parent.parent.parent / "prompts"

class PromptManager:
    """Lädt und formatiert Prompt-Templates."""
    
    def __init__(self):
        self.templates = self._load_templates()
    
    def _load_templates(self) -> Dict[str, str]:
        """Lädt alle Prompt-Templates."""
        templates = {}
        template_dir = PROMPTS_DIR / "templates"
        
        for file in template_dir.glob("*.txt"):
            templates[file.stem] = file.read_text()
        
        return templates
    
    def get_anomaly_detection_prompt(self, timeline: List[Dict]) -> str:
        """Erstellt Anomalie-Erkennungs-Prompt."""
        template = self.templates["anomaly_detection"]
        return template.format(
            timeline=json.dumps(timeline[:100], indent=2)  # Limitiere auf 100 Events
        )
    
    def get_timeline_interpretation_prompt(self, 
                                          timeline: List[Dict], 
                                          iocs: List[str] = None) -> str:
        """Erstellt Timeline-Interpretations-Prompt."""
        template = self.templates["timeline_interpretation"]
        ioc_context = ", ".join(iocs) if iocs else "Keine bekannten IOCs"
        
        return template.format(
            timeline=json.dumps(timeline, indent=2),
            iocs=ioc_context
        )
    
    def get_report_generation_prompt(self, 
                                     findings: List[Dict],
                                     risk_scores: List[float]) -> str:
        """Erstellt Report-Generierungs-Prompt."""
        template = self.templates["report_generation"]
        return template.format(
            findings=json.dumps(findings, indent=2),
            risk_scores=risk_scores
        )
    
    def get_system_prompt(self, role: str = "forensic_expert") -> str:
        """Lädt System-Prompt für Rollen-Definition."""
        path = PROMPTS_DIR / "system_prompts" / f"{role}.txt"
        return path.read_text()