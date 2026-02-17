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
        """Lädt alle Wissensquellen."""
        kb = {}
        kb_dir = RAG_DIR / "knowledge_base"
        
        for file in kb_dir.glob("*.json"):
            with open(file) as f:
                kb[file.stem] = json.load(f)
        
        logger.info(f"Knowledge Base geladen: {list(kb.keys())}")
        return kb
    
    def get_relevant_context(self, timeline: List[Dict]) -> str:
        """Findet relevanten Kontext aus Knowledge Base."""
        context_parts = []
        
        # Prüfe bekannte IOCs
        for event in timeline[:50]:  # Nur erste 50 Events
            event_str = json.dumps(event).lower()
            
            for ioc in self.knowledge_base.get("iocs", []):
                if ioc["value"].lower() in event_str:
                    context_parts.append(
                        f"Bekannter IOC gefunden: {ioc['value']} "
                        f"(Typ: {ioc['type']}, Threat: {ioc['threat']})"
                    )
        
        return "\n".join(context_parts[:5])  # Max 5 Kontexte
    
    def get_mitre_techniques(self, timeline: List[Dict]) -> str:
        """Matched Timeline-Events zu MITRE ATT&CK Techniques."""
        techniques = []
        
        for event in timeline[:50]:
            event_str = json.dumps(event).lower()
            
            # Beispiel-Matching (vereinfacht)
            if "cron" in event_str or "scheduled" in event_str:
                techniques.append("T1053 - Scheduled Task/Job (Persistence)")
            
            if "ssh" in event_str and "root" in event_str:
                techniques.append("T1021.004 - Remote Services: SSH (Lateral Movement)")
        
        return "\n".join(set(techniques[:5]))