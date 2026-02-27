"""
LLM Agent Module für forensische Analyse.

Dieses Modul enthält alle Komponenten für die LLM-basierte Analyse:
- Agent: Hauptklasse für forensische LLM-Operationen
- PromptManager: Verwaltung von Prompt-Templates
- OllamaClient: API-Wrapper für Ollama
- RAGHandler: Retrieval-Augmented Generation
"""

from .agent import ForensicLLMAgent
from .prompts import PromptManager
from .ollama_client import OllamaClient
from .rag_handler import RAGHandler
from .multi_agent import MultiAgentOrchestrator
from .case_correlator import CaseCorrelationAgent

__version__ = "1.0.0"

__all__ = [
    # Main Agent
    "ForensicLLMAgent",
    "MultiAgentOrchestrator",
    "CaseCorrelationAgent",

    # Components
    "PromptManager",
    "OllamaClient",
    "RAGHandler",
]


# Convenience function for quick agent creation
def create_agent(model: str = None,
                 use_rag: bool = True,
                 **kwargs) -> ForensicLLMAgent:
    """
    Factory-Funktion zum schnellen Erstellen eines Agents.

    Args:
        model: LLM-Model-Name (default: aus config.py)
        use_rag: RAG aktivieren (default: True)
        **kwargs: Weitere Parameter für ForensicLLMAgent

    Returns:
        Konfigurierter ForensicLLMAgent
    """
    return ForensicLLMAgent(model=model, use_rag=use_rag, **kwargs)


# Module-level configuration (optional)
DEFAULT_CONFIG = {
    "model": "llama3.1:8b",
    "temperature": {
        "anomaly_detection": 0.3,  # Niedrig für faktische Analyse
        "timeline_interpretation": 0.5,  # Mittel für Hypothesen
        "report_generation": 0.4,  # Niedrig-Mittel für Reports
    },
    "max_tokens": 2000,
    "use_rag": True,
    "rag_top_k": 5,  # Top-K relevante Dokumente aus RAG
}


def get_default_config() -> dict:
    """
    Gibt Default-Konfiguration zurück.
    
    Returns:
        Dict mit Standard-Einstellungen
    """
    return DEFAULT_CONFIG.copy()