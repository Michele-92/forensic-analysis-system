"""Ollama API-Wrapper."""
import requests
import logging
from typing import Optional

logger = logging.getLogger(__name__)

class OllamaClient:
    """Client für Ollama-API-Calls."""
    
    def __init__(self, 
                 model: str = "llama3.1",
                 base_url: str = "http://localhost:11434"):
        self.model = model
        self.base_url = base_url
        
    def generate(self, 
                 system_prompt: str,
                 user_prompt: str,
                 temperature: float = 0.7,
                 max_tokens: int = 2000) -> str:
        """
        Generiert Response von Ollama.
        
        Args:
            system_prompt: System-Level Instruktionen
            user_prompt: User-Query
            temperature: 0.0-1.0 (niedrig = faktisch, hoch = kreativ)
            max_tokens: Max. Response-Länge
        
        Returns:
            Generated Text
        """
        try:
            response = requests.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": f"{system_prompt}\n\n{user_prompt}",
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                    "stream": False
                },
                timeout=120  # 2 Minuten Timeout
            )
            
            response.raise_for_status()
            result = response.json()
            
            logger.info(f"LLM-Response generiert ({len(result['response'])} Zeichen)")
            return result["response"]
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Ollama-API-Fehler: {e}")
            raise