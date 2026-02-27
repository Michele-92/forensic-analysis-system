"""Ollama API-Wrapper."""
import requests
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Import timeout from config, fallback to 120s
try:
    from backend.config import LLM_TIMEOUT, OLLAMA_BASE_URL, DEFAULT_LLM_MODEL
except ImportError:
    try:
        from config import LLM_TIMEOUT, OLLAMA_BASE_URL, DEFAULT_LLM_MODEL
    except ImportError:
        LLM_TIMEOUT = 120
        OLLAMA_BASE_URL = "http://localhost:11434"
        DEFAULT_LLM_MODEL = "llama3.1"


class OllamaClient:
    """Client für Ollama-API-Calls."""

    def __init__(self,
                 model: str = None,
                 base_url: str = None,
                 timeout: int = None):
        self.model = model or DEFAULT_LLM_MODEL
        self.base_url = base_url or OLLAMA_BASE_URL
        self.timeout = timeout or LLM_TIMEOUT

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
            max_tokens: Max. Response-Laenge (Ollama: num_predict)

        Returns:
            Generated Text
        """
        prompt_len = len(system_prompt) + len(user_prompt)
        logger.info(f"Ollama-Request: model={self.model}, prompt={prompt_len} chars, max_tokens={max_tokens}")

        try:
            response = requests.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "system": system_prompt,
                    "prompt": user_prompt,
                    "options": {
                        "temperature": temperature,
                        "num_predict": max_tokens,
                    },
                    "stream": False
                },
                timeout=self.timeout
            )

            response.raise_for_status()
            result = response.json()

            response_text = result.get("response", "")
            if not response_text:
                logger.warning("Ollama hat eine leere Response zurueckgegeben")
                return "(Keine LLM-Antwort erhalten)"

            # Statistiken loggen
            total_duration = result.get("total_duration", 0) / 1e9  # ns -> s
            eval_count = result.get("eval_count", 0)
            tokens_per_sec = eval_count / total_duration if total_duration > 0 else 0
            logger.info(f"LLM-Response: {len(response_text)} Zeichen, {eval_count} tokens in {total_duration:.1f}s ({tokens_per_sec:.1f} tok/s)")

            return response_text

        except requests.exceptions.ConnectionError:
            msg = f"Ollama nicht erreichbar unter {self.base_url}. Ist Ollama gestartet?"
            logger.error(msg)
            raise ConnectionError(msg)
        except requests.exceptions.Timeout:
            msg = f"Ollama-Timeout nach {self.timeout}s. Modell '{self.model}' antwortet nicht rechtzeitig."
            logger.error(msg)
            raise TimeoutError(msg)
        except requests.exceptions.RequestException as e:
            logger.error(f"Ollama-API-Fehler: {e}")
            raise
