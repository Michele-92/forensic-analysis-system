"""
================================================================================
OLLAMA CLIENT — HTTP-Wrapper für die lokale Ollama LLM-API
================================================================================
Kapselt alle HTTP-Kommunikation mit dem lokal laufenden Ollama-Dienst.
Bietet sowohl blockierende (generate) als auch streamende (generate_stream)
Anfragen für die LLM-Agenten-Pipeline.

Aufgaben:
    - Senden von Prompts an den Ollama /api/generate Endpunkt
    - Token-für-Token Streaming für Echtzeit-Ausgabe im Frontend (SSE)
    - Einheitliche Fehlerbehandlung für Connection- und Timeout-Fehler
    - Logging von Laufzeit-Statistiken (Tokens/Sekunde, Gesamtdauer)

Verwendung:
    client = OllamaClient(model='llama3.1', timeout=120)
    result = client.generate(system_prompt='...', user_prompt='...')

    # Oder streaming (Token-für-Token):
    for token in client.generate_stream(system_prompt, user_prompt):
        print(token, end='', flush=True)

Abhängigkeiten:
    - requests (HTTP-Client)
    - backend.config (OLLAMA_BASE_URL, LLM_TIMEOUT, DEFAULT_LLM_MODEL)

Kontext: LFX Forensic Analysis System — LLM-Integrations-Schicht
================================================================================
"""
import requests
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ── Konfiguration laden (mit mehrstufigem Fallback) ───────────────────────────
# Dreifacher Import-Fallback: backend.config → config → hartcodierte Defaults.
# Ermöglicht die Verwendung des Moduls sowohl aus der API (backend.config)
# als auch aus der Pipeline (config) und in isolierten Tests (Defaults).
try:
    from backend.config import LLM_TIMEOUT, OLLAMA_BASE_URL, DEFAULT_LLM_MODEL
except ImportError:
    try:
        from config import LLM_TIMEOUT, OLLAMA_BASE_URL, DEFAULT_LLM_MODEL
    except ImportError:
        LLM_TIMEOUT = 120
        OLLAMA_BASE_URL = "http://localhost:11434"
        DEFAULT_LLM_MODEL = "llama3.1"


# ── Hauptklasse ───────────────────────────────────────────────────────────────

class OllamaClient:
    """
    HTTP-Client für die lokale Ollama LLM-API.

    Bietet eine vereinfachte Schnittstelle für zwei Anfrage-Modi:
      - Blockierend (generate): Wartet auf die vollständige Antwort
      - Streaming (generate_stream): Liefert Tokens schrittweise via Generator

    Alle Netzwerk-Fehler werden in sprechende Python-Exceptions umgewandelt
    (ConnectionError, TimeoutError), damit aufrufender Code einheitlich
    reagieren kann, unabhängig vom HTTP-Status-Code.

    Beispiel:
        client = OllamaClient()
        text = client.generate(
            system_prompt="Du bist Forensik-Experte.",
            user_prompt="Analysiere diese Timeline...",
            temperature=0.3,
        )
    """

    def __init__(self,
                 model: str = None,
                 base_url: str = None,
                 timeout: int = None):
        self.model = model or DEFAULT_LLM_MODEL
        self.base_url = base_url or OLLAMA_BASE_URL
        self.timeout = timeout or LLM_TIMEOUT

    # ── Blockierende Anfrage ──────────────────────────────────────────────────

    def generate(self,
                 system_prompt: str,
                 user_prompt: str,
                 temperature: float = 0.7,
                 max_tokens: int = 2000) -> str:
        """
        Sendet einen blockierenden LLM-Request an Ollama.

        Wartet auf die vollständige Antwort bevor zurückgegeben wird.
        Für Token-für-Token Streaming: generate_stream() verwenden.
        Nach erfolgreichem Aufruf werden Leistungsmetriken (Tokens/Sekunde,
        Gesamtdauer) im Info-Log ausgegeben.

        Args:
            system_prompt: Rollen-/Kontext-Instruktionen für das Modell
                           (z.B. "Du bist ein Senior DFIR-Analyst...")
            user_prompt:   Die eigentliche Analyse-Aufgabe oder Frage
            temperature:   Kreativität der Antwort (0.0 = faktisch/deterministisch,
                           1.0 = kreativ/variabel). Für forensische Analyse
                           typischerweise 0.2–0.4.
            max_tokens:    Maximale Antwortlänge in Tokens. Ollama-Parameter: num_predict.

        Returns:
            Generierter Text als String. Bei leerer Antwort: "(Keine LLM-Antwort erhalten)"

        Raises:
            ConnectionError: Ollama-Dienst nicht erreichbar (nicht gestartet oder
                             falsche URL in OLLAMA_BASE_URL)
            TimeoutError:    Modell hat nicht innerhalb von self.timeout Sekunden
                             geantwortet (Modell zu groß, System überlastet)
            requests.exceptions.RequestException: Sonstige HTTP-Fehler (z.B. 404,
                             Modell nicht geladen)
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

            # Leistungsmetriken aus der Ollama-Antwort extrahieren und loggen.
            # total_duration kommt in Nanosekunden → Umrechnung in Sekunden.
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

    # ── Streaming-Anfrage ─────────────────────────────────────────────────────

    def generate_stream(self,
                        system_prompt: str,
                        user_prompt: str,
                        temperature: float = 0.7,
                        max_tokens: int = 2000):
        """
        Sendet einen LLM-Request an Ollama mit Token-für-Token Streaming.

        Im Gegensatz zu generate() wartet diese Methode nicht auf die
        vollständige Antwort, sondern liefert jeden Token sofort als Generator.
        Ideal für SSE (Server-Sent Events) im Frontend, damit der Nutzer
        die LLM-Ausgabe in Echtzeit sieht.

        Technisch: Ollama antwortet mit NDJSON (newline-delimited JSON),
        wobei jede Zeile einen Token-Chunk enthält. Das Streaming endet
        wenn chunk['done'] == True.

        Args:
            system_prompt: Rollen-/Kontext-Instruktionen für das Modell
            user_prompt:   Die eigentliche Analyse-Aufgabe oder Frage
            temperature:   Kreativität der Antwort (0.0–1.0)
            max_tokens:    Maximale Antwortlänge in Tokens (Ollama: num_predict)

        Yields:
            str: Einzelne Tokens oder kurze Token-Gruppen aus dem Stream.
                 Leere Strings werden übersprungen.

        Raises:
            ConnectionError: Ollama-Dienst nicht erreichbar
            TimeoutError:    Verbindung hat nach self.timeout Sekunden kein
                             weiteres Token geliefert
            requests.exceptions.RequestException: Sonstige HTTP-Fehler
        """
        import json as _json
        prompt_len = len(system_prompt) + len(user_prompt)
        logger.info(f"Ollama-Stream-Request: model={self.model}, prompt={prompt_len} chars, max_tokens={max_tokens}")

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
                    "stream": True,
                },
                stream=True,
                timeout=self.timeout,
            )
            response.raise_for_status()

            # Jede NDJSON-Zeile enthält einen Token-Chunk.
            # Ungültige Zeilen (leere, fehlerhaftes JSON, Encoding-Probleme)
            # werden stillschweigend übersprungen um den Stream nicht zu unterbrechen.
            for line in response.iter_lines():
                if not line:
                    continue
                try:
                    chunk = _json.loads(line.decode('utf-8'))
                    token = chunk.get('response', '')
                    if token:
                        yield token
                    if chunk.get('done', False):
                        break
                except (_json.JSONDecodeError, UnicodeDecodeError):
                    continue

        except requests.exceptions.ConnectionError:
            msg = f"Ollama nicht erreichbar unter {self.base_url}. Ist Ollama gestartet?"
            logger.error(msg)
            raise ConnectionError(msg)
        except requests.exceptions.Timeout:
            msg = f"Ollama-Timeout nach {self.timeout}s. Modell '{self.model}' antwortet nicht rechtzeitig."
            logger.error(msg)
            raise TimeoutError(msg)
        except requests.exceptions.RequestException as e:
            logger.error(f"Ollama-Stream-API-Fehler: {e}")
            raise
