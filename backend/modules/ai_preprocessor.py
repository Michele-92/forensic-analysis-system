"""
================================================================================
AI PREPROCESSOR — Aufbereitung forensischer Daten für LLM-Analyse
================================================================================
Filtert, priorisiert und formatiert normalisierte Timeline-Events für die
Übergabe an den Large Language Model (LLM) Agenten.

Kernaufgaben:
    1. Filterung        — Reduziert potentiell tausende Events auf die
                          verdächtigsten (Standard: max. 1000), um das
                          Token-Limit des LLMs nicht zu überschreiten.
    2. IOC-Extraktion   — Erkennt und bündelt Indicators of Compromise (IPs,
                          Domains, Benutzer, Prozesse, Dateipfade, Hostnamen)
                          aus allen Event-Beschreibungen und Metadaten.
    3. Kontext-Summary  — Erstellt eine kompakte Zusammenfassung der Analyse-
                          session (Zeitraum, Event-Anzahl, bekannte IOCs).
    4. Prompt-Formatierung — Konvertiert Events in einen lesbaren Text-Block,
                          der direkt in einen LLM-Prompt eingefügt werden kann.

Verdächtigkeits-Heuristik (in _is_suspicious):
    Ein Event gilt als verdächtig wenn EINES der folgenden zutrifft:
    - event_type ist in der Liste hochverdächtiger Typen (z.B. 'auth_failure')
    - is_anomaly=True oder anomaly_score > 0.5 (vom AnomalyDetector gesetzt)
    - Beschreibung oder Nachricht enthält verdächtige Schlüsselwörter

Verwendung:
    # Verdächtige Events für LLM filtern
    top_events = AIPreprocessor.prepare_timeline_for_llm(timeline, max_events=1000)

    # IOCs extrahieren
    indicators = AIPreprocessor.extract_key_indicators(timeline)
    # → {'ips': ['185.220.101.42'], 'users': ['root', 'admin'], ...}

    # Kontext-Zusammenfassung erstellen
    summary = AIPreprocessor.create_context_summary(artifacts)

    # LLM-Prompt formatieren
    prompt_text = AIPreprocessor.format_for_prompt(top_events, context=summary)

Abhängigkeiten:
    - Standard-Library (re, json, logging)

Kontext: LFX Forensic Analysis System — Pipeline Stage 7 (LLM-Vorverarbeitung)
"""

import logging
from typing import List, Dict, Any
import json

# ── Modul-Logger ───────────────────────────────────────────────────────────────
logger = logging.getLogger(__name__)


# ── Haupt-Klasse ───────────────────────────────────────────────────────────────

class AIPreprocessor:
    """
    Bereitet forensische Timeline-Daten für die LLM-Analyse vor.

    Alle Methoden sind als @staticmethod implementiert, da die Klasse
    keinen internen Zustand verwaltet. Sie kann ohne Instanziierung
    direkt aufgerufen werden.

    Zusammenspiel mit anderen Modulen:
        - Eingabe: normalisierte Events aus DataNormalizer (Stage 5)
                   mit anomaly_score-Feldern aus AnomalyDetector (Stage 6)
        - Ausgabe: reduzierte/formatierte Events für ForensicLLMAgent (Stage 8)
    """

    @staticmethod
    def prepare_timeline_for_llm(timeline: List[Dict],
                                 max_events: int = 1000,
                                 focus: str = 'suspicious') -> List[Dict]:
        """
        Filtert und priorisiert Timeline-Events für die LLM-Übergabe.

        Reduziert die Timeline nach der gewählten Strategie auf max_events
        und vereinfacht die Event-Struktur auf die für das LLM relevanten
        Felder (timestamp, type, description, source).

        Filter-Strategien:
            'suspicious' — Nur Events, die _is_suspicious() als verdächtig markiert
                           (empfohlen; fokussiert das LLM auf relevante Aktivitäten)
            'recent'     — Alle Events, neueste zuerst
            'all'        — Alle Events ohne Filter, nur durch max_events begrenzt

        Args:
            timeline:   Vollständige normalisierte Timeline (nach Anomalie-Erkennung).
            max_events: Maximale Anzahl Events für den LLM-Prompt (Token-Budget).
            focus:      Filter-Strategie ('suspicious', 'recent', 'all').

        Returns:
            Liste vereinfachter Event-Dicts mit den Feldern:
                {'timestamp': str, 'type': str, 'description': str, 'source': str}
        """
        logger.info(f"→ Bereite Timeline für LLM vor: {len(timeline)} Events → focus='{focus}'")

        try:
            # Filter nach Focus
            if focus == 'suspicious':
                filtered = [e for e in timeline if AIPreprocessor._is_suspicious(e)]
                logger.debug(f"  ✓ Gefiltert: {len(timeline)} → {len(filtered)} verdächtige Events")
            elif focus == 'recent':
                filtered = sorted(timeline, key=lambda x: x.get('timestamp', ''), reverse=True)
                logger.debug(f"  ✓ Sortiert nach aktuellen Events")
            else:
                filtered = timeline
                logger.debug(f"  ✓ Kein Filter (all)")

            # Limitiere
            result = filtered[:max_events]
            logger.debug(f"  ✓ Limitiert: {len(filtered)} → {len(result)} Events (max={max_events})")

            # Simplifiziere für LLM — nur die für den LLM relevanten Kernfelder
            simplified = []
            for event in result:
                simplified.append({
                    'timestamp': event.get('timestamp'),
                    'type': event.get('event_type'),
                    'description': event.get('description'),
                    'source': event.get('source')
                })

            logger.info(f"✓ Timeline vorbereitet: {len(simplified)} Events für LLM")
            return simplified
        except Exception as e:
            logger.error(f"✗ Fehler beim Timeline-Preprocessing: {e}")
            # Fallback: ungefilterte Timeline zurückgeben
            return timeline

    @staticmethod
    def _is_suspicious(event: Dict) -> bool:
        """
        Heuristik zur Bewertung ob ein Event verdächtig ist.

        Prüft drei unabhängige Kriterien (OR-Verknüpfung):
            1. Event-Typ in der Liste bekannt-verdächtiger Typen
               (gesetzt vom LogParser oder Normalizer)
            2. ML-Anomalie-Markierung (is_anomaly=True oder score > 0.5)
               (gesetzt vom AnomalyDetector in Stage 6)
            3. Verdächtige Schlüsselwörter in description oder metadata.message

        Args:
            event: Normalisiertes Event-Dict.

        Returns:
            True wenn das Event als verdächtig eingestuft wird, sonst False.
        """
        # Hoch-verdaechtige Event-Typen (vom LogParser gesetzt)
        suspicious_types = {
            'auth_failure', 'credential_access', 'data_exfiltration',
            'anti_forensics', 'network_attack', 'privilege_escalation',
            'suspicious_request', 'network_tool', 'account_modification',
            'sqli_attempt', 'xss_attempt', 'http_error', 'file_download',
            'permission_change', 'firewall_block', 'firewall_drop',
            'firewall_deny', 'system_alert',
        }

        event_type = event.get('event_type', '')
        if event_type in suspicious_types:
            return True

        # Anomalie-Score (falls bereits gesetzt vom AnomalyDetector)
        if event.get('is_anomaly', False):
            return True
        if event.get('anomaly_score', 0) > 0.5:
            return True

        # Keyword-Check in description und metadata.message
        meta = event.get('metadata', {}) if isinstance(event.get('metadata'), dict) else {}
        desc = (event.get('description', '') + ' ' + meta.get('message', '')).lower()

        suspicious_keywords = [
            'root', 'admin', 'sudo', 'ssh', 'tmp', 'failed', 'invalid',
            'cron', 'scheduled', 'powershell', 'cmd.exe', 'chmod',
            'base64', 'wget', 'curl', 'nc', 'netcat', 'nmap',
            'shadow', 'passwd', 'exfil', 'reverse', 'backdoor',
        ]

        return any(kw in desc for kw in suspicious_keywords)

    @staticmethod
    def create_context_summary(artifacts: Dict[str, Any]) -> str:
        """
        Erstellt eine kompakte Kontext-Zusammenfassung für den LLM-Prompt.

        Fasst die wichtigsten Metadaten der Analyse-Session zusammen:
        Eingabetyp, Gesamtzahl der Events, Zeitraum der Timeline und
        Anzahl bekannter IOCs. Wird als Kontext-Header im LLM-Prompt verwendet.

        Args:
            artifacts: Vollständiges Artefakt-Dict aus der Pipeline mit
                       optionalen Feldern 'metadata', 'timeline', 'iocs'.

        Returns:
            Pipe-separierter Zusammenfassungsstring, z.B.:
            "System: disk_image | Total Events: 4821 | Timespan: 2024-01-01T00:00 to 2024-01-15T23:59"
            Fallback bei Fehlern: "Unknown Context"
        """
        logger.debug("→ Erstelle Context-Summary...")

        summary_parts = []

        try:
            # System-Info
            if 'metadata' in artifacts:
                summary_parts.append(f"System: {artifacts['metadata'].get('input_type', 'unknown')}")

            # Event-Counts
            timeline = artifacts.get('timeline', [])
            summary_parts.append(f"Total Events: {len(timeline)}")

            # Zeitraum
            if timeline:
                timestamps = [e.get('timestamp') for e in timeline if e.get('timestamp')]
                if timestamps:
                    summary_parts.append(f"Timespan: {min(timestamps)} to {max(timestamps)}")

            # IOCs
            iocs = artifacts.get('iocs', [])
            if iocs:
                summary_parts.append(f"Known IOCs: {len(iocs)}")

            result = " | ".join(summary_parts)
            logger.debug(f"✓ Context-Summary: {result}")
            return result
        except Exception as e:
            logger.error(f"✗ Fehler beim Context-Summary-Creation: {e}")
            return "Unknown Context"

    @staticmethod
    def extract_key_indicators(timeline: List[Dict]) -> Dict[str, List[str]]:
        """
        Extrahiert Indicators of Compromise (IOCs) aus allen Timeline-Events.

        Durchsucht sowohl strukturierte Metadaten-Felder als auch freien Text
        (description, message, raw_line) nach forensisch relevanten Indikatoren.

        Erkannte IOC-Kategorien:
            ips        — IPv4-Adressen (öffentlich und privat, außer Localhost)
            domains    — Domänennamen mit bekannten TLDs (.com, .net, .org, etc.)
            users      — Benutzernamen aus metadata.user und Text-Patterns
            processes  — Prozessnamen aus metadata.process
            files      — Dateipfade aus metadata.path und metadata.name
            hostnames  — Hostnamen aus metadata.hostname

        Hinweis: Localhost-Adressen (127.0.0.1, 0.0.0.0) werden automatisch
        herausgefiltert. Alle Ergebnisse sind dedupliziert und sortiert.

        Args:
            timeline: Normalisierte Timeline (vorzugsweise nach Anomalie-Erkennung).

        Returns:
            Dict mit Listen von IOC-Strings pro Kategorie:
            {
                'ips':       ['185.220.101.42', ...],
                'domains':   ['evil.ru', ...],
                'users':     ['root', 'administrator', ...],
                'processes': ['nc', 'wget', ...],
                'files':     ['/tmp/backdoor', ...],
                'hostnames': ['attacker-host', ...]
            }
        """
        import re

        logger.info(f"Extrahiere Key-Indicators aus {len(timeline)} Events")

        # Sets für automatische Deduplizierung während der Extraktion
        indicators = {
            'ips': set(),
            'domains': set(),
            'users': set(),
            'processes': set(),
            'files': set(),
            'hostnames': set(),
        }

        # Regex für IPv4-Adressen (einfache Variante, ausreichend für forensische Logs)
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        # Regex für Domänennamen mit gängigen TLDs (englisch + internationale)
        domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|de|ru|cn|info|biz|xyz)\b'

        try:
            for event in timeline:
                desc = event.get('description', '')
                meta = event.get('metadata', {}) if isinstance(event.get('metadata'), dict) else {}

                # Kombinierter Text fuer Regex-Suche (alle Textquellen zusammenführen)
                search_text = desc + ' ' + meta.get('message', '') + ' ' + meta.get('raw_line', '')

                # ── IPs — aus Text und expliziten Feldern ─────────────────────
                indicators['ips'].update(re.findall(ip_pattern, search_text))
                if meta.get('src_ip'):
                    indicators['ips'].add(meta['src_ip'])

                # ── Domains ───────────────────────────────────────────────────
                indicators['domains'].update(re.findall(domain_pattern, search_text))

                # ── Users — aus Metadata-Feldern und Text-Patterns ────────────
                if meta.get('user') and meta['user'] not in ('-', 'None', ''):
                    indicators['users'].add(str(meta['user']))
                # "user:" Pattern in Text
                for pattern in [r'user[=: ]+(\w+)', r'for (\w+) from']:
                    for match in re.findall(pattern, search_text, re.IGNORECASE):
                        if match and len(match) > 1:
                            indicators['users'].add(match)

                # ── Processes ─────────────────────────────────────────────────
                if meta.get('process') and meta['process'] not in ('', 'None'):
                    indicators['processes'].add(str(meta['process']))

                # ── Hostnames ─────────────────────────────────────────────────
                if meta.get('hostname') and meta['hostname'] not in ('', 'None'):
                    indicators['hostnames'].add(str(meta['hostname']))

                # ── Files/Paths ───────────────────────────────────────────────
                if meta.get('path') and meta['path'] not in ('/', ''):
                    indicators['files'].add(str(meta['path']))
                if meta.get('name'):
                    indicators['files'].add(str(meta['name']))

            # Localhost / triviale Eintraege filtern (kein forensischer Mehrwert)
            indicators['ips'].discard('127.0.0.1')
            indicators['ips'].discard('0.0.0.0')

            # Konvertiere sets zu sortierten lists für serialisierbares Ergebnis
            result = {k: sorted(list(v)) for k, v in indicators.items()}

            logger.info(f"Key-Indicators extrahiert:")
            for key, vals in result.items():
                if vals:
                    logger.info(f"  {key}: {len(vals)} ({', '.join(vals[:5])}{'...' if len(vals) > 5 else ''})")

            return result
        except Exception as e:
            logger.error(f"Fehler beim Indicators-Extraction: {e}")
            # Sichere leere Rückgabe bei Fehlern
            return {k: [] for k in indicators.keys()}

    @staticmethod
    def format_for_prompt(timeline: List[Dict],
                         context: str = "",
                         max_length: int = 10000) -> str:
        """
        Formatiert Timeline-Events als lesbaren Text-Block für einen LLM-Prompt.

        Erstellt eine nummerierte Liste aller Events mit Timestamp und
        Beschreibung. Überschreitet der Text max_length Zeichen, wird
        die Ausgabe mit "... (truncated)" abgeschnitten, um das Token-Limit
        des LLMs zu respektieren.

        Args:
            timeline:   Liste (vereinfachter) Events, üblicherweise von
                        prepare_timeline_for_llm() vorbereitet.
            context:    Kontextstring (z.B. von create_context_summary()),
                        wird als Header eingefügt.
            max_length: Maximale Zeichenanzahl der Ausgabe (Standard: 10.000).

        Returns:
            Formatierter Multi-line-String, bereit zur Einbettung in einen
            LLM-Prompt, z.B.:
                "Context: System: disk_image | Total Events: 4821
                 Timeline Events:
                 1. [2024-01-01T03:14:07] Failed login for root from 185.220.101.42
                 2. [2024-01-01T03:14:12] Permission change: /etc/crontab
                 ... (truncated)"
        """
        logger.debug(f"→ Formatiere {len(timeline)} Events für LLM-Prompt (max_length={max_length})")

        try:
            output = f"Context: {context}\n\nTimeline Events:\n"
            truncated = False

            for i, event in enumerate(timeline, 1):
                line = f"{i}. [{event.get('timestamp')}] {event.get('description')}\n"

                # Abbrechen wenn Token-Budget erschöpft ist
                if len(output) + len(line) > max_length:
                    output += "\n... (truncated)"
                    truncated = True
                    break

                output += line

            logger.debug(f"✓ Prompt formatiert: {len(output)} Zeichen (truncated: {truncated})")
            return output
        except Exception as e:
            logger.error(f"✗ Fehler beim Prompt-Formatting: {e}")
            return f"Error formatting prompt: {str(e)}"
