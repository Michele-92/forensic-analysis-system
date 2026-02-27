"""
REPARATUR #59: AI Preprocessor mit verbessertem Logging.

Bereitet Daten für KI/LLM-Analyse vor.
"""

import logging
from typing import List, Dict, Any
import json

# REPARATUR #60: Besseres Logging für AI Preprocessor
logger = logging.getLogger(__name__)


class AIPreprocessor:
    """Bereitet forensische Daten für LLM-Analyse vor."""
    
    @staticmethod
    def prepare_timeline_for_llm(timeline: List[Dict],
                                 max_events: int = 1000,
                                 focus: str = 'suspicious') -> List[Dict]:
        """
        REPARATUR #61: Bereitet Timeline für LLM vor mit besserem Logging.
        
        Args:
            timeline: Vollständige Timeline
            max_events: Max. Events (Token-Limit)
            focus: Filter (all, suspicious, recent)
        
        Returns:
            Gefilterte und sortierte Timeline
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
            
            # Simplifiziere für LLM
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
            return timeline
    
    @staticmethod
    def _is_suspicious(event: Dict) -> bool:
        """Heuristik fuer verdaechtige Events. Nutzt event_type UND description."""
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

        # Anomalie-Score (falls bereits gesetzt)
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
        REPARATUR #63: Erstellt Kontext-Zusammenfassung für LLM mit Logging.
        
        Args:
            artifacts: Alle gesammelten Artefakte
        
        Returns:
            Text-Zusammenfassung
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
        Extrahiert Key-Indicators (IOCs) aus Timeline-Events.
        Unterstuetzt sowohl Filesystem- als auch Log-parsed Events.
        """
        import re

        logger.info(f"Extrahiere Key-Indicators aus {len(timeline)} Events")

        indicators = {
            'ips': set(),
            'domains': set(),
            'users': set(),
            'processes': set(),
            'files': set(),
            'hostnames': set(),
        }

        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|de|ru|cn|info|biz|xyz)\b'

        try:
            for event in timeline:
                desc = event.get('description', '')
                meta = event.get('metadata', {}) if isinstance(event.get('metadata'), dict) else {}

                # Kombinierter Text fuer Regex-Suche
                search_text = desc + ' ' + meta.get('message', '') + ' ' + meta.get('raw_line', '')

                # IPs — aus Text und expliziten Feldern
                indicators['ips'].update(re.findall(ip_pattern, search_text))
                if meta.get('src_ip'):
                    indicators['ips'].add(meta['src_ip'])

                # Domains
                indicators['domains'].update(re.findall(domain_pattern, search_text))

                # Users — aus Metadata-Feldern und Text
                if meta.get('user') and meta['user'] not in ('-', 'None', ''):
                    indicators['users'].add(str(meta['user']))
                # "user:" Pattern in Text
                for pattern in [r'user[=: ]+(\w+)', r'for (\w+) from']:
                    for match in re.findall(pattern, search_text, re.IGNORECASE):
                        if match and len(match) > 1:
                            indicators['users'].add(match)

                # Processes
                if meta.get('process') and meta['process'] not in ('', 'None'):
                    indicators['processes'].add(str(meta['process']))

                # Hostnames
                if meta.get('hostname') and meta['hostname'] not in ('', 'None'):
                    indicators['hostnames'].add(str(meta['hostname']))

                # Files/Paths
                if meta.get('path') and meta['path'] not in ('/', ''):
                    indicators['files'].add(str(meta['path']))
                if meta.get('name'):
                    indicators['files'].add(str(meta['name']))

            # Localhost / triviale Eintraege filtern
            indicators['ips'].discard('127.0.0.1')
            indicators['ips'].discard('0.0.0.0')

            # Konvertiere sets zu lists
            result = {k: sorted(list(v)) for k, v in indicators.items()}

            logger.info(f"Key-Indicators extrahiert:")
            for key, vals in result.items():
                if vals:
                    logger.info(f"  {key}: {len(vals)} ({', '.join(vals[:5])}{'...' if len(vals) > 5 else ''})")

            return result
        except Exception as e:
            logger.error(f"Fehler beim Indicators-Extraction: {e}")
            return {k: [] for k in indicators.keys()}
    
    @staticmethod
    def format_for_prompt(timeline: List[Dict],
                         context: str = "",
                         max_length: int = 10000) -> str:
        """
        REPARATUR #64: Formatiert Daten für LLM-Prompt mit Logging.
        
        Args:
            timeline: Timeline-Events
            context: Zusätzlicher Kontext
            max_length: Max. Zeichen
        
        Returns:
            Formatierter String für LLM-Prompt
        """
        logger.debug(f"→ Formatiere {len(timeline)} Events für LLM-Prompt (max_length={max_length})")
        
        try:
            output = f"Context: {context}\n\nTimeline Events:\n"
            truncated = False
            
            for i, event in enumerate(timeline, 1):
                line = f"{i}. [{event.get('timestamp')}] {event.get('description')}\n"
                
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