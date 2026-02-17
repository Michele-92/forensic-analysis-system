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
        """Heuristik für verdächtige Events."""
        desc = event.get('description', '').lower()
        
        suspicious_keywords = [
            'root', 'admin', 'sudo', 'ssh', 'tmp',
            'cron', 'scheduled', 'powershell', 'cmd.exe',
            'base64', 'wget', 'curl', 'nc', 'netcat'
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
        REPARATUR #62: Extrahiert Key-Indicators aus Timeline mit Logging.
        
        Args:
            timeline: Timeline-Events
        
        Returns:
            Dict mit kategorisierten Indicators (IPs, Domains, Users, etc.)
        """
        import re
        
        logger.info(f"→ Extrahiere Key-Indicators aus {len(timeline)} Events")
        
        indicators = {
            'ips': set(),
            'domains': set(),
            'users': set(),
            'processes': set(),
            'files': set()
        }
        
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
        
        try:
            for event in timeline:
                desc = event.get('description', '')
                
                # IPs
                indicators['ips'].update(re.findall(ip_pattern, desc))
                
                # Domains
                indicators['domains'].update(re.findall(domain_pattern, desc))
                
                # Users (vereinfacht)
                if 'user:' in desc.lower():
                    user = desc.lower().split('user:')[1].split()[0]
                    indicators['users'].add(user)
                
                # Files
                if 'path' in event.get('metadata', {}):
                    indicators['files'].add(event['metadata']['path'])
            
            # Konvertiere sets zu lists
            result = {k: list(v) for k, v in indicators.items()}
            
            logger.info(f"✓ Key-Indicators extrahiert:")
            logger.info(f"  → IPs: {len(result['ips'])}")
            logger.info(f"  → Domains: {len(result['domains'])}")
            logger.info(f"  → Users: {len(result['users'])}")
            logger.info(f"  → Files: {len(result['files'])}")
            
            return result
        except Exception as e:
            logger.error(f"✗ Fehler beim Indicators-Extraction: {e}")
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