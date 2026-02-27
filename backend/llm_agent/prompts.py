"""Zentrale Prompt-Verwaltung für LLM-Agent."""
from pathlib import Path
from typing import Dict, List
from datetime import datetime
import json
import logging

logger = logging.getLogger(__name__)

PROMPTS_DIR = Path(__file__).parent.parent.parent / "prompts"

# Fallback-Templates falls Dateien fehlen
_DEFAULT_TEMPLATES = {
    "anomaly_detection": (
        "Analysiere die folgende forensische Timeline auf Anomalien.\n\n"
        "Timeline Events:\n{timeline}\n\n"
        "Identifiziere verdächtige Aktivitäten, ungewöhnliche Muster und potenzielle "
        "Indicators of Compromise (IOCs). Bewerte jede Anomalie mit einem Risiko-Score."
    ),
    "timeline_interpretation": (
        "Interpretiere die folgende forensische Timeline.\n\n"
        "Timeline Events:\n{timeline}\n\n"
        "Bekannte IOCs: {iocs}\n\n"
        "Erstelle eine strukturierte Analyse mit Hypothesen über mögliche Angriffsvektoren."
    ),
    "report_generation": (
        "Erstelle einen forensischen Bericht basierend auf den folgenden Ergebnissen.\n\n"
        "Findings:\n{findings}\n\n"
        "Risk Scores: {risk_scores}\n\n"
        "Der Bericht soll eine Executive Summary, detaillierte Findings und "
        "Empfehlungen enthalten."
    ),
    # ── Täterinfrastruktur-Analyse ─────────────────────────────────────────
    "attacker_infra_analysis": (
        "Du analysierst die Infrastruktur eines Angreifers (kein Opfersystem).\n\n"
        "Erkannte Infrastruktur-Events:\n{infra_events}\n\n"
        "Bekannte IOCs (IPs, Domains, Tools):\n{iocs}\n\n"
        "MITRE ATT&CK Taktiken die erkannt wurden: {mitre_tactics}\n\n"
        "Beantworte folgende Fragen:\n"
        "1. Welche C2-Infrastruktur wurde genutzt? (IPs, Domains, Protokolle)\n"
        "2. Welche Tools wurden auf dem System vorbereitet/eingesetzt?\n"
        "3. Gibt es Hinweise auf VPN/Proxy-Nutzung zur Verschleierung?\n"
        "4. Wurden Daten exfiltriert? Falls ja — wohin und wie viel?\n"
        "5. Welche MITRE ATT&CK Techniken (Resource Development, C2) wurden eingesetzt?\n"
        "6. Wie ist die Täterinfrastruktur mit anderen Systemen verbunden?\n\n"
        "Antworte strukturiert in Markdown."
    ),
    "attacker_infra_report": (
        "Erstelle einen Täterinfrastruktur-Bericht für folgende Analyse:\n\n"
        "Triage-Ergebnis:\n{triage_result}\n\n"
        "DFIR-Analyse:\n{analyst_result}\n\n"
        "Untersuchte Datei: {input_file} (Typ: {input_type})\n"
        "Analysezeitpunkt: {timestamp}\n\n"
        "Der Bericht soll folgende Abschnitte enthalten:\n"
        "1. Executive Summary (Täterinfrastruktur-Perspektive)\n"
        "2. C2-Infrastruktur Übersicht\n"
        "3. Eingesetzte Tools und Capabilities\n"
        "4. Verschleierungstechniken (VPN, Proxy, Obfuscation)\n"
        "5. Exfiltrations-Analyse\n"
        "6. MITRE ATT&CK Mapping (Resource Development, C2, Exfiltration)\n"
        "7. Attributions-Hinweise (falls vorhanden)\n"
        "8. Empfehlungen für weitere Ermittlungen"
    ),
}

_DEFAULT_SYSTEM_PROMPT = (
    "Du bist ein erfahrener digitaler Forensik-Experte. "
    "Analysiere die vorgelegten Daten sorgfältig und gib strukturierte, "
    "faktische Einschätzungen ab. Nutze MITRE ATT&CK Referenzen wo möglich."
)

_ATTACKER_INFRA_SYSTEM_PROMPT = (
    "Du bist ein erfahrener Threat Intelligence Analyst mit Spezialisierung auf "
    "Täterinfrastruktur-Analyse (Attacker Infrastructure Forensics). "
    "Du untersuchst NICHT ein angegriffenes Opfersystem, sondern die INFRASTRUKTUR DES ANGREIFERS — "
    "also Server, VPS, C2-Server, Staging-Systeme und Proxies die vom Täter genutzt wurden. "
    "\n\n"
    "DEIN FOKUS:\n"
    "- Command & Control (C2) Kommunikation und Beaconing-Muster\n"
    "- Staging-Aktivitäten: Welche Tools wurden vorbereitet und hochgeladen?\n"
    "- VPN/Proxy-Nutzung zur Verschleierung der Täter-Identität\n"
    "- Lateral Movement zwischen Täter-kontrollierten Systemen\n"
    "- Exfiltrations-Kanäle und Datenmengen\n"
    "- MITRE ATT&CK Resource Development (T1583/T1584/T1587/T1608)\n"
    "\n"
    "Nutze ausschließlich MITRE ATT&CK Enterprise v15. "
    "Trenne klar zwischen gesicherten Fakten (Logeinträge) und Schlussfolgerungen."
)


class PromptManager:
    """Lädt und formatiert Prompt-Templates."""

    def __init__(self):
        self.templates = self._load_templates()

    def _load_templates(self) -> Dict[str, str]:
        """Lädt alle Prompt-Templates mit Fallback."""
        templates = dict(_DEFAULT_TEMPLATES)
        template_dir = PROMPTS_DIR / "templates"

        if not template_dir.exists():
            logger.warning(f"Template-Verzeichnis nicht gefunden: {template_dir}, nutze Defaults")
            return templates

        for file in template_dir.glob("*.txt"):
            try:
                templates[file.stem] = file.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as e:
                logger.warning(f"Template {file.name} konnte nicht geladen werden: {e}")

        return templates

    def get_anomaly_detection_prompt(self, timeline: List[Dict]) -> str:
        """Erstellt Anomalie-Erkennungs-Prompt."""
        template = self.templates.get("anomaly_detection", _DEFAULT_TEMPLATES["anomaly_detection"])
        try:
            return template.format(
                timeline=json.dumps(timeline[:100], indent=2, default=str)
            )
        except (KeyError, IndexError) as e:
            logger.warning(f"Template-Formatierung fehlgeschlagen: {e}")
            return f"Analysiere diese Timeline auf Anomalien:\n{json.dumps(timeline[:100], indent=2, default=str)}"

    def get_timeline_interpretation_prompt(self,
                                          timeline: List[Dict],
                                          iocs: List[str] = None) -> str:
        """Erstellt Timeline-Interpretations-Prompt."""
        template = self.templates.get("timeline_interpretation", _DEFAULT_TEMPLATES["timeline_interpretation"])
        ioc_context = ", ".join(iocs) if iocs else "Keine bekannten IOCs"

        try:
            return template.format(
                timeline=json.dumps(timeline, indent=2, default=str),
                iocs=ioc_context
            )
        except (KeyError, IndexError) as e:
            logger.warning(f"Template-Formatierung fehlgeschlagen: {e}")
            return f"Interpretiere diese Timeline:\n{json.dumps(timeline[:100], indent=2, default=str)}\nIOCs: {ioc_context}"

    def get_report_generation_prompt(self,
                                     findings: List[Dict],
                                     risk_scores: List[float]) -> str:
        """Erstellt Report-Generierungs-Prompt."""
        template = self.templates.get("report_generation", _DEFAULT_TEMPLATES["report_generation"])
        try:
            return template.format(
                findings=json.dumps(findings, indent=2, default=str),
                risk_scores=risk_scores
            )
        except (KeyError, IndexError) as e:
            logger.warning(f"Template-Formatierung fehlgeschlagen: {e}")
            return f"Erstelle einen Report:\n{json.dumps(findings, indent=2, default=str)}"

    def get_attacker_infra_prompt(self,
                                  infra_events: List[Dict],
                                  iocs: Dict,
                                  mitre_tactics: List[str] = None) -> str:
        """
        Erstellt den Analyse-Prompt für Täterinfrastruktur-Modus.

        Verwendet das 'attacker_infra_analysis' Template.
        Dieser Prompt ersetzt den Standard-Timeline-Prompt wenn
        analysis_mode='attacker_infra' gesetzt ist.
        """
        template = self.templates.get(
            "attacker_infra_analysis",
            _DEFAULT_TEMPLATES["attacker_infra_analysis"]
        )

        # IOC-Text aufbereiten
        ioc_lines = []
        for key, vals in (iocs or {}).items():
            if vals:
                ioc_lines.append(f"  {key}: {', '.join(str(v) for v in vals[:20])}")
        ioc_text = "\n".join(ioc_lines) if ioc_lines else "Keine IOCs extrahiert"

        # Taktiken-Text
        tactics_text = ", ".join(mitre_tactics) if mitre_tactics else "Keine MITRE-Taktiken erkannt"

        try:
            return template.format(
                infra_events=json.dumps(infra_events[:80], indent=2, default=str),
                iocs=ioc_text,
                mitre_tactics=tactics_text,
            )
        except (KeyError, IndexError) as e:
            logger.warning(f"Infra-Template-Formatierung fehlgeschlagen: {e}")
            return (
                f"Analysiere diese Täterinfrastruktur-Events:\n"
                f"{json.dumps(infra_events[:50], indent=2, default=str)}\n"
                f"IOCs: {ioc_text}"
            )

    def get_attacker_infra_report_prompt(self,
                                         triage_result: str,
                                         analyst_result: str,
                                         summary: Dict = None) -> str:
        """Erstellt den Report-Prompt für Täterinfrastruktur-Modus."""
        template = self.templates.get(
            "attacker_infra_report",
            _DEFAULT_TEMPLATES["attacker_infra_report"]
        )
        summary = summary or {}
        try:
            return template.format(
                triage_result=triage_result,
                analyst_result=analyst_result,
                input_file=summary.get("input_file", "Unbekannt"),
                input_type=summary.get("input_type", "Unbekannt"),
                timestamp=summary.get("analysis_timestamp", datetime.now().isoformat()
                          if hasattr(datetime, 'now') else ""),
            )
        except (KeyError, IndexError) as e:
            logger.warning(f"Infra-Report-Template-Formatierung fehlgeschlagen: {e}")
            return (
                f"Erstelle Täterinfrastruktur-Bericht:\n"
                f"Triage: {triage_result[:500]}\n"
                f"Analyse: {analyst_result[:500]}"
            )

    def get_system_prompt(self, role: str = "forensic_expert") -> str:
        """
        Lädt System-Prompt für Rollen-Definition mit Fallback.

        Spezielle Rollen:
        - 'forensic_expert'    → Standard-Forensik-Experte (Opfer-Perspektive)
        - 'attacker_infra'     → Täterinfrastruktur-Analyst (Angreifer-Perspektive)
        """
        # Eingebauter Attacker-Infra-Prompt (keine Datei nötig)
        if role == "attacker_infra":
            return _ATTACKER_INFRA_SYSTEM_PROMPT

        path = PROMPTS_DIR / "system_prompts" / f"{role}.txt"

        if not path.exists():
            logger.warning(f"System-Prompt nicht gefunden: {path}, nutze Default")
            return _DEFAULT_SYSTEM_PROMPT

        try:
            return path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as e:
            logger.warning(f"System-Prompt konnte nicht gelesen werden: {e}")
            return _DEFAULT_SYSTEM_PROMPT
