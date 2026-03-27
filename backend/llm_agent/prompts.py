"""
================================================================================
PROMPT MANAGER — Zentrale Verwaltung aller LLM-Prompt-Templates
================================================================================
Verwaltet die Prompt-Templates und System-Prompts für alle LLM-Agenten der
forensischen Analyse-Pipeline. Trennt Prompt-Inhalte vom Agenten-Code und
ermöglicht das Austauschen von Templates ohne Code-Änderungen.

Aufgaben:
    - Laden von Template-Dateien aus prompts/templates/*.txt (mit Fallback auf
      eingebettete Default-Templates bei fehlenden Dateien)
    - Laden von System-Prompts aus prompts/system_prompts/*.txt
    - Befüllen der Templates mit konkreten Analysedaten (format()-Aufrufe)
    - Unterstützung zweier Analyse-Modi:
        * Standard-Forensik (Opfer-Perspektive)
        * Täterinfrastruktur-Analyse (Angreifer-Perspektive)

Verwendung:
    pm = PromptManager()

    # Standard-Analyse:
    prompt = pm.get_anomaly_detection_prompt(timeline_events)
    system = pm.get_system_prompt(role='forensic_expert')

    # Täterinfrastruktur-Modus:
    prompt = pm.get_attacker_infra_prompt(infra_events, iocs, mitre_tactics)
    system = pm.get_system_prompt(role='attacker_infra')

Abhängigkeiten:
    - pathlib (Template-Pfad-Auflösung)
    - json (Serialisierung der Timeline-Daten für den Prompt)

Template-Verzeichnis: <repo-root>/prompts/templates/*.txt
System-Prompts:       <repo-root>/prompts/system_prompts/<role>.txt

Kontext: LFX Forensic Analysis System — LLM-Integrations-Schicht
================================================================================
"""
from pathlib import Path
from typing import Dict, List
from datetime import datetime
import json
import logging

logger = logging.getLogger(__name__)

# Absoluter Pfad zum prompts/-Verzeichnis (zwei Ebenen über diesem Modul:
# backend/llm_agent/prompts.py → backend/ → repo-root/ → prompts/)
PROMPTS_DIR = Path(__file__).parent.parent.parent / "prompts"

# ── Eingebettete Default-Templates ───────────────────────────────────────────
# Fallback-Templates, die verwendet werden wenn keine Template-Dateien
# im prompts/templates/-Verzeichnis existieren (z.B. frische Installation,
# fehlende Datei, Deployment ohne prompts/-Ordner).
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
    # Speziell für den Modus analysis_mode='attacker_infra':
    # Perspektive wechselt vom Opfersystem zur Infrastruktur des Angreifers.
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

# ── Eingebettete System-Prompts ───────────────────────────────────────────────
# System-Prompts definieren die Rolle/Persona des LLM-Modells.
# Sie werden als "system"-Feld im Ollama-API-Aufruf übergeben.

# Standard-Forensik-Experte (Perspektive: angegriffenes Opfersystem)
_DEFAULT_SYSTEM_PROMPT = (
    "Du bist ein erfahrener digitaler Forensik-Experte. "
    "Analysiere die vorgelegten Daten sorgfältig und gib strukturierte, "
    "faktische Einschätzungen ab. Nutze MITRE ATT&CK Referenzen wo möglich."
)

# Spezialist für Täterinfrastruktur-Analyse (Perspektive: Server/System des Angreifers).
# Betont die umgekehrte Analyseperspektive und MITRE Resource Development Taktiken.
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


# ── Hauptklasse ───────────────────────────────────────────────────────────────

class PromptManager:
    """
    Verwaltet und befüllt alle LLM-Prompt-Templates der forensischen Pipeline.

    Beim Initialisieren werden Template-Dateien aus dem Dateisystem geladen.
    Fehlt das Verzeichnis oder einzelne Dateien, werden die eingebetteten
    Default-Templates (_DEFAULT_TEMPLATES) als Fallback verwendet.

    Für jeden der drei Analyse-Schritte (Anomalie-Erkennung, Timeline-
    Interpretation, Report-Generierung) sowie für den Täterinfrastruktur-Modus
    gibt es eine dedizierte get_*-Methode, die das Template mit konkreten
    Analysedaten befüllt.

    Beispiel:
        pm = PromptManager()
        user_prompt = pm.get_anomaly_detection_prompt(timeline[:100])
        system_prompt = pm.get_system_prompt('forensic_expert')
    """

    def __init__(self):
        # Templates werden einmalig beim Start geladen.
        # Spätere Änderungen an Template-Dateien erfordern einen Neustart.
        self.templates = self._load_templates()

    # ── Template-Laden ────────────────────────────────────────────────────────

    def _load_templates(self) -> Dict[str, str]:
        """
        Lädt alle .txt-Dateien aus prompts/templates/ in ein Dictionary.

        Datei-Stammname (ohne .txt) wird als Key verwendet, Dateiinhalt als Value.
        Startet mit den Default-Templates und überschreibt diese mit Datei-Inhalten,
        falls vorhanden. So bleiben Defaults für Templates ohne eigene Datei erhalten.

        Returns:
            Dict mit Template-Namen als Keys und Template-Text als Values.
        """
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

    # ── Standard-Analyse-Prompts ──────────────────────────────────────────────

    def get_anomaly_detection_prompt(self, timeline: List[Dict]) -> str:
        """
        Erstellt den User-Prompt für Schritt 1 der LLM-Analyse: Anomalie-Erkennung.

        Limitiert die Timeline auf die ersten 100 Events um den Kontext-Umfang
        des Modells nicht zu überschreiten.

        Args:
            timeline: Liste von normalisierten Timeline-Events (Dicts)

        Returns:
            Befüllter Prompt-Text als String
        """
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
        """
        Erstellt den User-Prompt für Schritt 2: Timeline-Interpretation.

        Kombiniert die Timeline mit bekannten IOCs aus dem RAG-Handler,
        damit das Modell gezielt auf bekannte Bedrohungs-Indikatoren eingehen kann.

        Args:
            timeline: Vollständige normalisierte Timeline (alle gefilterten Events)
            iocs:     Liste bekannter IOC-Strings aus der RAG-Knowledge-Base.
                      Bei None/leer wird "Keine bekannten IOCs" eingefügt.

        Returns:
            Befüllter Prompt-Text als String
        """
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
        """
        Erstellt den User-Prompt für Schritt 3: Report-Generierung.

        Übergibt die konsolidierten Findings und Risk-Scores aus den
        vorherigen Analyse-Schritten für die finale Berichts-Erstellung.

        Args:
            findings:    Liste der identifizierten Findings als Dicts
            risk_scores: Liste der Anomalie-Scores (0.0–1.0) aus dem
                         IsolationForest-Modell

        Returns:
            Befüllter Prompt-Text als String
        """
        template = self.templates.get("report_generation", _DEFAULT_TEMPLATES["report_generation"])
        try:
            return template.format(
                findings=json.dumps(findings, indent=2, default=str),
                risk_scores=risk_scores
            )
        except (KeyError, IndexError) as e:
            logger.warning(f"Template-Formatierung fehlgeschlagen: {e}")
            return f"Erstelle einen Report:\n{json.dumps(findings, indent=2, default=str)}"

    # ── Täterinfrastruktur-Prompts ────────────────────────────────────────────

    def get_attacker_infra_prompt(self,
                                  infra_events: List[Dict],
                                  iocs: Dict,
                                  mitre_tactics: List[str] = None) -> str:
        """
        Erstellt den Analyse-Prompt für den Täterinfrastruktur-Modus.

        Verwendet das 'attacker_infra_analysis' Template und wechselt die
        Analyse-Perspektive: Statt angegriffenes Opfer wird die Infrastruktur
        des Angreifers untersucht (C2-Server, Staging-Systeme, Proxies).

        Dieser Prompt ersetzt get_timeline_interpretation_prompt() wenn
        analysis_mode='attacker_infra' gesetzt ist.

        Args:
            infra_events:  Liste der Infrastruktur-relevanten Events (max. 80
                           werden übergeben um den Kontext-Umfang zu begrenzen)
            iocs:          Dict mit IOC-Kategorien als Keys (ips, domains, etc.)
                           und Listen von IOC-Werten als Values
            mitre_tactics: Liste erkannter MITRE ATT&CK Taktik-Namen

        Returns:
            Befüllter Prompt-Text als String
        """
        template = self.templates.get(
            "attacker_infra_analysis",
            _DEFAULT_TEMPLATES["attacker_infra_analysis"]
        )

        # IOC-Dictionary in lesbaren Text umwandeln (max. 20 Werte pro Kategorie)
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
        """
        Erstellt den Report-Prompt für den Täterinfrastruktur-Modus.

        Kombiniert Triage- und DFIR-Analyst-Ergebnisse mit Metadaten der
        analysierten Datei für einen finalen Täterinfrastruktur-Bericht.
        Entspricht get_report_generation_prompt() für den Standard-Modus.

        Args:
            triage_result:  Markdown-Output des Triage-Agenten
            analyst_result: Markdown-Output des DFIR-Analyst-Agenten
            summary:        Analyse-Zusammenfassung (input_file, input_type,
                            analysis_timestamp) aus analysis_summary.json

        Returns:
            Befüllter Prompt-Text als String
        """
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

    # ── System-Prompts ────────────────────────────────────────────────────────

    def get_system_prompt(self, role: str = "forensic_expert") -> str:
        """
        Lädt den System-Prompt für die angegebene Agenten-Rolle.

        Prüft zuerst auf eingebettete Spezial-Rollen (attacker_infra), dann
        sucht nach einer .txt-Datei in prompts/system_prompts/. Falls keine
        Datei gefunden wird, wird der allgemeine Default-Prompt verwendet.

        Spezielle Rollen (eingebettet, keine Datei erforderlich):
            - 'attacker_infra': Täterinfrastruktur-Analyst (umgekehrte Perspektive,
              Fokus auf C2, Staging, MITRE Resource Development)

        Datei-basierte Rollen (aus prompts/system_prompts/<role>.txt):
            - 'forensic_expert': Standard-Forensik-Experte (Opfer-Perspektive)
            - Weitere Rollen können durch neue .txt-Dateien hinzugefügt werden

        Args:
            role: Rollenname (Dateiname ohne .txt oder eingebettete Rolle)

        Returns:
            System-Prompt als String. Fallback: _DEFAULT_SYSTEM_PROMPT
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
