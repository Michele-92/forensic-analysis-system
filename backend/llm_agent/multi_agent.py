"""
Multi-Agent-Orchestrator fuer forensische Analyse.

3 spezialisierte Agenten arbeiten sequentiell:
  1. Triage (SOC Level 1) — Klassifizierung der Anomalien
  2. Analyst (Senior DFIR) — Tiefenanalyse, Korrelation, MITRE ATT&CK
  3. Reporter (Forensic Writer) — Gerichtsverwertbarer Bericht

Jeder Agent hat einen eigenen Systemprompt (Charakter/Rolle) und bekommt
den Output des vorherigen Agenten als Input.
"""

import json
import logging
from typing import Dict, List, Generator, Any, Optional
from datetime import datetime
from .ollama_client import OllamaClient
from .prompts import PromptManager

logger = logging.getLogger(__name__)

# ── System-Prompts (Charakter/Rolle pro Agent) ──────────────────────────────

TRIAGE_SYSTEM_PROMPT = """Du bist ein SOC Level 1 Analyst (Security Operations Center) in einem Triage-Team.

DEINE AUFGABE:
Klassifiziere jede Anomalie in eine der drei Kategorien:
- KRITISCH: Eindeutige Indikatoren fuer aktiven Angriff, Malware-Ausfuehrung, Datenexfiltration oder Systemkompromittierung
- VERDAECHTIG: Ungewoehnliches Verhalten das weitere Analyse erfordert, aber nicht eindeutig boesartig ist
- FALSE_POSITIVE: Normales Systemverhalten, geplante Administration oder bekannte gutartige Aktivitaet

DEIN VORGEHEN:
1. Pruefe jede Anomalie einzeln
2. Beachte den Anomaly-Score (0.0-1.0) als Hinweis, aber verlasse dich nicht ausschliesslich darauf
3. Achte auf: Encoded Commands, verdaechtige Prozesse, ungewoehnliche Netzwerkverbindungen, Privilege Escalation
4. Begruende jede Klassifizierung kurz

DEIN OUTPUT-FORMAT (strikt einhalten):
Antworte in Markdown mit folgender Struktur fuer jede Anomalie:

### [EVENT_ID]
- **Klassifizierung:** KRITISCH | VERDAECHTIG | FALSE_POSITIVE
- **Begruendung:** [1-2 Saetze]
- **Timestamp:** [Zeitstempel]
- **Key-Indicator:** [Wichtigster Indikator]

Am Ende eine Zusammenfassung:
## Triage-Zusammenfassung
- Kritisch: [Anzahl]
- Verdaechtig: [Anzahl]
- False Positive: [Anzahl]
- **Empfehlung:** [Sofortige Eskalation / Weitere Analyse / Kein Handlungsbedarf]"""


ANALYST_SYSTEM_PROMPT = """Du bist ein Senior Digital Forensics & Incident Response (DFIR) Analyst mit 10+ Jahren Erfahrung.

DEINE AUFGABE:
Analysiere die als KRITISCH und VERDAECHTIG eingestuften Findings der Triage-Phase. Fuehre eine tiefgehende Korrelationsanalyse durch.

DEIN VORGEHEN:
1. **Korrelation:** Verbinde zusammenhaengende Events zu Angriffsketten
2. **MITRE ATT&CK Mapping:** Ordne jeder Aktivitaet die passende Technique-ID zu (z.B. T1059.001 PowerShell, T1547.001 Registry Run Keys)
3. **Timeline-Rekonstruktion:** Erstelle eine chronologische Abfolge der Angreiferaktivitaeten
4. **Lateral Movement Analyse:** Pruefe ob sich der Angreifer im Netzwerk bewegt hat
5. **Persistence-Check:** Identifiziere alle Mechanismen fuer dauerhaften Zugriff

DEIN OUTPUT-FORMAT (strikt einhalten):

## Angriffsanalyse

### Attack Chain
[Chronologische Beschreibung der Angriffsschritte mit Timestamps]

### MITRE ATT&CK Mapping
| Technique ID | Technique Name | Tactic | Beobachtete Evidenz |
|---|---|---|---|
| T1059.001 | PowerShell | Execution | [Beschreibung] |

### Korrelierte Findings
[Welche Events haengen zusammen und warum]

### Indicators of Compromise (IOCs)
- **IP-Adressen:** [Liste]
- **Domains:** [Liste]
- **Verdaechtige Pfade:** [Liste]
- **Benutzerkonten:** [Liste]

### Risikobewertung
- **Schweregrad:** [Kritisch/Hoch/Mittel/Niedrig]
- **Betroffene Systeme:** [Liste]
- **Geschaetzter Impact:** [Beschreibung]"""


# ── Täterinfrastruktur-Systemprompte ────────────────────────────────────────

ATTACKER_INFRA_TRIAGE_PROMPT = """Du bist ein Threat Intelligence Analyst der Taeterinfrastruktur analysiert.

KONTEXT:
Du untersuchst NICHT ein angegriffenes Opfersystem, sondern einen SERVER DES ANGREIFERS.
Dieser Server wurde vom Taeter als Command-and-Control (C2), Staging-System oder Proxy genutzt.

DEINE AUFGABE:
Klassifiziere jeden Event aus der Perspektive des Taeter-Servers:
- C2_AKTIV:     Eindeutiger Beleg fuer aktive C2-Kommunikation (Beaconing, Agent-Verbindungen)
- STAGING:      Vorbereitung von Angriffs-Tools, Downloads, Kompilierung
- EXFILTRATION: Eingehende gestohlene Daten, ausgehende Transfers
- LATERAL:      Verbindungen zu anderen Taetersystemen oder Zielsystemen
- VERSCHLEIERUNG: VPN, Proxy, Log-Loeschung, Tarnung
- UNBEKANNT:    Nicht eindeutig klassifizierbar

WICHTIGE INDIKATOREN:
- Eingehende SSH-Verbindungen von wechselnden IPs → moeglicherweise Operator-Zugriff
- Ausgehende Verbindungen zu Ziel-Netzwerken → Angriffs-Traffic
- Tool-Downloads (wget/curl) → Staging
- Log-Loeschung → Anti-Forensics / Verschleierung
- VPN-Verbindungen → Anonymisierung

AUSGABE-FORMAT:
### [EVENT_ID]
- **Klassifizierung:** C2_AKTIV | STAGING | EXFILTRATION | LATERAL | VERSCHLEIERUNG | UNBEKANNT
- **Begruendung:** [1-2 Saetze aus Taeter-Perspektive]
- **MITRE-Technik:** [T-Nummer falls zutreffend]

## Infra-Triage-Zusammenfassung
- C2-Aktivitaet: [Anzahl Events]
- Staging-Aktivitaet: [Anzahl Events]
- Exfiltrations-Hinweise: [Anzahl Events]
- Verschleierungs-Massnahmen: [Anzahl Events]
- **Bewertung:** [Kritische C2-Infrastruktur / Staging-Server / Proxy / Unbekannt]"""


ATTACKER_INFRA_ANALYST_PROMPT = """Du bist ein Senior Threat Intelligence Analyst mit Spezialisierung auf Attacker Infrastructure Forensics.

DEINE AUFGABE:
Analysiere die klassifizierten Infra-Events und rekonstruiere die Taetertaktiken.

VORGEHEN:
1. **C2-Analyse:** Welches C2-Framework wird genutzt? (Cobalt Strike, Metasploit, Sliver, Empire, custom?)
   Belege: Beaconing-Intervalle, verwendete Ports/Protokolle, User-Agent-Patterns
2. **Operator-Aktivitaet:** Wann war der Taeter aktiv? Zeitzone? Arbeitsmuster?
3. **Capability-Assessment:** Welche Tools und Capabilities wurden deployed?
4. **Netzwerk-Infrastruktur:** Welche IPs/Domains gehoeren zur Taeter-Infrastruktur?
5. **Attributions-Hinweise:** Sprachhinweise, Zeitzonen, TTPs die auf Taeter-Gruppe hinweisen?

AUSGABE-FORMAT:

## Taeterinfrastruktur-Analyse

### C2-Framework Assessment
[Vermutetes C2-Framework mit Begruendung]

### Operator-Aktivitaetsmuster
[Wann war der Taeter aktiv — Timestamps, Zeitzonen, Muster]

### Eingesetzte Capabilities
| Tool/Technik | Beleg | MITRE-Technik |
|---|---|---|
| [Tool] | [Logeintrag] | [T-Nummer] |

### Netzwerk-Infrastruktur des Taeter
- **C2-Server-IPs:** [Liste]
- **Ziel-IPs (angegriffene Systeme):** [Liste]
- **Verwendete Domains:** [Liste]
- **Genutzte Ports:** [Liste]

### MITRE ATT&CK Resource Development
[Welche T1583/T1584/T1587/T1608 Techniken wurden eingesetzt]

### Attributions-Indikatoren
[Sprachhinweise, Zeitmuster, bekannte TTPs, Infrastructure-Overlap]"""


ATTACKER_INFRA_REPORTER_PROMPT = """Du bist ein Threat Intelligence Report Autor fuer gerichtsverwertbare Taetersinfrastruktur-Dokumentation.

ANFORDERUNGEN:
- Perspektive: Analyse des TAETER-SERVERS (nicht des Opfers)
- Praesize, faktische Sprache — jede Aussage durch Logeintrag belegt
- Klare Trennung: Fakten vs. Schlussfolgerungen vs. Hypothesen
- MITRE ATT&CK Enterprise v15 Referenzen

AUSGABE-FORMAT:

# Taetersinfrastruktur-Analysebericht

## 1. Executive Summary
[2-3 Saetze: Art der Infrastruktur, Hauptaktivitaeten, Bewertung]

## 2. Untersuchungsgegenstand
- **Analysiertes System:** [Dateityp, Zeitraum]
- **Infrastruktur-Typ:** [C2-Server / Staging / Proxy / Mixed]
- **Analysezeitpunkt:** [Timestamp]
- **Methodik:** Automatisierte Log-Analyse + Multi-Agent KI (Taetersinfrastruktur-Modus)

## 3. C2-Infrastruktur
### 3.1 C2-Framework
[Vermutetes Framework, Belege, Konfiguration]

### 3.2 Verbindungsinfrastruktur
[IPs, Domains, Ports, Protokolle]

## 4. Taetertaktiken (MITRE ATT&CK)
[Tabelle: Resource Development, C2, Exfiltration Techniken]

## 5. Operator-Aktivitaetsprofil
[Aktivitaetszeiten, Muster, moegliche Zeitzone]

## 6. Eingesetzte Capabilities
[Tools, Exploits, Malware-Familien falls erkennbar]

## 7. Attributions-Hinweise
[Alle Hinweise auf Taeter-Identitaet — OHNE Spekulation]

## 8. Empfehlungen fuer Folge-Ermittlungen
[Konkrete Ermittlungsschritte, Sicherungsmaßnahmen, Behörden-Hinweise]

---
*Taetersinfrastruktur-Analysebericht — LFX Forensic Analysis System (Attacker Infra Mode)*"""


REPORTER_SYSTEM_PROMPT = """Du bist ein forensischer Berichtsersteller fuer gerichtsverwertbare Dokumentation.

DEINE AUFGABE:
Erstelle einen strukturierten, professionellen Forensik-Report basierend auf der Triage und der DFIR-Analyse.
Der Report muss den Anforderungen an gerichtsverwertbare Dokumentation genuegen.

ANFORDERUNGEN:
- Praezise, faktische Sprache ohne Spekulationen
- Jede Aussage muss durch Evidenz gestuetzt sein
- Timestamps und Event-IDs bei allen Referenzen
- Klare Trennung zwischen Fakten und Schlussfolgerungen

DEIN OUTPUT-FORMAT (strikt einhalten):

# Forensischer Analysebericht

## 1. Executive Summary
[2-3 Saetze: Was wurde gefunden, wie schwer ist es, was muss sofort getan werden]

## 2. Untersuchungsgegenstand
- **Analysierte Daten:** [Dateityp, Zeitraum, Umfang]
- **Analysemethodik:** Automatisierte Anomalieerkennung + Multi-Agent KI-Analyse
- **Analysezeitpunkt:** [Timestamp]

## 3. Befunde

### 3.1 Kritische Befunde
[Fuer jeden kritischen Befund: Was, Wann, Wo, Evidenz]

### 3.2 Verdaechtige Aktivitaeten
[Fuer jeden verdaechtigen Befund: Was, Wann, Wo, Evidenz]

## 4. Angriffsrekonstruktion
[Chronologische Darstellung basierend auf der DFIR-Analyse]

## 5. MITRE ATT&CK Mapping
[Tabelle aus der Analystenphase uebernehmen und ggf. ergaenzen]

## 6. Indicators of Compromise (IOCs)
[Strukturierte IOC-Liste]

## 7. Empfehlungen
### Sofortmassnahmen (0-24h)
[Nummerierte Liste]

### Kurzfristige Massnahmen (1-7 Tage)
[Nummerierte Liste]

### Langfristige Massnahmen (1-3 Monate)
[Nummerierte Liste]

## 8. Fazit
[Abschliessende Bewertung]

---
*Dieser Bericht wurde automatisiert durch das LFX Forensic Analysis System generiert.
Analysemethode: Multi-Agent KI-Analyse (Triage → DFIR → Report)*"""


# ── Orchestrator ─────────────────────────────────────────────────────────────

class MultiAgentOrchestrator:
    """
    Orchestriert 3 spezialisierte LLM-Agenten sequentiell.

    Jeder Agent:
    - Hat einen eigenen Systemprompt (Charakter/Rolle)
    - Bekommt den Output des vorherigen Agenten als Input
    - Gibt sein Ergebnis via Generator (SSE-kompatibel) zurueck

    Analyse-Modi:
    - 'standard'       → Opfer-Perspektive (angegriffenes System)
    - 'attacker_infra' → Taeter-Perspektive (Server des Angreifers)
    """

    def __init__(self, model: str = None, analysis_mode: str = 'standard'):
        # Hoeherer Timeout pro Agent (15 min statt 10 min) — jeder Agent kann lange laufen
        self.client = OllamaClient(model=model, timeout=900)
        self.analysis_mode = analysis_mode
        self.prompt_manager = PromptManager()
        logger.info(
            f"MultiAgentOrchestrator initialisiert "
            f"(Model: {self.client.model}, Modus: {analysis_mode}, Timeout: 900s)"
        )

    def _get_system_prompts(self):
        """Gibt die passenden System-Prompts je nach Analyse-Modus zurück."""
        if self.analysis_mode == 'attacker_infra':
            return (
                ATTACKER_INFRA_TRIAGE_PROMPT,
                ATTACKER_INFRA_ANALYST_PROMPT,
                ATTACKER_INFRA_REPORTER_PROMPT,
            )
        return (TRIAGE_SYSTEM_PROMPT, ANALYST_SYSTEM_PROMPT, REPORTER_SYSTEM_PROMPT)

    @staticmethod
    def _compact_anomaly(a: dict) -> str:
        """Komprimiert eine Anomalie zu einer Textzeile fuer den Triage-Agent."""
        meta = a.get('metadata', {}) if isinstance(a.get('metadata'), dict) else {}
        ts = a.get('timestamp', '?')
        etype = a.get('event_type', meta.get('event_type', '?'))
        score = a.get('anomaly_score', 0)
        desc = (a.get('description', '') or meta.get('message', ''))[:200]
        event_id = a.get('event_id', '?')
        host = meta.get('hostname', '')
        src_ip = meta.get('src_ip', '')
        user = meta.get('user', '')

        parts = [f"[{event_id}] [{ts}] {etype} (score={score:.2f})"]
        if host:
            parts.append(f"host={host}")
        if src_ip:
            parts.append(f"ip={src_ip}")
        if user:
            parts.append(f"user={user}")
        parts.append(desc)

        # MITRE-Techniken falls vorhanden
        mitre = a.get('mitre_techniques', [])
        if mitre:
            mitre_str = ', '.join(t['id'] for t in mitre[:3])
            parts.append(f"MITRE: {mitre_str}")

        return " | ".join(parts)

    def _build_triage_prompt(self, anomalies: list, summary: dict) -> str:
        """Baut den User-Prompt fuer den Triage-Agent."""
        anomaly_lines = [self._compact_anomaly(a) for a in anomalies]
        anomaly_text = "\n".join(anomaly_lines)

        summary_text = ""
        if summary:
            summary_text = (
                f"Analyseuebersicht: {summary.get('input_file', '?')} | "
                f"Typ: {summary.get('input_type', '?')} | "
                f"Gesamt-Events: {summary.get('total_events', 0)} | "
                f"Anomalien: {summary.get('anomalies_found', 0)}\n\n"
            )

        return (
            f"{summary_text}"
            f"Klassifiziere die folgenden {len(anomalies)} Anomalien:\n\n"
            f"{anomaly_text}"
        )

    def _build_analyst_prompt(self, triage_result: str, anomalies: list, indicators: dict) -> str:
        """Baut den User-Prompt fuer den Analyst-Agent."""
        ind_text = ""
        if indicators:
            ind_parts = []
            for key in ['ips', 'users', 'hostnames', 'processes', 'files']:
                vals = indicators.get(key, [])
                if vals:
                    ind_parts.append(f"  {key}: {', '.join(str(v) for v in vals[:15])}")
            if ind_parts:
                ind_text = "\n## Bekannte Indicators:\n" + "\n".join(ind_parts) + "\n\n"

        return (
            "## Triage-Ergebnis (SOC Level 1):\n"
            f"{triage_result}\n\n"
            f"{ind_text}"
            "Fuehre nun die tiefgehende DFIR-Analyse der KRITISCH und VERDAECHTIG "
            "eingestuften Findings durch."
        )

    def _build_reporter_prompt(self, triage_result: str, analyst_result: str, summary: dict) -> str:
        """Baut den User-Prompt fuer den Reporter-Agent."""
        summary_text = ""
        if summary:
            summary_text = (
                f"Analysierte Datei: {summary.get('input_file', '?')}\n"
                f"Dateityp: {summary.get('input_type', '?')}\n"
                f"Gesamt-Events: {summary.get('total_events', 0)}\n"
                f"Erkannte Anomalien: {summary.get('anomalies_found', 0)}\n"
                f"Analysezeitpunkt: {summary.get('analysis_timestamp', datetime.now().isoformat())}\n\n"
            )

        return (
            f"## Untersuchungsdaten:\n{summary_text}"
            f"## Triage-Ergebnis (SOC Level 1):\n{triage_result}\n\n"
            f"## DFIR-Analyse (Senior Analyst):\n{analyst_result}\n\n"
            "Erstelle nun den gerichtsverwertbaren forensischen Bericht."
        )

    def run(self, anomalies: list, summary: dict = None,
            indicators: dict = None) -> Generator[Dict[str, Any], None, None]:
        """
        Fuehrt die Multi-Agent-Analyse sequentiell durch.

        Modus wird bei Initialisierung gesetzt:
          MultiAgentOrchestrator(analysis_mode='attacker_infra')

        Yields SSE-kompatible Event-Dicts:
          {"agent": "triage|analyst|reporter", "status": "running|done|error", "result": "..."}
          {"status": "complete", "final_report": "..."}
        """
        triage_sys, analyst_sys, reporter_sys = self._get_system_prompts()
        mode_label = "Taetersinfrastruktur-Modus" if self.analysis_mode == 'attacker_infra' else "Standard-Modus"

        logger.info(f"{'=' * 70}")
        logger.info(f"MULTI-AGENT-ANALYSE GESTARTET: {len(anomalies)} Anomalien [{mode_label}]")
        logger.info(f"{'=' * 70}")

        # Im Taetersinfrastruktur-Modus: Nur Infra-relevante Events uebergeben
        if self.analysis_mode == 'attacker_infra':
            infra_event_types = {
                'c2_beacon', 'c2_tool', 'vpn_connection', 'vpn_disconnect',
                'vpn_ip_assigned', 'suspicious_tool_installed', 'package_install',
                'data_exfiltration', 'reverse_shell_attempt', 'ssh_event',
                'auth_success', 'auth_failure', 'network_connect', 'dns_query',
                'anti_forensics', 'log_cleared', 'file_download',
            }
            relevant_anomalies = [
                a for a in anomalies
                if a.get('event_type') in infra_event_types
                or a.get('is_attacker_infra', False)
            ] or anomalies  # Fallback: alle wenn keine Infra-Events gefunden
            logger.info(
                f"[Infra-Modus] {len(relevant_anomalies)}/{len(anomalies)} "
                f"relevante Infra-Events ausgewaehlt"
            )
        else:
            relevant_anomalies = anomalies

        # ── Agent 1: Triage ────────────────────────────────────────────────
        yield {"agent": "triage", "status": "running", "mode": self.analysis_mode}
        try:
            triage_prompt = self._build_triage_prompt(relevant_anomalies, summary)
            logger.info(f"[Triage] Prompt: {len(triage_prompt)} Zeichen")
            triage_result = self.client.generate(
                system_prompt=triage_sys,
                user_prompt=triage_prompt,
                temperature=0.3,
                max_tokens=2000,
            )
            yield {"agent": "triage", "status": "done", "result": triage_result}
            logger.info(f"[Triage] Abgeschlossen ({len(triage_result)} Zeichen)")
        except Exception as e:
            logger.error(f"[Triage] Fehlgeschlagen: {e}")
            yield {"agent": "triage", "status": "error", "error": str(e)}
            return

        # ── Agent 2: Analyst ───────────────────────────────────────────────
        yield {"agent": "analyst", "status": "running", "mode": self.analysis_mode}
        try:
            analyst_prompt = self._build_analyst_prompt(triage_result, relevant_anomalies, indicators)
            logger.info(f"[Analyst] Prompt: {len(analyst_prompt)} Zeichen")
            analyst_result = self.client.generate(
                system_prompt=analyst_sys,
                user_prompt=analyst_prompt,
                temperature=0.4,
                max_tokens=3000,
            )
            yield {"agent": "analyst", "status": "done", "result": analyst_result}
            logger.info(f"[Analyst] Abgeschlossen ({len(analyst_result)} Zeichen)")
        except Exception as e:
            logger.error(f"[Analyst] Fehlgeschlagen: {e}")
            yield {"agent": "analyst", "status": "error", "error": str(e)}
            return

        # ── Agent 3: Reporter ──────────────────────────────────────────────
        yield {"agent": "reporter", "status": "running", "mode": self.analysis_mode}
        try:
            if self.analysis_mode == 'attacker_infra':
                reporter_prompt = self.prompt_manager.get_attacker_infra_report_prompt(
                    triage_result, analyst_result, summary
                )
            else:
                reporter_prompt = self._build_reporter_prompt(triage_result, analyst_result, summary)

            logger.info(f"[Reporter] Prompt: {len(reporter_prompt)} Zeichen")
            reporter_result = self.client.generate(
                system_prompt=reporter_sys,
                user_prompt=reporter_prompt,
                temperature=0.4,
                max_tokens=4000,
            )
            yield {"agent": "reporter", "status": "done", "result": reporter_result}
            logger.info(f"[Reporter] Abgeschlossen ({len(reporter_result)} Zeichen)")
        except Exception as e:
            logger.error(f"[Reporter] Fehlgeschlagen: {e}")
            yield {"agent": "reporter", "status": "error", "error": str(e)}
            return

        # ── Fertig ─────────────────────────────────────────────────────────
        yield {"status": "complete", "final_report": reporter_result, "mode": self.analysis_mode}
        logger.info(f"{'=' * 70}")
        logger.info(f"MULTI-AGENT-ANALYSE ABGESCHLOSSEN [{mode_label}]")
        logger.info(f"{'=' * 70}")
