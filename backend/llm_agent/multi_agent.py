"""
================================================================================
MULTI-AGENT ORCHESTRATOR — Sequentielle 3-Agenten-Pipeline für forensische Analyse
================================================================================
Orchestriert drei spezialisierte LLM-Agenten die sequentiell arbeiten und
ihre Ergebnisse aneinander weiterreichen:

    Agent 1 — Triage (SOC Level 1):
        Klassifiziert jede Anomalie in KRITISCH / VERDÄCHTIG / FALSE_POSITIVE.
        Niedrige Temperatur (0.3) für konsistente, regelbasierte Klassifizierung.

    Agent 2 — Analyst (Senior DFIR):
        Erhält das Triage-Ergebnis und führt Tiefenanalyse durch:
        Korrelation von Events, MITRE ATT&CK Mapping, Lateral-Movement-Analyse.
        Mittlere Temperatur (0.4) für strukturierte aber nuancierte Analyse.

    Agent 3 — Reporter (Forensic Writer):
        Erhält Triage + DFIR-Analyse und erstellt den gerichtsverwertbaren
        Markdown-Report mit Executive Summary, Befunden und Empfehlungen.
        Mittlere Temperatur (0.4) für professionellen, faktischen Schreibstil.

Analyse-Modi:
    - 'standard':       Opfer-Perspektive (Standard; angegriffenes System)
    - 'attacker_infra': Täter-Perspektive (Server/Infrastruktur des Angreifers;
                        andere System-Prompts, andere Event-Filterung)

Streaming:
    run() ist ein Generator der SSE-kompatible Dicts yieldet — jeder Token
    wird sofort an das Frontend weitergeleitet ohne auf den vollständigen
    LLM-Output zu warten. Das Frontend empfängt die Tokens über den
    /api/analyze/stream-Endpunkt.

Verwendung:
    orchestrator = MultiAgentOrchestrator(model='llama3.1', analysis_mode='standard')
    for event in orchestrator.run(anomalies, summary, indicators):
        if event.get('status') == 'complete':
            final_report = event['final_report']
        elif event.get('status') == 'streaming':
            print(event['token'], end='')  # Echtzeit-Output

Abhängigkeiten:
    - .ollama_client (OllamaClient — Streaming-API-Aufrufe)
    - .prompts (PromptManager — Täterinfrastruktur-Report-Prompt)

Kontext: LFX Forensic Analysis System — LLM-Integrations-Schicht
================================================================================
"""

import json
import logging
from typing import Dict, List, Generator, Any, Optional
from datetime import datetime
from .ollama_client import OllamaClient
from .prompts import PromptManager

logger = logging.getLogger(__name__)

# ── System-Prompts: Standard-Modus (Opfer-Perspektive) ───────────────────────
# Diese drei Prompts definieren Charakter und Aufgabe je eines Agenten.
# Sie werden als "system"-Feld im Ollama-API-Aufruf übergeben.
# Jeder Prompt enthält strikt definierte Output-Formate damit der nächste
# Agent den Output des vorherigen zuverlässig parsen kann.

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


# ── System-Prompts: Täterinfrastruktur-Modus ─────────────────────────────────
# Alternative Prompts für analysis_mode='attacker_infra'.
# Wechselt die Analyse-Perspektive: Nicht "Was wurde auf dem Opfer gemacht?"
# sondern "Was hat der Angreifer von seinem eigenen Server aus getan?"
# Verwendet andere Klassifizierungs-Kategorien (C2_AKTIV, STAGING etc.)
# und fokussiert auf MITRE Resource Development Taktiken.

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


# ── Orchestrator ──────────────────────────────────────────────────────────────

class MultiAgentOrchestrator:
    """
    Orchestriert 3 spezialisierte LLM-Agenten für forensische Analyse.

    Implementiert eine sequentielle Pipeline: Jeder Agent erhält den Output
    des vorherigen als Teil seines User-Prompts. Das ermöglicht progressive
    Verfeinerung der Analyse — vom groben Triage-Ergebnis über die technische
    DFIR-Analyse bis zum finalen Report.

    Jeder Agent nutzt Streaming (generate_stream) und yieldet Tokens sofort,
    sodass das Frontend die Ausgabe in Echtzeit über SSE empfangen kann.

    Analyse-Modi (bei Initialisierung festgelegt):
        'standard':       Standard-Forensik-Agenten (SOC Analyst → DFIR → Reporter)
        'attacker_infra': Täterinfrastruktur-Agenten (Infra-Triage → TI-Analyst → Infra-Reporter)

    Timeout:
        900 Sekunden (15 Minuten) pro Agent. Forensische LLM-Analysen können bei
        großen Timelines erheblich länger dauern als normale LLM-Anfragen.

    Beispiel:
        orc = MultiAgentOrchestrator(model='llama3.1', analysis_mode='standard')
        for event in orc.run(anomalies, summary={'input_file': 'disk.dd'}, indicators={}):
            if event['status'] == 'streaming':
                sys.stdout.write(event['token'])
            elif event['status'] == 'complete':
                report = event['final_report']
    """

    def __init__(self, model: str = None, analysis_mode: str = 'standard'):
        # Höherer Timeout pro Agent (15 min statt 10 min) — jeder Agent kann lange laufen
        self.client = OllamaClient(model=model, timeout=900)
        self.analysis_mode = analysis_mode
        self.prompt_manager = PromptManager()
        logger.info(
            f"MultiAgentOrchestrator initialisiert "
            f"(Model: {self.client.model}, Modus: {analysis_mode}, Timeout: 900s)"
        )

    # ── System-Prompt-Auswahl ─────────────────────────────────────────────────

    def _get_system_prompts(self):
        """
        Gibt das passende System-Prompt-Tripel je nach Analyse-Modus zurück.

        Returns:
            Tuple (triage_sys, analyst_sys, reporter_sys) mit den System-Prompts
            für die drei Agenten im gewählten Analyse-Modus.
        """
        if self.analysis_mode == 'attacker_infra':
            return (
                ATTACKER_INFRA_TRIAGE_PROMPT,
                ATTACKER_INFRA_ANALYST_PROMPT,
                ATTACKER_INFRA_REPORTER_PROMPT,
            )
        return (TRIAGE_SYSTEM_PROMPT, ANALYST_SYSTEM_PROMPT, REPORTER_SYSTEM_PROMPT)

    # ── Prompt-Builder ────────────────────────────────────────────────────────

    @staticmethod
    def _compact_anomaly(a: dict) -> str:
        """
        Komprimiert eine Anomalie-Dict zu einer kompakten Textzeile.

        Reduziert den Kontext-Verbrauch im Triage-Prompt indem die relevantesten
        Felder jeder Anomalie in einer einzigen Zeile zusammengefasst werden.
        Details wie Metadaten werden auf die wichtigsten Attribute (host, ip, user)
        reduziert. MITRE-Techniken werden als IDs angehängt.

        Args:
            a: Anomalie-Dict aus anomalies_detected.json

        Returns:
            Einzeilige Textzusammenfassung der Anomalie
        """
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

        # MITRE-Techniken falls vorhanden (max. 3 IDs)
        mitre = a.get('mitre_techniques', [])
        if mitre:
            mitre_str = ', '.join(t['id'] for t in mitre[:3])
            parts.append(f"MITRE: {mitre_str}")

        return " | ".join(parts)

    def _build_triage_prompt(self, anomalies: list, summary: dict) -> str:
        """
        Baut den User-Prompt für Agent 1 (Triage).

        Enthält eine optionale Analysezusammenfassung (Gesamtstatistik) gefolgt
        von komprimierten Anomalie-Zeilen für jede zu klassifizierende Anomalie.

        Args:
            anomalies: Liste der Anomalie-Dicts (aus anomalies_detected.json)
            summary:   Analyse-Zusammenfassung aus analysis_summary.json

        Returns:
            Vollständiger User-Prompt-Text für den Triage-Agenten
        """
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
        """
        Baut den User-Prompt für Agent 2 (Senior DFIR Analyst).

        Enthält das vollständige Triage-Ergebnis aus Agent 1 sowie
        extrahierte Indikatoren (IPs, User, Prozesse) für die Korrelationsanalyse.

        Args:
            triage_result: Vollständiger Markdown-Output von Agent 1 (Triage)
            anomalies:     Originale Anomalie-Liste (nur für Zählung/Referenz)
            indicators:    Dict mit IOC-Kategorien aus dem AI-Preprocessor

        Returns:
            Vollständiger User-Prompt-Text für den DFIR-Analyst-Agenten
        """
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
        """
        Baut den User-Prompt für Agent 3 (Reporter).

        Kombiniert Triage- und DFIR-Analyst-Ergebnisse mit Metadaten der
        analysierten Datei für den finalen Report.

        Args:
            triage_result:  Vollständiger Markdown-Output von Agent 1 (Triage)
            analyst_result: Vollständiger Markdown-Output von Agent 2 (DFIR Analyst)
            summary:        Analyse-Zusammenfassung mit Datei-Metadaten

        Returns:
            Vollständiger User-Prompt-Text für den Reporter-Agenten
        """
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

    # ── Haupt-Orchestrierung ──────────────────────────────────────────────────

    def run(self, anomalies: list, summary: dict = None,
            indicators: dict = None) -> Generator[Dict[str, Any], None, None]:
        """
        Führt die sequentielle Multi-Agent-Analyse durch.

        Jeder der drei Agenten läuft nacheinander: Das Ergebnis von Agent N
        wird als Input für Agent N+1 verwendet. Alle Agents streamen ihre
        Ausgabe Token-für-Token via Generator.

        Im Täterinfrastruktur-Modus ('attacker_infra') werden vor der Übergabe
        an die Agenten nur Infrastruktur-relevante Event-Typen (c2_beacon,
        ssh_event, vpn_connection etc.) herausgefiltert um den Kontext
        zu fokussieren.

        Bei einem Fehler in einem Agenten wird ein Error-Event geyieldet
        und die Pipeline abgebrochen (return statt Exception um den Generator
        sauber zu beenden).

        Args:
            anomalies:   Liste der Anomalie-Dicts aus anomalies_detected.json
            summary:     Analyse-Zusammenfassung aus analysis_summary.json
                         (optional, wird für Metadaten in Prompts verwendet)
            indicators:  Dict mit extrahierten IOC-Kategorien aus dem
                         AI-Preprocessor (optional, für Agent 2)

        Yields:
            Dicts mit SSE-kompatiblem Format:
            - {"agent": "triage", "status": "running", "mode": "standard"}
            - {"agent": "triage", "status": "streaming", "token": "..."}
            - {"agent": "triage", "status": "done", "result": "..."}
            - {"agent": "analyst", ...} (analog)
            - {"agent": "reporter", ...} (analog)
            - {"status": "complete", "final_report": "...", "mode": "..."}
            - {"agent": "...", "status": "error", "error": "..."} (bei Fehler)
        """
        triage_sys, analyst_sys, reporter_sys = self._get_system_prompts()
        mode_label = "Taetersinfrastruktur-Modus" if self.analysis_mode == 'attacker_infra' else "Standard-Modus"

        logger.info(f"{'=' * 70}")
        logger.info(f"MULTI-AGENT-ANALYSE GESTARTET: {len(anomalies)} Anomalien [{mode_label}]")
        logger.info(f"{'=' * 70}")

        # Im Täterinfrastruktur-Modus: Nur Infra-relevante Events übergeben.
        # Verhindert dass normale Dateisystem-Events den Infra-Kontext verwässern.
        # Fallback auf alle Anomalien wenn keine Infra-Events gefunden werden.
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

        # ── Agent 1: Triage ────────────────────────────────────────────────────
        yield {"agent": "triage", "status": "running", "mode": self.analysis_mode}
        try:
            triage_prompt = self._build_triage_prompt(relevant_anomalies, summary)
            logger.info(f"[Triage] Prompt: {len(triage_prompt)} Zeichen")
            triage_tokens = []
            for token in self.client.generate_stream(
                system_prompt=triage_sys,
                user_prompt=triage_prompt,
                temperature=0.3,   # Niedrig: konsistente, regelbasierte Klassifizierung
                max_tokens=2000,
            ):
                triage_tokens.append(token)
                yield {"agent": "triage", "status": "streaming", "token": token}
            triage_result = ''.join(triage_tokens)
            yield {"agent": "triage", "status": "done", "result": triage_result}
            logger.info(f"[Triage] Abgeschlossen ({len(triage_result)} Zeichen)")
        except Exception as e:
            logger.error(f"[Triage] Fehlgeschlagen: {e}")
            yield {"agent": "triage", "status": "error", "error": str(e)}
            return

        # ── Agent 2: Analyst ───────────────────────────────────────────────────
        yield {"agent": "analyst", "status": "running", "mode": self.analysis_mode}
        try:
            analyst_prompt = self._build_analyst_prompt(triage_result, relevant_anomalies, indicators)
            logger.info(f"[Analyst] Prompt: {len(analyst_prompt)} Zeichen")
            analyst_tokens = []
            for token in self.client.generate_stream(
                system_prompt=analyst_sys,
                user_prompt=analyst_prompt,
                temperature=0.4,   # Mittel: strukturierte aber nuancierte DFIR-Analyse
                max_tokens=3000,
            ):
                analyst_tokens.append(token)
                yield {"agent": "analyst", "status": "streaming", "token": token}
            analyst_result = ''.join(analyst_tokens)
            yield {"agent": "analyst", "status": "done", "result": analyst_result}
            logger.info(f"[Analyst] Abgeschlossen ({len(analyst_result)} Zeichen)")
        except Exception as e:
            logger.error(f"[Analyst] Fehlgeschlagen: {e}")
            yield {"agent": "analyst", "status": "error", "error": str(e)}
            return

        # ── Agent 3: Reporter ──────────────────────────────────────────────────
        yield {"agent": "reporter", "status": "running", "mode": self.analysis_mode}
        try:
            # Im Täterinfrastruktur-Modus: Spezialisierten Infra-Report-Prompt verwenden
            if self.analysis_mode == 'attacker_infra':
                reporter_prompt = self.prompt_manager.get_attacker_infra_report_prompt(
                    triage_result, analyst_result, summary
                )
            else:
                reporter_prompt = self._build_reporter_prompt(triage_result, analyst_result, summary)

            logger.info(f"[Reporter] Prompt: {len(reporter_prompt)} Zeichen")
            reporter_tokens = []
            for token in self.client.generate_stream(
                system_prompt=reporter_sys,
                user_prompt=reporter_prompt,
                temperature=0.4,   # Mittel: professioneller, faktischer Schreibstil
                max_tokens=4000,   # Größeres Limit: Reports sind länger als Analysen
            ):
                reporter_tokens.append(token)
                yield {"agent": "reporter", "status": "streaming", "token": token}
            reporter_result = ''.join(reporter_tokens)
            yield {"agent": "reporter", "status": "done", "result": reporter_result}
            logger.info(f"[Reporter] Abgeschlossen ({len(reporter_result)} Zeichen)")
        except Exception as e:
            logger.error(f"[Reporter] Fehlgeschlagen: {e}")
            yield {"agent": "reporter", "status": "error", "error": str(e)}
            return

        # ── Pipeline abgeschlossen ─────────────────────────────────────────────
        # final_report ist der vollständige Markdown-Output des Reporter-Agenten.
        # Er wird in pipeline.py als report.md gespeichert.
        yield {"status": "complete", "final_report": reporter_result, "mode": self.analysis_mode}
        logger.info(f"{'=' * 70}")
        logger.info(f"MULTI-AGENT-ANALYSE ABGESCHLOSSEN [{mode_label}]")
        logger.info(f"{'=' * 70}")
