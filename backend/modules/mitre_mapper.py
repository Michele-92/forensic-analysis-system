"""
================================================================================
MITRE ATT&CK MAPPER — Event-Typ zu Technik-ID Zuordnung
================================================================================
Ordnet erkannte forensische Event-Typen den entsprechenden MITRE ATT&CK
Enterprise Techniken (Version 15, Stand 2024) zu. Unterstützt beide
Analyse-Perspektiven:

  - Täterinfrastruktur-Modus ('attacker_infra'):
      Fokus auf Angreifer-Server — C2-Kommunikation, Tool-Staging,
      Lateral Movement, Ressourcen-Entwicklung.

  - Opfer-Server-Modus ('victim_server'):
      Fokus auf angegriffene Systeme — Initial Access, Privilege Escalation,
      Defense Evasion, Exfiltration.

  - Beide Modi ('both', Standard):
      Alle verfügbaren Taktiken werden berücksichtigt.

Aufgaben:
    - Statisches Mapping: event_type → MITRE Technique-ID + Name + Taktik
    - Timeline-Anreicherung: Fügt jedem Event mitre_techniques + mitre_tactics hinzu
    - Scoring: Gewichtete Zusammenfassungen (Taktik-Häufigkeit, Technik-Häufigkeit)
    - Täterinfrastruktur-Analyse: Kategorisiert C2, Staging, Lateral, Exfil
    - Kill-Chain-Coverage: Mappt erkannte Taktiken auf Lockheed Martin Kill Chain

Verwendung:
    mapper = MitreMapper(mode='both')
    enriched = mapper.enrich_timeline(timeline_events)
    summary  = mapper.get_tactic_summary(enriched)
    # → {'Defense Evasion': 42, 'Command and Control': 17, ...}

Wichtige Konstanten:
    MITRE_MAPPING:          Dict[event_type → List[technique_dicts]]
    ATTACKER_INFRA_TACTICS: Set — Taktiken typisch für Angreifer-Infrastruktur
    VICTIM_SERVER_TACTICS:  Set — Taktiken typisch für angegriffene Systeme

Scoring-Kategorien (dokumentiert als Kommentare im MITRE_MAPPING):
    HIGH   (Score 7–10): Kritische Indikatoren, sofortige Relevanz
    MEDIUM (Score 4–6):  Auffällig, im Kontext zu bewerten
    LOW    (Score 1–3):  Hintergrundrauschen
    INFRA:               Täterinfrastruktur-spezifische Einträge

Abhängigkeiten:
    - Keine externen Pakete (nur Python-stdlib: logging, typing)

Kontext: LFX Forensic Analysis System — Pipeline Stage 8 (MITRE-Mapping),
         aufgerufen aus backend/pipeline.py nach der Anomalie-Erkennung.
"""

import logging
from typing import List, Dict, Tuple

logger = logging.getLogger(__name__)


# ── Statisches Mapping: event_type → [(technique_id, name, tactic)] ──────────
#
# Aufbau eines Eintrags:
#   'event_type': [
#       {'id': 'T1234',     'name': 'Technique Name', 'tactic': 'Tactic Name'},
#       {'id': 'T1234.001', 'name': 'Sub-Technique',  'tactic': 'Tactic Name'},
#   ]
#
# Leere Listen ([]) bedeuten: bekannter Event-Typ, aber kein MITRE-Mapping
# sinnvoll (Hintergrundrauschen / normaler Betrieb).
# ─────────────────────────────────────────────────────────────────────────────

MITRE_MAPPING: Dict[str, List[Dict[str, str]]] = {

    # ══════════════════════════════════════════════════════════════════════
    # ── HOCH VERDÄCHTIG (Score 7–10) ──────────────────────────────────────
    # ══════════════════════════════════════════════════════════════════════

    # Authentifizierungsfehler → Brute Force
    'auth_failure': [
        {'id': 'T1110',     'name': 'Brute Force',                     'tactic': 'Credential Access'},
        {'id': 'T1110.001', 'name': 'Password Guessing',               'tactic': 'Credential Access'},
        {'id': 'T1110.003', 'name': 'Password Spraying',               'tactic': 'Credential Access'},
    ],

    # Erfolgreicher Login nach Fehlern → Valid Accounts (kompromittiert)
    'auth_success': [
        {'id': 'T1078',     'name': 'Valid Accounts',                  'tactic': 'Defense Evasion'},
        {'id': 'T1078.003', 'name': 'Local Accounts',                  'tactic': 'Defense Evasion'},
    ],

    # Privilege Escalation (sudo, su, SUID)
    'privilege_escalation': [
        {'id': 'T1548',     'name': 'Abuse Elevation Control Mechanism', 'tactic': 'Privilege Escalation'},
        {'id': 'T1548.003', 'name': 'Sudo and Sudo Caching',           'tactic': 'Privilege Escalation'},
    ],
    'sudo_failure': [
        {'id': 'T1548.003', 'name': 'Sudo and Sudo Caching',           'tactic': 'Privilege Escalation'},
        {'id': 'T1110',     'name': 'Brute Force',                     'tactic': 'Credential Access'},
    ],
    'sudo_denied': [
        {'id': 'T1548.003', 'name': 'Sudo and Sudo Caching',           'tactic': 'Privilege Escalation'},
    ],

    # Credential Access (shadow, passwd, SSH-Keys lesen)
    'credential_access': [
        {'id': 'T1003',     'name': 'OS Credential Dumping',           'tactic': 'Credential Access'},
        {'id': 'T1003.008', 'name': '/etc/passwd and /etc/shadow',     'tactic': 'Credential Access'},
        {'id': 'T1552',     'name': 'Unsecured Credentials',           'tactic': 'Credential Access'},
        {'id': 'T1552.001', 'name': 'Credentials In Files',            'tactic': 'Credential Access'},
    ],

    # Web-Angriffe
    'sqli_attempt': [
        {'id': 'T1190',     'name': 'Exploit Public-Facing Application', 'tactic': 'Initial Access'},
        {'id': 'T1059',     'name': 'Command and Scripting Interpreter','tactic': 'Execution'},
    ],
    'xss_attempt': [
        {'id': 'T1189',     'name': 'Drive-by Compromise',             'tactic': 'Initial Access'},
        {'id': 'T1059.007', 'name': 'JavaScript',                      'tactic': 'Execution'},
    ],
    'path_traversal': [
        {'id': 'T1083',     'name': 'File and Directory Discovery',    'tactic': 'Discovery'},
        {'id': 'T1190',     'name': 'Exploit Public-Facing Application', 'tactic': 'Initial Access'},
    ],
    'webshell_access': [
        {'id': 'T1505.003', 'name': 'Web Shell',                       'tactic': 'Persistence'},
        {'id': 'T1059',     'name': 'Command and Scripting Interpreter','tactic': 'Execution'},
    ],

    # Reverse Shell / Remote Code Execution
    'reverse_shell_attempt': [
        {'id': 'T1059.004', 'name': 'Unix Shell',                      'tactic': 'Execution'},
        {'id': 'T1071.001', 'name': 'Web Protocols',                   'tactic': 'Command and Control'},
        {'id': 'T1095',     'name': 'Non-Application Layer Protocol',  'tactic': 'Command and Control'},
    ],
    'code_execution': [
        {'id': 'T1059',     'name': 'Command and Scripting Interpreter','tactic': 'Execution'},
        {'id': 'T1059.004', 'name': 'Unix Shell',                      'tactic': 'Execution'},
        {'id': 'T1059.006', 'name': 'Python',                          'tactic': 'Execution'},
    ],

    # Anti-Forensics / Evidence Removal
    'anti_forensics': [
        {'id': 'T1070',     'name': 'Indicator Removal',               'tactic': 'Defense Evasion'},
        {'id': 'T1070.003', 'name': 'Clear Command History',           'tactic': 'Defense Evasion'},
        {'id': 'T1070.004', 'name': 'File Deletion',                   'tactic': 'Defense Evasion'},
    ],
    'log_cleared': [
        {'id': 'T1070.002', 'name': 'Clear Linux or Mac System Logs',  'tactic': 'Defense Evasion'},
        {'id': 'T1070',     'name': 'Indicator Removal',               'tactic': 'Defense Evasion'},
    ],
    'audit_config_change': [
        {'id': 'T1562.012', 'name': 'Disable or Modify Linux Audit System', 'tactic': 'Defense Evasion'},
        {'id': 'T1562',     'name': 'Impair Defenses',                 'tactic': 'Defense Evasion'},
    ],

    # Daten-Exfiltration
    'data_exfiltration': [
        {'id': 'T1041',     'name': 'Exfiltration Over C2 Channel',   'tactic': 'Exfiltration'},
        {'id': 'T1048',     'name': 'Exfiltration Over Alternative Protocol', 'tactic': 'Exfiltration'},
        {'id': 'T1048.003', 'name': 'Exfiltration Over Unencrypted Non-C2 Protocol', 'tactic': 'Exfiltration'},
    ],

    # Netzwerk-Angriffe
    'network_attack': [
        {'id': 'T1498',     'name': 'Network Denial of Service',       'tactic': 'Impact'},
        {'id': 'T1046',     'name': 'Network Service Discovery',       'tactic': 'Discovery'},
    ],

    # ══════════════════════════════════════════════════════════════════════
    # ── TÄTERINFRASTRUKTUR (INFRA) ──────────────────────────────────────
    # Schwerpunkt: Angreifer-Server Forensik
    # ══════════════════════════════════════════════════════════════════════

    # C2-Beaconing (Rückruf zu Command-and-Control-Server)
    'c2_beacon': [
        {'id': 'T1071',     'name': 'Application Layer Protocol',      'tactic': 'Command and Control'},
        {'id': 'T1071.001', 'name': 'Web Protocols',                   'tactic': 'Command and Control'},
        {'id': 'T1071.002', 'name': 'File Transfer Protocols',         'tactic': 'Command and Control'},
        {'id': 'T1071.004', 'name': 'DNS',                             'tactic': 'Command and Control'},
        {'id': 'T1219',     'name': 'Remote Access Software',          'tactic': 'Command and Control'},
    ],

    # C2-Tools (Netcat, Socat, Proxychains, Tor)
    'c2_tool': [
        {'id': 'T1219',     'name': 'Remote Access Software',          'tactic': 'Command and Control'},
        {'id': 'T1090',     'name': 'Proxy',                           'tactic': 'Command and Control'},
        {'id': 'T1090.003', 'name': 'Multi-hop Proxy',                 'tactic': 'Command and Control'},
        {'id': 'T1571',     'name': 'Non-Standard Port',               'tactic': 'Command and Control'},
    ],

    # VPN-Verbindungen (Täterinfrastruktur nutzt VPN zur Verschleierung)
    'vpn_connection': [
        {'id': 'T1090.003', 'name': 'Multi-hop Proxy',                 'tactic': 'Command and Control'},
        {'id': 'T1583.003', 'name': 'Virtual Private Server',          'tactic': 'Resource Development'},
    ],
    'vpn_disconnect': [
        {'id': 'T1090.003', 'name': 'Multi-hop Proxy',                 'tactic': 'Command and Control'},
    ],
    'vpn_ip_assigned': [
        {'id': 'T1090',     'name': 'Proxy',                           'tactic': 'Command and Control'},
        {'id': 'T1583.003', 'name': 'Virtual Private Server',          'tactic': 'Resource Development'},
    ],

    # Verdächtige Tools installiert (Hacker-Tools via APT/YUM)
    'suspicious_tool_installed': [
        {'id': 'T1587',     'name': 'Develop Capabilities',            'tactic': 'Resource Development'},
        {'id': 'T1587.001', 'name': 'Malware',                         'tactic': 'Resource Development'},
        {'id': 'T1588.002', 'name': 'Tool',                            'tactic': 'Resource Development'},
        {'id': 'T1072',     'name': 'Software Deployment Tools',       'tactic': 'Execution'},
    ],

    # Paketinstallation allgemein (Staging: Werkzeuge auf Infrastruktur vorbereiten)
    'package_install': [
        {'id': 'T1608',     'name': 'Stage Capabilities',              'tactic': 'Resource Development'},
        {'id': 'T1608.001', 'name': 'Upload Malware',                  'tactic': 'Resource Development'},
    ],
    'package_remove': [
        {'id': 'T1070.004', 'name': 'File Deletion',                   'tactic': 'Defense Evasion'},
    ],

    # DNS-Tunneling / DNS-C2
    'dns_query': [
        {'id': 'T1071.004', 'name': 'DNS',                             'tactic': 'Command and Control'},
        {'id': 'T1568',     'name': 'Dynamic Resolution',              'tactic': 'Command and Control'},
    ],

    # Netzwerk-Scanning (Aufklärung des Netzwerks)
    'network_tool': [
        {'id': 'T1046',     'name': 'Network Service Discovery',       'tactic': 'Discovery'},
        {'id': 'T1595.001', 'name': 'Scanning IP Blocks',              'tactic': 'Reconnaissance'},
        {'id': 'T1595.002', 'name': 'Vulnerability Scanning',          'tactic': 'Reconnaissance'},
    ],

    # Datei-Download (Tool-Transfer auf Zielsystem)
    'file_download': [
        {'id': 'T1105',     'name': 'Ingress Tool Transfer',           'tactic': 'Command and Control'},
        {'id': 'T1204.002', 'name': 'Malicious File',                  'tactic': 'Execution'},
    ],

    # Lateral Movement (SSH, SCP zwischen Systemen)
    'ssh_event': [
        {'id': 'T1021.004', 'name': 'SSH',                             'tactic': 'Lateral Movement'},
        {'id': 'T1563.001', 'name': 'SSH Hijacking',                   'tactic': 'Lateral Movement'},
    ],
    'ssh_disconnect': [
        {'id': 'T1021.004', 'name': 'SSH',                             'tactic': 'Lateral Movement'},
    ],
    'network_connect': [
        {'id': 'T1021',     'name': 'Remote Services',                 'tactic': 'Lateral Movement'},
        {'id': 'T1071',     'name': 'Application Layer Protocol',      'tactic': 'Command and Control'},
    ],

    # Persistence-Mechanismen
    'scheduled_task': [
        {'id': 'T1053',     'name': 'Scheduled Task/Job',              'tactic': 'Persistence'},
        {'id': 'T1053.003', 'name': 'Cron',                            'tactic': 'Persistence'},
    ],
    'scheduled_task_created': [
        {'id': 'T1053.003', 'name': 'Cron',                            'tactic': 'Persistence'},
        {'id': 'T1053',     'name': 'Scheduled Task/Job',              'tactic': 'Persistence'},
    ],
    'crontab_modified': [
        {'id': 'T1053.003', 'name': 'Cron',                            'tactic': 'Persistence'},
    ],
    'persistence_mechanism': [
        {'id': 'T1543.002', 'name': 'Systemd Service',                 'tactic': 'Persistence'},
        {'id': 'T1053',     'name': 'Scheduled Task/Job',              'tactic': 'Persistence'},
        {'id': 'T1547',     'name': 'Boot or Logon Autostart Execution', 'tactic': 'Persistence'},
    ],
    'ssh_key_modified': [
        {'id': 'T1098.004', 'name': 'SSH Authorized Keys',             'tactic': 'Persistence'},
        {'id': 'T1098',     'name': 'Account Manipulation',            'tactic': 'Persistence'},
    ],

    # Account-Manipulation
    'account_modification': [
        {'id': 'T1098',     'name': 'Account Manipulation',            'tactic': 'Persistence'},
        {'id': 'T1136',     'name': 'Create Account',                  'tactic': 'Persistence'},
    ],
    'user_created': [
        {'id': 'T1136.001', 'name': 'Local Account',                   'tactic': 'Persistence'},
        {'id': 'T1136',     'name': 'Create Account',                  'tactic': 'Persistence'},
    ],
    'user_deleted': [
        {'id': 'T1070.004', 'name': 'File Deletion',                   'tactic': 'Defense Evasion'},
    ],

    # Permission-Änderungen
    'permission_change': [
        {'id': 'T1222',     'name': 'File and Directory Permissions Modification', 'tactic': 'Defense Evasion'},
        {'id': 'T1222.002', 'name': 'Linux and Mac File Permissions Modification', 'tactic': 'Defense Evasion'},
    ],
    'privilege_change': [
        {'id': 'T1548.001', 'name': 'Setuid and Setgid',               'tactic': 'Privilege Escalation'},
    ],

    # ══════════════════════════════════════════════════════════════════════
    # ── MITTEL VERDÄCHTIG (Score 4–6) ─────────────────────────────────────
    # ══════════════════════════════════════════════════════════════════════

    'suspicious_request': [
        {'id': 'T1595',     'name': 'Active Scanning',                 'tactic': 'Reconnaissance'},
        {'id': 'T1190',     'name': 'Exploit Public-Facing Application', 'tactic': 'Initial Access'},
    ],
    'http_error': [
        {'id': 'T1595.002', 'name': 'Vulnerability Scanning',          'tactic': 'Reconnaissance'},
    ],
    'http_request': [],   # Normaler Traffic — kein Mapping

    'process_create': [
        {'id': 'T1059',     'name': 'Command and Scripting Interpreter','tactic': 'Execution'},
    ],

    'firewall_drop': [
        {'id': 'T1071',     'name': 'Application Layer Protocol',      'tactic': 'Command and Control'},
    ],
    'firewall_allow': [
        {'id': 'T1071',     'name': 'Application Layer Protocol',      'tactic': 'Command and Control'},
    ],
    'firewall_deny': [
        {'id': 'T1071',     'name': 'Application Layer Protocol',      'tactic': 'Command and Control'},
    ],
    'firewall_event': [
        {'id': 'T1562.004', 'name': 'Disable or Modify System Firewall', 'tactic': 'Defense Evasion'},
    ],
    'firewall_forward': [
        {'id': 'T1090',     'name': 'Proxy',                           'tactic': 'Command and Control'},
    ],

    'service_event': [
        {'id': 'T1543.002', 'name': 'Systemd Service',                 'tactic': 'Persistence'},
    ],

    'system_alert': [
        {'id': 'T1499',     'name': 'Endpoint Denial of Service',      'tactic': 'Impact'},
    ],

    'process_crash': [
        {'id': 'T1499.004', 'name': 'Application or System Exploitation', 'tactic': 'Impact'},
    ],

    # Datenbank-Events
    'db_connect': [
        {'id': 'T1078',     'name': 'Valid Accounts',                  'tactic': 'Defense Evasion'},
    ],
    'db_error': [
        {'id': 'T1499.002', 'name': 'Service Exhaustion Flood',        'tactic': 'Impact'},
    ],

    # Remote-Thread (Sysmon EventID 8 — häufig bei Injection)
    'remote_thread_create': [
        {'id': 'T1055',     'name': 'Process Injection',               'tactic': 'Defense Evasion'},
        {'id': 'T1055.012', 'name': 'Process Hollowing',               'tactic': 'Defense Evasion'},
    ],

    # Sysmon-spezifische Events
    'file_create': [
        {'id': 'T1105',     'name': 'Ingress Tool Transfer',           'tactic': 'Command and Control'},
    ],
    'file_deleted': [
        {'id': 'T1070.004', 'name': 'File Deletion',                   'tactic': 'Defense Evasion'},
    ],
    'file_access': [
        {'id': 'T1083',     'name': 'File and Directory Discovery',    'tactic': 'Discovery'},
    ],

    # ══════════════════════════════════════════════════════════════════════
    # ── NIEDRIG / HINTERGRUND (Score 1–3) ─────────────────────────────────
    # ══════════════════════════════════════════════════════════════════════

    'session_closed': [],       # Normaler Logout
    'system_boot': [
        {'id': 'T1529',     'name': 'System Shutdown/Reboot',          'tactic': 'Impact'},
    ],
    'pam_event': [],
    'db_query': [],
    'db_warning': [],
    'db_event': [],
    'vpn_event': [],
    'vpn_tls_error': [],
    'kernel_event': [],
    'system_event': [],
    'network_activity': [],
    'audit_event': [],
    'sysmon_event': [],
    'process_event': [],
    'log_entry': [],
    'login_event': [],

    # ══════════════════════════════════════════════════════════════════════
    # ── ERGAENZUNG: Fehlende Techniken fuer >= 80 Gesamt (ATT&CK v15) ────
    # ══════════════════════════════════════════════════════════════════════

    # Obfuskation / Verschleierung von Dateien und Payloads
    'obfuscation': [
        {'id': 'T1027',     'name': 'Obfuscated Files or Information', 'tactic': 'Defense Evasion'},
        {'id': 'T1027.001', 'name': 'Binary Padding',                  'tactic': 'Defense Evasion'},
        {'id': 'T1027.004', 'name': 'Compile After Delivery',          'tactic': 'Defense Evasion'},
    ],

    # Masquerading: Angreifer-Tool tarnt sich als legitimes Programm
    'masquerading': [
        {'id': 'T1036',     'name': 'Masquerading',                    'tactic': 'Defense Evasion'},
        {'id': 'T1036.005', 'name': 'Match Legitimate Name or Location','tactic': 'Defense Evasion'},
    ],

    # Daten archivieren vor Exfiltration (zip, tar, 7z)
    'data_archived': [
        {'id': 'T1560',     'name': 'Archive Collected Data',          'tactic': 'Collection'},
        {'id': 'T1560.001', 'name': 'Archive via Utility',             'tactic': 'Collection'},
    ],

    # Daten aus lokalem System sammeln (Clipboard, Screenshots, Dateien)
    'data_collection': [
        {'id': 'T1005',     'name': 'Data from Local System',          'tactic': 'Collection'},
        {'id': 'T1074',     'name': 'Data Staged',                     'tactic': 'Collection'},
        {'id': 'T1074.001', 'name': 'Local Data Staging',              'tactic': 'Collection'},
    ],

    # Supply-Chain / externe Ressourcen missbrauchen
    'supply_chain': [
        {'id': 'T1195',     'name': 'Supply Chain Compromise',         'tactic': 'Initial Access'},
        {'id': 'T1195.002', 'name': 'Compromise Software Supply Chain','tactic': 'Initial Access'},
    ],
}


# ── Taktik-Gruppen für Analyse-Modus-Filter ───────────────────────────────────
#
# Diese Sets werden in MitreMapper.map_event() verwendet, um Techniken nach
# Analyse-Perspektive zu filtern. Ein Event kann in beiden Sets relevante
# Taktiken haben — der Modus entscheidet, welche zurückgegeben werden.
# ─────────────────────────────────────────────────────────────────────────────

# Taktiken die typisch für Täterinfrastruktur sind
ATTACKER_INFRA_TACTICS = {
    'Resource Development',
    'Command and Control',
    'Exfiltration',
    'Lateral Movement',
}

# Taktiken die typisch für angegriffene Server sind
VICTIM_SERVER_TACTICS = {
    'Initial Access',
    'Execution',
    'Persistence',
    'Privilege Escalation',
    'Defense Evasion',
    'Credential Access',
    'Discovery',
    'Impact',
}


# ── Mapper-Klasse ─────────────────────────────────────────────────────────────

class MitreMapper:
    """
    Ordnet forensische Events MITRE ATT&CK Techniken zu und reichert die
    Timeline mit strukturierten Taktik- und Technik-Informationen an.

    Unterstützt drei Analyse-Modi, die über den Konstruktor gesetzt werden:
      - 'attacker_infra' : Nur Techniken aus ATTACKER_INFRA_TACTICS zurückgeben
      - 'victim_server'  : Nur Techniken aus VICTIM_SERVER_TACTICS zurückgeben
      - 'both' (Standard): Alle Techniken zurückgeben, kein Filter

    Typischer Aufruf-Ablauf in der Pipeline:
        1. mapper.enrich_timeline(timeline)   → Timeline mit Technik-Feldern
        2. mapper.get_tactic_summary(events)  → Häufigkeits-Übersicht pro Taktik
        3. mapper.get_kill_chain_coverage(events) → Kill-Chain Visualisierungs-Daten
    """

    def __init__(self, mode: str = 'both'):
        self.mapping = MITRE_MAPPING
        self.mode = mode

    def map_event(self, event: Dict) -> List[Dict[str, str]]:
        """
        Gibt MITRE-Techniken für ein einzelnes Event zurück.
        Filtert nach Analyse-Modus wenn gesetzt.

        Args:
            event: Normalisiertes Event-Dict, muss 'event_type' enthalten.
                   Fallback: event['metadata']['event_type'] wird geprüft.

        Returns:
            Liste von Technik-Dicts mit Feldern 'id', 'name', 'tactic'.
            Leere Liste wenn kein Mapping oder event_type 'unknown'.
        """
        event_type = event.get('event_type', '')
        if not event_type or event_type == 'unknown':
            # Fallback: event_type aus verschachteltem metadata-Feld holen
            meta = event.get('metadata', {})
            if isinstance(meta, dict):
                event_type = meta.get('event_type', 'unknown')

        techniques = self.mapping.get(event_type, [])

        # Modus-Filter anwenden
        if self.mode == 'attacker_infra':
            techniques = [t for t in techniques if t['tactic'] in ATTACKER_INFRA_TACTICS]
        elif self.mode == 'victim_server':
            techniques = [t for t in techniques if t['tactic'] in VICTIM_SERVER_TACTICS]

        return techniques

    def enrich_timeline(self, timeline: List[Dict]) -> List[Dict]:
        """
        Reichert alle Timeline-Events mit MITRE-Techniken an.

        Fügt jedem Event folgende Felder hinzu:
        - 'mitre_techniques': Liste der zugeordneten Techniken
        - 'mitre_tactics':    Deduplizierte Taktiken-Liste (Reihenfolge erhalten)
        - 'is_attacker_infra': True wenn mindestens eine Täterinfrastruktur-Taktik vorhanden

        Args:
            timeline: Liste normalisierter Event-Dicts (wird in-place modifiziert).

        Returns:
            Dieselbe Timeline-Liste, jetzt mit MITRE-Feldern angereichert.
        """
        mapped_count   = 0
        technique_ids  = set()
        infra_count    = 0

        for event in timeline:
            techniques = self.map_event(event)
            event['mitre_techniques'] = techniques

            if techniques:
                mapped_count += 1
                technique_ids.update(t['id'] for t in techniques)

                # Deduplizierte Taktiken-Liste (dict.fromkeys erhält Reihenfolge)
                tactics = list(dict.fromkeys(t['tactic'] for t in techniques))
                event['mitre_tactics'] = tactics

                # Täterinfrastruktur-Flag setzen
                is_infra = any(t['tactic'] in ATTACKER_INFRA_TACTICS for t in techniques)
                event['is_attacker_infra'] = is_infra
                if is_infra:
                    infra_count += 1
            else:
                event['mitre_tactics']    = []
                event['is_attacker_infra'] = False

        logger.info(
            f"✓ MITRE-Mapping: {mapped_count}/{len(timeline)} Events zugeordnet "
            f"({len(technique_ids)} Techniken, {infra_count} Täterinfrastruktur-Events)"
        )
        return timeline

    def get_tactic_summary(self, events: List[Dict]) -> Dict[str, int]:
        """
        Zählt Vorkommnisse pro MITRE-Taktik (sortiert nach Häufigkeit, absteigend).

        Args:
            events: Liste von Events, die bereits durch enrich_timeline() angereichert wurden.

        Returns:
            Dict {tactic_name: count}, z.B. {'Defense Evasion': 42, 'Execution': 17}.
        """
        tactic_counts: Dict[str, int] = {}
        for event in events:
            for tech in event.get('mitre_techniques', []):
                tactic = tech['tactic']
                tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
        return dict(sorted(tactic_counts.items(), key=lambda x: x[1], reverse=True))

    def get_technique_summary(self, events: List[Dict]) -> List[Dict]:
        """
        Gibt alle gefundenen Techniken mit ihrer Auftretenshäufigkeit zurück
        (sortiert nach Häufigkeit, absteigend).

        Args:
            events: Liste von Events, die bereits durch enrich_timeline() angereichert wurden.

        Returns:
            Liste von Dicts mit Feldern 'id', 'name', 'tactic', 'count'.
            Jede Technik erscheint nur einmal (dedupliziert nach Technik-ID).
        """
        technique_counts: Dict[str, Dict] = {}
        for event in events:
            for tech in event.get('mitre_techniques', []):
                tid = tech['id']
                if tid not in technique_counts:
                    technique_counts[tid] = {
                        'id':     tid,
                        'name':   tech['name'],
                        'tactic': tech['tactic'],
                        'count':  0,
                    }
                technique_counts[tid]['count'] += 1
        return sorted(technique_counts.values(), key=lambda x: x['count'], reverse=True)

    def get_attacker_infra_summary(self, events: List[Dict]) -> Dict:
        """
        Erstellt eine Täterinfrastruktur-spezifische Zusammenfassung der Events.

        Kategorisiert Events in vier operative Aktivitätsbereiche:
          - c2_indicators:    C2-Kommunikation (Beaconing, Tunnel, VPN)
          - tool_staging:     Werkzeug-Vorbereitung (Downloads, Tool-Installationen)
          - lateral_movement: Seitwärtsbewegung im Netzwerk (SSH, Auth-Erfolge)
          - exfiltration:     Daten-Diebstahl (Exfiltrations-Events, Downloads)

        Args:
            events: Liste normalisierter Events (sollten bereits MITRE-angereichert sein).

        Returns:
            Dict mit den vier Kategorien-Listen sowie 'tactic_coverage' (Liste
            aller erkannten MITRE-Taktiken als Set → wird zu List konvertiert).
        """
        summary = {
            'c2_indicators':    [],
            'tool_staging':     [],
            'lateral_movement': [],
            'exfiltration':     [],
            'tactic_coverage':  set(),
        }

        c2_event_types = {
            'c2_beacon', 'c2_tool', 'vpn_connection', 'dns_query', 'network_connect',
        }
        staging_event_types = {
            'suspicious_tool_installed', 'package_install', 'file_download',
            'file_create',
        }
        lateral_event_types = {
            'ssh_event', 'auth_success', 'vpn_connection',
        }
        exfil_event_types = {
            'data_exfiltration', 'file_download',
        }

        for event in events:
            et = event.get('event_type', '')
            techniques = event.get('mitre_techniques', [])

            for tech in techniques:
                summary['tactic_coverage'].add(tech['tactic'])

            if et in c2_event_types:
                summary['c2_indicators'].append(event)
            if et in staging_event_types:
                summary['tool_staging'].append(event)
            if et in lateral_event_types:
                summary['lateral_movement'].append(event)
            if et in exfil_event_types:
                summary['exfiltration'].append(event)

        # Set zu List konvertieren für JSON-Serialisierbarkeit
        summary['tactic_coverage'] = list(summary['tactic_coverage'])

        logger.info(
            f"Täterinfrastruktur-Analyse: "
            f"C2={len(summary['c2_indicators'])}, "
            f"Staging={len(summary['tool_staging'])}, "
            f"Lateral={len(summary['lateral_movement'])}, "
            f"Exfil={len(summary['exfiltration'])}"
        )
        return summary

    def get_kill_chain_coverage(self, events: List[Dict]) -> List[Dict]:
        """
        Gibt die Cyber Kill Chain Coverage als strukturierte Liste zurück.

        Mappt alle 13 MITRE ATT&CK Taktiken auf die entsprechenden Phasen der
        Lockheed Martin Cyber Kill Chain und markiert, welche im Datensatz
        tatsächlich erkannt wurden.

        Args:
            events: Liste von Events, die durch enrich_timeline() angereichert wurden.

        Returns:
            Liste von Dicts (eine Eintrag pro Taktik) mit:
              - 'tactic':           MITRE-Taktik-Name (englisch)
              - 'label_de':         Deutscher Kill-Chain-Phasen-Name
              - 'detected':         True wenn diese Taktik im Datensatz vorkommt
              - 'is_infra_tactic':  True wenn Täterinfrastruktur-Taktik
        """
        KILL_CHAIN_MAP = {
            'Reconnaissance':         'Aufklärung',
            'Resource Development':   'Waffenentwicklung',
            'Initial Access':         'Zustellung / Erstzugriff',
            'Execution':              'Ausführung',
            'Persistence':            'Persistenz',
            'Privilege Escalation':   'Rechteausweitung',
            'Defense Evasion':        'Tarnung',
            'Credential Access':      'Anmeldedaten-Diebstahl',
            'Discovery':              'Aufklärung (intern)',
            'Lateral Movement':       'Seitwärtsbewegung',
            'Command and Control':    'C2-Kommunikation',
            'Exfiltration':           'Daten-Exfiltration',
            'Impact':                 'Auswirkung / Schaden',
        }

        found_tactics = set()
        for event in events:
            for tech in event.get('mitre_techniques', []):
                found_tactics.add(tech['tactic'])

        result = []
        for mitre_tactic, german_label in KILL_CHAIN_MAP.items():
            result.append({
                'tactic':        mitre_tactic,
                'label_de':      german_label,
                'detected':      mitre_tactic in found_tactics,
                'is_infra_tactic': mitre_tactic in ATTACKER_INFRA_TACTICS,
            })
        return result
