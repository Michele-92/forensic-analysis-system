"""
================================================================================
SYSTEM PROFILER — Automatisches Profiling des analysierten Systems
================================================================================
Erstellt ein strukturiertes Systemprofil aus bereits extrahierten forensischen
Artefakten und der normalisierten Timeline. Das Profil dient nachgelagerten
Pipeline-Stufen (Anomalie-Erkennung, LLM-Agent) als Kontext-Grundlage, damit
diese die Befunde richtig einordnen können.

Aufgaben:
    - OS-Erkennung: Identifiziert Linux / Windows / macOS anhand bekannter
      Pfadmuster in der Timeline und in Artefakten (Score-basiert)
    - Distro-Erkennung: Unterscheidet Debian/Ubuntu, RHEL/CentOS, Arch, Alpine
      über Pfade und Regex-Auswertung von Log-Nachrichten
    - Kernel-Version: Extrahiert aus Boot- und Syslog-Events
    - Hostname: Häufigstes nicht-triviales 'hostname'-Feld aller Events
    - Benutzerkonten: Aggregiert alle auftretenden Usernamen, filtert System-
      Accounts heraus, sortiert nach Häufigkeit
    - Installierte Pakete: Sammelt APT/YUM-Installationsereignisse
    - Laufende Dienste: Identifiziert Systemd-Units aus service_event-Einträgen
    - Netzwerk-IPs: Extrahiert per Regex die häufigsten IP-Adressen aus Logs
    - Verdächtige Verzeichnisse: Findet Dateien in typischen Malware-Ablageorten
      (/tmp, /dev/shm, /run/user, ...)
    - Konfidenz-Bewertung: Bewertet Vollständigkeit des erstellten Profils

Verwendung:
    profiler = SystemProfiler()
    profile  = profiler.build_profile(timeline=events, artifacts=artifacts)
    # → {'os_type': 'linux', 'distribution': 'Debian/Ubuntu', 'kernel': '5.15.0',
    #    'hostname': 'srv-web01', 'users': ['alice', 'bob'], ...}

Pipeline-Position:
    Stage 5b — nach DataNormalizer (Stage 5), vor AntiForensicsChecker (Stage 5c)
    und vor AnomalyDetector (Stage 6).

Abhängigkeiten:
    - re      (stdlib) — Regex für Kernel/Distro-Erkennung und IP-Extraktion
    - logging (stdlib)
    - pathlib (stdlib)
    - typing  (stdlib)

Kontext: LFX Forensic Analysis System — backend/pipeline.py
"""

import re
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class SystemProfiler:
    """
    Erstellt ein Systemprofil aus extrahierten Artefakten und Timeline-Events.

    Das Profil ist ein Dict mit standardisierten Feldern (siehe _empty_profile).
    Die Methode build_profile() orchestriert alle internen Extraktions-Methoden
    und gibt das fertige Profil zurück.

    Erkannte Eigenschaften:
    - OS-Typ (Linux / Windows / macOS / unbekannt)
    - Linux-Distribution und Version
    - Kernel-Version
    - Hostname
    - Zeitzone
    - Benutzerliste (aus /etc/passwd oder Artefakten)
    - Installierte Pakete (aus APT/YUM-Logs)
    - Netzwerkschnittstellen (aus Logs)
    - Relevante Dienste (aus systemd/service Events)
    - Verdaechtige Pfade und Hinweise fuer die Anomalie-Erkennung

    Beispiel-Ausgabe (Profil-Dict):
        {
          'os_type':        'linux',
          'os_family':      'debian',
          'distribution':   'Ubuntu',
          'version':        '22.04',
          'kernel':         '5.15.0-91-generic',
          'hostname':       'srv-web01',
          'users':          ['alice', 'bob', 'deploy'],
          'packages':       [{'name': 'nmap', 'action': 'install'}, ...],
          'services':       ['nginx.service', 'sshd.service'],
          'network_ifaces': ['192.168.1.10', '10.0.0.5'],
          'suspicious_dirs': ['/tmp/payload.sh'],
          'confidence':     'high',
          ...
        }
    """

    # Typische Linux-Pfade zur OS-Erkennung
    LINUX_INDICATORS = {
        '/etc/os-release', '/etc/debian_version', '/etc/redhat-release',
        '/etc/centos-release', '/etc/ubuntu_version', '/etc/arch-release',
        '/etc/gentoo-release', '/etc/alpine-release', '/proc/version',
        '/bin/bash', '/usr/bin/python3', '/usr/bin/perl',
    }

    WINDOWS_INDICATORS = {
        'C:\\Windows\\System32', 'C:\\Windows\\SysWOW64',
        'NTUSER.DAT', 'SAM', 'SYSTEM', 'SOFTWARE',
    }

    MACOS_INDICATORS = {
        '/System/Library', '/usr/local/bin', '/Applications',
        'com.apple', '.plist',
    }

    # Regex fuer Kernel-Version aus /proc/version oder uname-Ausgabe
    KERNEL_RE = re.compile(r'Linux version (\S+)', re.IGNORECASE)
    # Debian/Ubuntu: "buster/sid", "jammy"
    DEBIAN_RE = re.compile(r'(Ubuntu|Debian)[^\d]*(\d+[\.\d]*)', re.IGNORECASE)
    # RHEL/CentOS: "CentOS Linux release 7.9"
    RHEL_RE = re.compile(r'(CentOS|Red Hat|Rocky|AlmaLinux|Fedora)[^\d]*(\d+[\.\d]*)', re.IGNORECASE)

    def __init__(self):
        self.profile: Dict[str, Any] = self._empty_profile()

    @staticmethod
    def _empty_profile() -> Dict[str, Any]:
        """
        Gibt ein leeres Profil-Dict mit allen erwarteten Feldern zurück.
        Wird zu Beginn jedes build_profile()-Aufrufs als Startpunkt gesetzt,
        damit keine Felder aus einem vorherigen Lauf erhalten bleiben.
        """
        return {
            'os_type':        'unknown',
            'os_family':      'unknown',
            'distribution':   None,
            'version':        None,
            'kernel':         None,
            'hostname':       None,
            'timezone':       None,
            'users':          [],
            'packages':       [],
            'services':       [],
            'network_ifaces': [],
            'suspicious_dirs':[],
            'indicators':     [],
            'confidence':     'low',
            'evidence':       [],
        }

    def build_profile(self, timeline: List[Dict], artifacts: List[Dict]) -> Dict[str, Any]:
        """
        Erstellt das vollständige Systemprofil aus Timeline-Events und Artefakten.

        Orchestriert alle internen Erkennungs-Methoden in der sinnvollen
        Reihenfolge (OS → Hostname → Kernel → Benutzer → ...) und gibt
        am Ende das ausgefüllte Profil-Dict zurück.

        Args:
            timeline:  Normalisierte Timeline-Events (Ausgabe des DataNormalizer).
            artifacts: Extrahierte Artefakte (Dissect, UAC, etc.) als Liste von Dicts.

        Returns:
            Vollstaendiges System-Profil als Dict (Felder siehe _empty_profile).
        """
        self.profile = self._empty_profile()

        self._detect_os_from_paths(timeline, artifacts)
        self._extract_hostname(timeline)
        self._extract_kernel(timeline)
        self._extract_users(timeline, artifacts)
        self._extract_packages(timeline)
        self._extract_services(timeline)
        self._extract_network(timeline)
        self._detect_suspicious_dirs(timeline)
        self._assess_confidence()

        logger.info(
            f"System-Profil erstellt: OS={self.profile['os_type']}, "
            f"Distro={self.profile['distribution']}, "
            f"Kernel={self.profile['kernel']}, "
            f"Nutzer={len(self.profile['users'])}, "
            f"Pakete={len(self.profile['packages'])}, "
            f"Confidence={self.profile['confidence']}"
        )
        return self.profile

    # ── OS-Erkennung ──────────────────────────────────────────────────────────

    def _detect_os_from_paths(self, timeline: List[Dict], artifacts: List[Dict]) -> None:
        """
        Erkennt OS-Typ anhand bekannter Pfadmuster in Timeline und Artefakten.

        Strategie: Sammelt alle Pfadangaben aus beiden Quellen, berechnet einen
        Score für Linux/Windows/macOS (Anzahl der Treffer gegen die jeweiligen
        Indikator-Sets), und wählt den OS-Typ mit dem höchsten Score.
        Bei Linux wird zusätzlich die Distro-Erkennung angestoßen.

        Args:
            timeline:  Normalisierte Events mit 'path'- oder metadata-Feldern.
            artifacts: Artefakt-Dicts mit 'path'- oder 'name'-Feldern.
        """
        all_paths = set()

        for event in timeline:
            p = event.get('path') or event.get('metadata', {}).get('path', '')
            if p:
                all_paths.add(str(p))

        for artifact in artifacts:
            p = artifact.get('path') or artifact.get('name', '')
            if p:
                all_paths.add(str(p))

        linux_score   = sum(1 for p in all_paths if any(ind in p for ind in self.LINUX_INDICATORS))
        windows_score = sum(1 for p in all_paths if any(ind in p for ind in self.WINDOWS_INDICATORS))
        macos_score   = sum(1 for p in all_paths if any(ind in p for ind in self.MACOS_INDICATORS))

        scores = {'linux': linux_score, 'windows': windows_score, 'macos': macos_score}
        best = max(scores, key=scores.get)

        if scores[best] > 0:
            self.profile['os_type'] = best
            self.profile['os_family'] = best
            self.profile['evidence'].append(
                f"OS-Erkennung: {best} ({scores[best]} Pfad-Indikatoren)"
            )

        # Linux-Distribution aus Pfaden ableiten
        if best == 'linux':
            self._detect_linux_distro(all_paths, timeline)

    def _detect_linux_distro(self, paths: set, timeline: List[Dict]) -> None:
        """
        Erkennt Linux-Distribution aus Pfaden und Log-Inhalten.

        Prüft zunächst die Pfad-Menge auf Paketmanager-spezifische Pfade
        (apt, yum, dnf, pacman, apk) und distro-spezifische Konfig-Dateien.
        Falls nicht eindeutig, wird per Regex nach Distro-Namen in Log-
        Nachrichten gesucht (z.B. "Ubuntu 22.04", "CentOS Linux release 7").

        Args:
            paths:    Menge aller gesammelten Dateipfade aus Timeline + Artefakten.
            timeline: Events für Regex-Suche in Nachrichten-Feldern.
        """
        # Aus Pfaden
        if any('/etc/debian_version' in p or 'apt' in p.lower() for p in paths):
            self.profile['distribution'] = 'Debian/Ubuntu'
            self.profile['os_family'] = 'debian'
        elif any('/etc/redhat-release' in p or '/etc/centos-release' in p
                 or 'yum' in p.lower() or 'dnf' in p.lower() for p in paths):
            self.profile['distribution'] = 'RHEL/CentOS/Fedora'
            self.profile['os_family'] = 'rhel'
        elif any('/etc/arch-release' in p or 'pacman' in p.lower() for p in paths):
            self.profile['distribution'] = 'Arch Linux'
            self.profile['os_family'] = 'arch'
        elif any('/etc/alpine-release' in p or 'apk' in p.lower() for p in paths):
            self.profile['distribution'] = 'Alpine Linux'
            self.profile['os_family'] = 'alpine'

        # Aus Log-Nachrichten (APT/YUM-Events)
        for event in timeline:
            msg = event.get('message', '') or event.get('description', '')
            if not msg:
                continue
            m = self.DEBIAN_RE.search(msg)
            if m:
                self.profile['distribution'] = m.group(1)
                self.profile['version'] = m.group(2)
                break
            m = self.RHEL_RE.search(msg)
            if m:
                self.profile['distribution'] = m.group(1)
                self.profile['version'] = m.group(2)
                break

    # ── Hostname-Extraktion ───────────────────────────────────────────────────

    def _extract_hostname(self, timeline: List[Dict]) -> None:
        """
        Extrahiert den wahrscheinlichsten Hostnamen aus Timeline-Events.

        Strategie: Zählt alle Hostname-Vorkommen (aus 'hostname', 'metadata.hostname'
        und 'host'-Feldern), ignoriert triviale Werte (localhost, 127.0.0.1, '-')
        und wählt den am häufigsten vorkommenden Wert.

        Args:
            timeline: Normalisierte Events mit optionalen Hostname-Feldern.
        """
        hostnames: Dict[str, int] = {}
        for event in timeline:
            h = (event.get('hostname') or
                 event.get('metadata', {}).get('hostname') or
                 event.get('host'))
            if h and h not in ('localhost', '127.0.0.1', '-', ''):
                hostnames[h] = hostnames.get(h, 0) + 1

        if hostnames:
            self.profile['hostname'] = max(hostnames, key=hostnames.get)
            self.profile['evidence'].append(
                f"Hostname: {self.profile['hostname']} ({hostnames[self.profile['hostname']]} Vorkommen)"
            )

    # ── Kernel-Version ────────────────────────────────────────────────────────

    def _extract_kernel(self, timeline: List[Dict]) -> None:
        """
        Extrahiert die Kernel-Version aus Boot- oder Syslog-Events.

        Sucht nach dem Muster "Linux version X.Y.Z..." (KERNEL_RE) in den
        Nachrichten-Feldern der Events. Bricht nach dem ersten Treffer ab.

        Args:
            timeline: Normalisierte Events; relevante Quelle sind typischerweise
                      system_boot- oder kernel_event-Einträge aus /proc/version
                      oder dem Kernel-Ring-Buffer (dmesg).
        """
        for event in timeline:
            msg = event.get('message', '') or event.get('description', '')
            if not msg:
                continue
            m = self.KERNEL_RE.search(str(msg))
            if m:
                self.profile['kernel'] = m.group(1)
                self.profile['evidence'].append(f"Kernel: {m.group(1)}")
                break

    # ── Benutzer-Extraktion ───────────────────────────────────────────────────

    def _extract_users(self, timeline: List[Dict], artifacts: List[Dict]) -> None:
        """
        Sammelt bekannte Benutzernamen aus Events und Artefakten.

        Filtert System-Accounts heraus (root, daemon, nobody, www-data, etc.)
        und sortiert die gefundenen Benutzernamen nach Häufigkeit. Gibt die
        Top 20 zurück, um das Profil kompakt zu halten.

        Args:
            timeline:  Events mit 'user'-, 'metadata.user'- oder 'username'-Feldern.
            artifacts: Artefakt-Dicts mit 'user'- oder 'username'-Feldern.
        """
        users: Dict[str, int] = {}
        skip = {'root', 'daemon', 'nobody', 'www-data', 'systemd', '-', '', 'unknown'}

        for event in timeline:
            u = (event.get('user') or
                 event.get('metadata', {}).get('user') or
                 event.get('username'))
            if u and u not in skip:
                users[u] = users.get(u, 0) + 1

        for artifact in artifacts:
            u = artifact.get('user') or artifact.get('username', '')
            if u and u not in skip:
                users[u] = users.get(u, 0) + 1

        # Nach Haeufigkeit sortiert, Top-20
        self.profile['users'] = sorted(users.keys(), key=lambda x: users[x], reverse=True)[:20]
        if self.profile['users']:
            self.profile['evidence'].append(
                f"Benutzer gefunden: {', '.join(self.profile['users'][:5])}"
                + (f" (+{len(self.profile['users']) - 5} weitere)" if len(self.profile['users']) > 5 else "")
            )

    # ── Paket-Extraktion ──────────────────────────────────────────────────────

    def _extract_packages(self, timeline: List[Dict]) -> None:
        """
        Extrahiert installierte Pakete aus APT/YUM-Events der Timeline.

        Berücksichtigt nur Events vom Typ 'package_install' oder
        'suspicious_tool_installed'. Speichert maximal 100 Pakete
        (chronologisch, neuere überschreiben ältere bei gleichem Namen).

        Args:
            timeline: Normalisierte Events; package_install-Einträge stammen
                      typischerweise aus dem Dissect APT/dpkg-Parser.
        """
        packages = {}
        for event in timeline:
            if event.get('event_type') not in ('package_install', 'suspicious_tool_installed'):
                continue
            pkg = (event.get('package') or
                   event.get('metadata', {}).get('package', ''))
            action = event.get('action', 'install')
            if pkg:
                packages[pkg] = action

        self.profile['packages'] = [
            {'name': k, 'action': v} for k, v in list(packages.items())[:100]
        ]
        if packages:
            self.profile['evidence'].append(
                f"Pakete: {len(packages)} Installationen/Updates erkannt"
            )

    # ── Dienste-Extraktion ────────────────────────────────────────────────────

    def _extract_services(self, timeline: List[Dict]) -> None:
        """
        Extrahiert laufende oder gestartete Dienste aus systemd-/service-Events.

        Wertet Events vom Typ 'service_event' und 'persistence_mechanism' aus
        und extrahiert den Unit-Namen aus 'unit'-, 'metadata.unit'- oder
        'metadata.service'-Feldern. Gibt maximal 50 Dienste zurück.

        Args:
            timeline: Normalisierte Events; relevante Quelle sind systemd-
                      Journal-Einträge die der Log-Parser erkannt hat.
        """
        services: Dict[str, str] = {}
        for event in timeline:
            if event.get('event_type') not in ('service_event', 'persistence_mechanism'):
                continue
            svc = (event.get('unit') or
                   event.get('metadata', {}).get('unit') or
                   event.get('metadata', {}).get('service', ''))
            if svc:
                services[svc] = event.get('event_type', 'service_event')

        self.profile['services'] = list(services.keys())[:50]

    # ── Netzwerk-Extraktion ───────────────────────────────────────────────────

    def _extract_network(self, timeline: List[Dict]) -> None:
        """
        Extrahiert häufige Netzwerk-IPs aus Event-Nachrichten per Regex.

        Sucht mit einem IPv4-Regex (4 Oktette) in 'message'- und 'description'-
        Feldern. Filtert Loopback (127.x) und Meta-Adressen (0.x) heraus.
        Gibt die Top 20 IPs nach Häufigkeit zurück.

        Hinweis: Das Feld heißt 'network_ifaces', enthält aber IP-Adressen
        (kein Interface-Name wie eth0), da die reinen Interface-Namen selten
        in Log-Nachrichten auftauchen.

        Args:
            timeline: Normalisierte Events mit Freitext-Nachrichten-Feldern.
        """
        ip_re = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        ips: Dict[str, int] = {}
        for event in timeline:
            msg = event.get('message', '') or event.get('description', '')
            for ip in ip_re.findall(str(msg)):
                # Localhost und private RFC1918 zaehlen, externe IPs separat markieren
                if not ip.startswith('127.') and not ip.startswith('0.'):
                    ips[ip] = ips.get(ip, 0) + 1

        # Top-20 IPs nach Haeufigkeit
        self.profile['network_ifaces'] = sorted(
            ips.keys(), key=lambda x: ips[x], reverse=True
        )[:20]

    # ── Verdaechtige Verzeichnisse ────────────────────────────────────────────

    def _detect_suspicious_dirs(self, timeline: List[Dict]) -> None:
        """
        Erkennt Dateien an typischen Malware-Ablageorten.

        Bekannte verdächtige Verzeichnisse: /tmp, /var/tmp, /dev/shm (RAM-Disk),
        /run/user, versteckte Dotfiles in /root/.* oder /home/*/.config.
        Ein Treffer erhöht nicht den Risiko-Score direkt, liefert aber
        Kontext für den AntiForensicsChecker und den LLM-Agenten.

        Args:
            timeline: Normalisierte Events mit 'path'- oder metadata-Pfad-Feldern.
        """
        suspicious_patterns = [
            '/tmp/', '/var/tmp/', '/dev/shm/', '/run/user/',
            '/.', '/root/.', '/home/.*/.config/',
        ]
        found = set()
        for event in timeline:
            p = event.get('path') or event.get('metadata', {}).get('path', '')
            if p:
                for pattern in suspicious_patterns:
                    if pattern.rstrip('/') in str(p):
                        found.add(str(p))
                        break

        self.profile['suspicious_dirs'] = sorted(found)[:30]
        if found:
            self.profile['indicators'].append(
                f"{len(found)} Dateien in verdaechtigen Verzeichnissen (/tmp, /dev/shm, ...)"
            )

    # ── Konfidenz-Bewertung ───────────────────────────────────────────────────

    def _assess_confidence(self) -> None:
        """
        Bewertet die Vollständigkeit und Qualität des erstellten Profils.

        Vergibt Punkte für jedes gefüllte Profilfeld und klassifiziert
        das Gesamtergebnis in 'high' (>=6), 'medium' (>=3) oder 'low' (<3).
        Das Konfidenz-Level hilft nachgelagerten Modulen einzuschätzen, wie
        verlässlich die Kontextinformationen des Profils sind.

        Punktevergabe:
            os_type bekannt:       +2
            hostname vorhanden:    +1
            kernel vorhanden:      +2
            benutzer gefunden:     +1
            distribution erkannt:  +1
            pakete gefunden:       +1
        """
        score = 0
        if self.profile['os_type'] != 'unknown':
            score += 2
        if self.profile['hostname']:
            score += 1
        if self.profile['kernel']:
            score += 2
        if self.profile['users']:
            score += 1
        if self.profile['distribution']:
            score += 1
        if self.profile['packages']:
            score += 1

        if score >= 6:
            self.profile['confidence'] = 'high'
        elif score >= 3:
            self.profile['confidence'] = 'medium'
        else:
            self.profile['confidence'] = 'low'
