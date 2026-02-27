"""
Log-Parser für Text-basierte und Binär-Log-Dateien.

Unterstützte Formate (Linux-Fokus, air-gapped):
────────────────────────────────────────────────
1.  Syslog / Auth.log      — klassisches RFC 3164 Format
2.  Apache / Nginx         — Combined Log Format
3.  Firewall (iptables)    — Kernel-Logging + einfaches ALLOW/BLOCK
4.  Linux Audit Log        — type=SYSCALL / type=EXECVE / type=USER_*
5.  Systemd Journal        — JSON-Export via journalctl --output=json
6.  APT / dpkg Log         — Debian/Ubuntu Paketverwaltung
7.  YUM / DNF Log          — RHEL/CentOS/Fedora Paketverwaltung
8.  wtmp / btmp / utmpdb   — Binäres Login-Journal (struct-basiert)
9.  MySQL Error Log        — 8.x und 5.7 Format
10. MySQL General Log      — Query-Log
11. OpenVPN Log            — Verbindungs- und Trennungs-Events
12. sysmon for Linux       — XML-Events in Syslog (Sysinternals)
13. ISO-Timestamp          — Windows Event Log Text-Export (Fallback)
14. Pipe-delimited         — Timeline-Format (Fallback)
15. Generic                — Unbekannte Formate (letzter Fallback)
"""

import re
import json
import struct
import logging
import subprocess
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# Regex-Kompilate (einmalig kompiliert für Performance)
# ═══════════════════════════════════════════════════════════════════════════════

# 1. Syslog RFC 3164: "Jan 15 08:00:01 hostname process[pid]: message"
SYSLOG_RE = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<hostname>\S+)\s+(?P<process>[^\[:]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.+)$'
)

# 1b. Syslog RFC 5424: "2025-01-15T08:00:01+00:00 hostname process[pid]: message"
SYSLOG5424_RE = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[+-]\d{2}:\d{2}|Z)?)\s+'
    r'(?P<hostname>\S+)\s+(?P<process>[^\[:]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.+)$'
)

# 2. Apache/Nginx Combined: '10.0.1.50 - admin [15/Jan/2025:08:00:01 +0000] "GET /path HTTP/1.1" 200 5432'
APACHE_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+\S+"\s+(?P<status>\d+)\s+(?P<size>\d+|-)'
)

# 3a. iptables Kernel-Log: "Jan 15 08:00:01 host kernel: [12345.678] IPTABLES-DROP: IN=eth0 ..."
IPTABLES_KERNEL_RE = re.compile(
    r'(?P<prefix>[A-Z0-9_-]+(?:ACCEPT|DROP|REJECT|DENY|BLOCK|LOG|FORWARD|INPUT|OUTPUT)[A-Z0-9_-]*):\s+'
    r'(?:IN=(?P<in_if>\S*)\s+)?'
    r'(?:OUT=(?P<out_if>\S*)\s+)?'
    r'(?:MAC=(?P<mac>\S+)\s+)?'
    r'(?:SRC=(?P<src_ip>\S+)\s+)?'
    r'(?:DST=(?P<dst_ip>\S+)\s+)?'
    r'(?:LEN=(?P<len>\d+)\s+)?'
    r'(?:PROTO=(?P<proto>\S+)\s+)?'
    r'(?:SPT=(?P<spt>\d+)\s+)?'
    r'(?:DPT=(?P<dpt>\d+)\s+)?'
    r'(?P<rest>.*)?$'
)

# 3b. Einfaches Firewall-Log: "2025-01-15 08:00:00 ALLOW/BLOCK TCP ..."
FIREWALL_SIMPLE_RE = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<action>ALLOW|BLOCK|DROP|DENY|REJECT)\s+(?P<proto>\S+)\s+(?P<rest>.+)$'
)

# 4. Linux Audit: "type=SYSCALL msg=audit(1620000000.000:123): key=value ..."
AUDIT_RE = re.compile(
    r'^type=(?P<type>\S+)\s+msg=audit\((?P<epoch>[\d.]+):(?P<serial>\d+)\):\s*(?P<data>.+)$'
)

# 5. ISO Timestamp: "2025-01-15T08:00:00.000Z ..."
ISO_TS_RE = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+'
    r'(?P<rest>.+)$'
)

# 6. APT history.log: "2025-01-15 08:00:01 install python3:amd64 <none> 3.11.0-1"
APT_RE = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<action>startup|install|upgrade|remove|purge|error|status|trigproc|configure)\s+'
    r'(?P<package>\S+)(?:\s+(?P<from_ver>\S+)\s+(?P<to_ver>\S+))?'
)

# 7. YUM/DNF log: "Jan 15 08:00:01 Installed: python3-3.9.0-1.el8.x86_64"
YUM_RE = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<action>Installed|Updated|Erased|Obsoleted|Dep-Installed|Reinstalled):\s+'
    r'(?P<package>.+)$'
)

# 7b. DNF4+ log: "2025-01-15T08:00:01Z INFO Installed: python3"
DNF4_RE = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+'
    r'(?P<level>DEBUG|INFO|WARNING|ERROR)\s+'
    r'(?P<message>.+)$'
)

# 8. MySQL Error 8.x: "2025-01-15T08:00:00.000000Z 0 [Note] [MY-000000] [Server] message"
MYSQL_ERROR_8_RE = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)\s+'
    r'(?P<thread>\d+)\s+\[(?P<level>[^\]]+)\]\s+\[(?P<code>[^\]]*)\]\s+\[(?P<subsys>[^\]]*)\]\s+'
    r'(?P<message>.+)$'
)

# 8b. MySQL Error 5.7: "2025-01-15T08:00:00.000000Z Note message"
MYSQL_ERROR_57_RE = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)\s+'
    r'(?P<level>Note|Warning|Error|ERROR)\s+(?P<message>.+)$'
)

# 9. MySQL General Log: "2025-01-15T08:00:01.000000Z    12 Connect/Query  ..."
MYSQL_GENERAL_RE = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)\s+'
    r'(?P<thread_id>\d+)\s+(?P<command>Connect|Query|Quit|Init\s+DB|Field\s+List|Change\s+user|'
    r'Ping|Statistics|Debug|Refresh|Shutdown|Processlist|Kill|Create\s+DB|Drop\s+DB|Reload)\s+'
    r'(?P<message>.+)?$'
)

# 10. OpenVPN: "Thu Jan 15 08:00:01 2025 192.168.1.100:1194 message"
OPENVPN_RE = re.compile(
    r'^(?P<dow>\w{3})\s+(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<year>\d{4})\s+(?:(?P<client_ip>\d+\.\d+\.\d+\.\d+)(?::(?P<client_port>\d+))?\s+)?'
    r'(?P<message>.+)$'
)

# 11. Pipe-delimited: "timestamp|category|source|event|host|user"
PIPE_RE = re.compile(r'^[^|]+\|[^|]+\|[^|]+\|[^|]+')

# Hilfsmuster
IP_RE = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')

MONTHS = {
    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
    'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
}

# wtmp/btmp: C-struct "utmp" (Linux, 384 Bytes je Record)
# struct utmp { short ut_type; int ut_pid; char ut_line[32]; char ut_id[4];
#               char ut_user[32]; char ut_host[256]; ... struct timeval ut_tv; ... }
UTMP_STRUCT_SIZE = 384
UTMP_STRUCT_FMT  = '<hi32s4s32s256s4si2I4I20s'


# ═══════════════════════════════════════════════════════════════════════════════
# Hauptklasse
# ═══════════════════════════════════════════════════════════════════════════════

class LogParser:
    """
    Universeller Log-Parser für Linux-forensische Untersuchungen.
    Erkennt das Format automatisch und delegiert an den passenden Sub-Parser.
    """

    def __init__(self, default_year: int = None):
        self.default_year    = default_year or datetime.now().year
        self.format_detected = None

    # ─────────────────────────────────────────────────────────────────────
    # Öffentliche Hauptmethode
    # ─────────────────────────────────────────────────────────────────────

    def parse_file(self, file_path: Path) -> List[Dict]:
        """
        Liest eine Log-Datei und gibt eine Liste von Timeline-Events zurück.

        Binäre Formate (wtmp/btmp) werden direkt via parse_wtmp() behandelt.
        Journald-Dateien (.journal) werden via journalctl geöffnet.
        Alle anderen Formate werden zeilenweise geparst.
        """
        file_path = Path(file_path)

        # ── Sonderfall: Binäres wtmp/btmp ─────────────────────────────────
        if file_path.name in ('wtmp', 'btmp', 'utmpdb', 'lastlog') or \
           file_path.suffix in ('.wtmp', '.btmp'):
            self.format_detected = 'wtmp_binary'
            events = self._parse_wtmp(file_path)
            logger.info(f"wtmp/btmp: {len(events)} Login-Events aus {file_path.name}")
            return events

        # ── Sonderfall: Systemd Journal-Datei ────────────────────────────
        if file_path.suffix == '.journal':
            self.format_detected = 'journald_binary'
            events = self._parse_journal_via_journalctl(file_path)
            logger.info(f"Journal: {len(events)} Events aus {file_path.name}")
            return events

        # ── Normale Text-Dateien ──────────────────────────────────────────
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except OSError as e:
            logger.error(f"Datei nicht lesbar: {e}")
            return []

        if not lines:
            logger.warning(f"Leere Datei: {file_path.name}")
            return []

        # Format aus den ersten 20 nicht-leeren Zeilen bestimmen
        sample = [l.strip() for l in lines[:30] if l.strip()][:20]
        self.format_detected = self._detect_format(sample, file_path)
        logger.info(f"Log-Format erkannt: {self.format_detected} ({len(lines)} Zeilen)")

        events = []
        for i, line in enumerate(lines):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            event = self._parse_line(line, i + 1)
            if event:
                events.append(event)

        logger.info(f"Log-Parser: {len(events)} Events aus {file_path.name}")
        return events

    # ─────────────────────────────────────────────────────────────────────
    # Format-Erkennung
    # ─────────────────────────────────────────────────────────────────────

    def _detect_format(self, sample_lines: List[str], file_path: Path) -> str:
        """Erkennt das Log-Format aus Dateiname + Inhalt."""
        name_lower = file_path.name.lower()
        stem_lower = file_path.stem.lower()

        # ── Dateiname-basierte Erkennung ──────────────────────────────────
        if 'audit' in name_lower:
            for line in sample_lines:
                if AUDIT_RE.match(line):
                    return 'audit'
        if 'journal' in name_lower and sample_lines and sample_lines[0].startswith('{'):
            return 'journal_json'
        if 'apt' in name_lower or 'dpkg' in name_lower or stem_lower in ('history', 'dpkg'):
            for line in sample_lines:
                if APT_RE.match(line):
                    return 'apt'
        if 'yum' in name_lower or 'dnf' in name_lower:
            for line in sample_lines:
                if YUM_RE.match(line) or DNF4_RE.match(line):
                    return 'yum'
        if 'mysql' in name_lower or 'mariadb' in name_lower:
            for line in sample_lines:
                if MYSQL_ERROR_8_RE.match(line) or MYSQL_ERROR_57_RE.match(line):
                    return 'mysql_error'
                if MYSQL_GENERAL_RE.match(line):
                    return 'mysql_general'
        if 'openvpn' in name_lower:
            for line in sample_lines:
                if OPENVPN_RE.match(line):
                    return 'openvpn'
        if name_lower in ('wtmp', 'btmp', 'utmpdb'):
            return 'wtmp_binary'

        # ── Inhalts-basierte Erkennung ────────────────────────────────────
        for line in sample_lines:
            if not line:
                continue
            # JSON (journald --output=json)
            if line.startswith('{') and '"__REALTIME_TIMESTAMP"' in line:
                return 'journal_json'
            # Pipe-delimited Timeline
            if PIPE_RE.match(line) and line.count('|') >= 4:
                return 'pipe_delimited'
            # Apache Combined
            if APACHE_RE.match(line):
                return 'apache_combined'
            # Linux Audit
            if AUDIT_RE.match(line):
                return 'audit'
            # APT
            if APT_RE.match(line):
                return 'apt'
            # YUM/DNF
            if YUM_RE.match(line):
                return 'yum'
            # MySQL Error 8.x
            if MYSQL_ERROR_8_RE.match(line):
                return 'mysql_error'
            # MySQL General
            if MYSQL_GENERAL_RE.match(line):
                return 'mysql_general'
            # OpenVPN
            if OPENVPN_RE.match(line):
                return 'openvpn'
            # iptables Kernel-Log (enthält typische Felder)
            if ('SRC=' in line and 'DST=' in line and 'PROTO=' in line):
                return 'iptables'
            # Einfaches Firewall-Log
            if FIREWALL_SIMPLE_RE.match(line):
                return 'firewall_simple'
            # Syslog RFC 5424
            if SYSLOG5424_RE.match(line):
                return 'syslog'
            # Syslog RFC 3164
            if SYSLOG_RE.match(line):
                return 'syslog'
            # ISO Timestamp
            if ISO_TS_RE.match(line):
                return 'iso_timestamp'

        return 'generic'

    # ─────────────────────────────────────────────────────────────────────
    # Dispatch
    # ─────────────────────────────────────────────────────────────────────

    def _parse_line(self, line: str, line_num: int) -> Optional[Dict]:
        """Leitet eine Zeile an den passenden Sub-Parser weiter."""
        try:
            dispatch = {
                'syslog':          self._parse_syslog,
                'apache_combined': self._parse_apache,
                'pipe_delimited':  self._parse_pipe,
                'firewall_simple': self._parse_firewall_simple,
                'iptables':        self._parse_iptables,
                'audit':           self._parse_audit,
                'journal_json':    self._parse_journal_json_line,
                'apt':             self._parse_apt,
                'yum':             self._parse_yum,
                'mysql_error':     self._parse_mysql_error,
                'mysql_general':   self._parse_mysql_general,
                'openvpn':         self._parse_openvpn,
                'iso_timestamp':   self._parse_iso,
            }
            parser = dispatch.get(self.format_detected, self._parse_generic)
            return parser(line, line_num)
        except Exception as e:
            logger.debug(f"Zeile {line_num} nicht parsebar: {e}")
            return None

    # ═══════════════════════════════════════════════════════════════════════
    # 1. Syslog (RFC 3164 + RFC 5424)
    # ═══════════════════════════════════════════════════════════════════════

    def _parse_syslog(self, line: str, line_num: int) -> Optional[Dict]:
        # Versuche RFC 5424 zuerst
        m = SYSLOG5424_RE.match(line)
        if m:
            ts_str = m.group('timestamp')
            try:
                ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
            except ValueError:
                ts = datetime.now()
            message = m.group('message')
            process = m.group('process').strip()
            hostname = m.group('hostname')
            event_type = self._categorize_syslog(process, message)
            return {
                'timestamp':   ts.isoformat(),
                'event_type':  event_type,
                'source':      'syslog',
                'hostname':    hostname,
                'process':     process,
                'pid':         m.group('pid'),
                'message':     message,
                'raw_line':    line,
                'line_number': line_num,
            }

        # RFC 3164
        m = SYSLOG_RE.match(line)
        if not m:
            return self._parse_generic(line, line_num)

        month = MONTHS.get(m.group('month'), 1)
        day   = int(m.group('day'))
        time_parts = m.group('time').split(':')
        ts = datetime(
            self.default_year, month, day,
            int(time_parts[0]), int(time_parts[1]), int(time_parts[2])
        )

        message  = m.group('message')
        process  = m.group('process').strip()
        hostname = m.group('hostname')

        # Sysmon-XML in Syslog-Nachricht erkennen
        if 'sysmon' in process.lower() and '<Event>' in message:
            return self._parse_sysmon_xml(message, ts, hostname, line_num)

        event_type = self._categorize_syslog(process, message)

        return {
            'timestamp':   ts.isoformat(),
            'event_type':  event_type,
            'source':      'syslog',
            'hostname':    hostname,
            'process':     process,
            'pid':         m.group('pid'),
            'message':     message,
            'raw_line':    line,
            'line_number': line_num,
        }

    def _categorize_syslog(self, process: str, message: str) -> str:
        """Kategorisiert Syslog-Nachrichten in forensisch relevante Event-Typen."""
        proc = process.lower()
        msg  = message.lower()

        # ── SSH / Authentifizierung ───────────────────────────────────────
        if 'sshd' in proc:
            if 'accepted' in msg:
                return 'auth_success'
            if any(k in msg for k in ['failed', 'invalid user', 'invalid password',
                                       'no matching key', 'connection closed by invalid']):
                return 'auth_failure'
            if 'disconnect' in msg:
                return 'ssh_disconnect'
            if any(k in msg for k in ['publickey', 'preauth', 'connection from']):
                return 'ssh_event'
            return 'ssh_event'

        # ── Privilege Escalation ─────────────────────────────────────────
        if 'sudo' in proc:
            if 'incorrect password' in msg or 'authentication failure' in msg:
                return 'sudo_failure'
            if 'command not allowed' in msg or 'user NOT in sudoers' in msg:
                return 'sudo_denied'
            return 'privilege_escalation'

        if 'su' == proc or proc.startswith('su[') or proc.startswith('su '):
            if 'failed' in msg or 'incorrect' in msg:
                return 'auth_failure'
            return 'privilege_escalation'

        # ── Scheduled Tasks / Cron ───────────────────────────────────────
        if proc in ('cron', 'crond', 'anacron', 'atd'):
            if 'new' in msg and ('job' in msg or 'crontab' in msg):
                return 'scheduled_task_created'
            return 'scheduled_task'

        # ── Systemd Journal ──────────────────────────────────────────────
        if proc in ('systemd', 'systemd[1]'):
            if any(k in msg for k in ['started', 'stopping', 'stopped']):
                return 'service_event'
            return 'system_event'

        # ── Kernel / iptables / UFW ───────────────────────────────────────
        if 'kernel' in proc:
            if 'ufw' in msg or 'iptables' in msg or 'SRC=' in message:
                return self._classify_iptables_action(msg)
            if 'oom' in msg or 'out of memory' in msg:
                return 'system_alert'
            if 'syn flood' in msg:
                return 'network_attack'
            if 'segfault' in msg:
                return 'process_crash'
            return 'kernel_event'

        # ── Paketverwaltung ───────────────────────────────────────────────
        if proc in ('apt', 'apt-get', 'dpkg', 'yum', 'dnf', 'rpm'):
            if any(k in msg for k in ['install', 'upgrade', 'update']):
                return 'package_install'
            if any(k in msg for k in ['remove', 'purge', 'erase']):
                return 'package_remove'
            return 'package_event'

        # ── Datei-Operationen ─────────────────────────────────────────────
        if any(kw in msg for kw in ['wget ', 'curl ', '/usr/bin/curl', '/usr/bin/wget']):
            return 'file_download'

        if any(kw in msg for kw in ['chmod ', 'chown ', 'chgrp ']):
            return 'permission_change'

        if any(kw in msg for kw in ['/etc/shadow', '/etc/passwd', '/etc/sudoers',
                                     'cat /etc/', 'less /etc/', 'more /etc/']):
            return 'credential_access'

        # ── Daten-Exfiltration / Netzwerk ────────────────────────────────
        if any(kw in msg for kw in ['scp ', 'rsync ', 'sftp ', 'ftp ', 'exfil']):
            return 'data_exfiltration'

        if any(kw in msg for kw in ['nc ', 'ncat ', 'netcat', 'nmap ', 'masscan']):
            return 'network_tool'

        if any(kw in msg for kw in ['socat', 'proxychains', 'tor ', 'proxytunnel']):
            return 'c2_tool'

        # ── Anti-Forensics ────────────────────────────────────────────────
        if any(kw in msg for kw in ['history -c', 'echo "" >', 'truncate',
                                     'shred ', 'wipe ', 'srm ', 'unlink']):
            return 'anti_forensics'

        if any(kw in msg for kw in ['rm -rf /var/log', 'rm -rf /tmp',
                                     '> /var/log', 'rm /var/log']):
            return 'log_cleared'

        # ── Account-Manipulation ─────────────────────────────────────────
        if any(kw in msg for kw in ['useradd', 'adduser']):
            return 'user_created'

        if any(kw in msg for kw in ['usermod', 'passwd', 'chpasswd']):
            return 'account_modification'

        if any(kw in msg for kw in ['userdel', 'deluser']):
            return 'user_deleted'

        # ── Persistence ───────────────────────────────────────────────────
        if any(kw in msg for kw in ['authorized_keys', 'id_rsa', '.ssh/']):
            return 'ssh_key_modified'

        if any(kw in msg for kw in ['crontab -e', '/etc/cron', '/var/spool/cron']):
            return 'crontab_modified'

        if any(kw in msg for kw in ['/etc/rc.local', '/etc/init.d/', 'systemctl enable']):
            return 'persistence_mechanism'

        # ── PAM / Authentifizierungs-Subsystem ───────────────────────────
        if 'pam' in proc:
            if any(k in msg for k in ['authentication failure', 'auth could not']):
                return 'auth_failure'
            if 'session opened' in msg:
                return 'auth_success'
            if 'session closed' in msg:
                return 'session_closed'
            return 'pam_event'

        # ── Reverse Shell / C2 Indikatoren ───────────────────────────────
        if any(kw in msg for kw in ['bash -i', '/dev/tcp/', '/dev/udp/',
                                     'mkfifo', 'mknod']):
            return 'reverse_shell_attempt'

        if any(kw in msg for kw in ['base64 -d', 'base64 --decode', 'python -c',
                                     'perl -e', 'ruby -e', 'php -r']):
            return 'code_execution'

        return 'system_event'

    def _classify_iptables_action(self, msg_lower: str) -> str:
        """Klassifiziert iptables/UFW Aktionen."""
        if any(k in msg_lower for k in ['drop', 'block', 'reject', 'deny']):
            return 'firewall_drop'
        if 'allow' in msg_lower or 'accept' in msg_lower:
            return 'firewall_allow'
        return 'firewall_event'

    # ═══════════════════════════════════════════════════════════════════════
    # 2. Apache / Nginx Combined Log
    # ═══════════════════════════════════════════════════════════════════════

    def _parse_apache(self, line: str, line_num: int) -> Optional[Dict]:
        m = APACHE_RE.match(line)
        if not m:
            return self._parse_generic(line, line_num)

        ts_str = m.group('timestamp')
        try:
            ts = datetime.strptime(ts_str.split()[0], '%d/%b/%Y:%H:%M:%S')
        except ValueError:
            ts = datetime.now()

        status = int(m.group('status'))
        path   = m.group('path')
        method = m.group('method')
        src_ip = m.group('ip')

        event_type = self._categorize_web_request(path, status, method)

        return {
            'timestamp':   ts.isoformat(),
            'event_type':  event_type,
            'source':      'webserver',
            'src_ip':      src_ip,
            'user':        m.group('user') if m.group('user') != '-' else None,
            'method':      method,
            'path':        path,
            'status':      status,
            'size':        int(m.group('size')) if m.group('size') != '-' else 0,
            'message':     f"{method} {path} → {status} (von {src_ip})",
            'raw_line':    line,
            'line_number': line_num,
        }

    def _categorize_web_request(self, path: str, status: int, method: str) -> str:
        """Kategorisiert Web-Requests nach Verdächtigkeitsgrad."""
        path_lower = path.lower()

        # SQLi-Muster
        if any(p in path_lower for p in ["'", '"', ' or ', 'union+', 'union%20',
                                          'select%20', '--', '1=1', '1%3d1']):
            return 'sqli_attempt'

        # XSS-Muster
        if any(p in path_lower for p in ['<script', '%3cscript', 'onerror=',
                                          'javascript:', 'alert(']):
            return 'xss_attempt'

        # Path Traversal
        if any(p in path_lower for p in ['../', '..%2f', '%2e%2e', '..../']):
            return 'path_traversal'

        # Web Shell / Code Execution
        if any(p in path_lower for p in ['.php?', 'cmd=', 'exec=', 'system(',
                                          'passthru', 'shell.php', 'webshell']):
            return 'webshell_access'

        # Sensible Pfade
        if any(p in path_lower for p in ['/admin', '/login', '/wp-admin',
                                          '/.env', '/config', '/passwd',
                                          '/shadow', '/etc/', '/.git']):
            return 'suspicious_request'

        # Scanner-Muster (viele 404 von einer IP)
        if status == 404:
            return 'http_error'
        if status >= 500:
            return 'http_server_error'
        if status >= 400:
            return 'http_error'

        return 'http_request'

    # ═══════════════════════════════════════════════════════════════════════
    # 3. iptables (Kernel-Log)
    # ═══════════════════════════════════════════════════════════════════════

    def _parse_iptables(self, line: str, line_num: int) -> Optional[Dict]:
        """
        Parst iptables Kernel-Log-Einträge.
        Diese erscheinen normalerweise im Syslog mit:
          kernel: [timestamp] CHAIN-PREFIX: IN=eth0 SRC=... DST=... PROTO=TCP SPT=... DPT=...
        """
        # Timestamp aus Syslog-Wrapper extrahieren
        ts = datetime.now()
        syslog_m = SYSLOG_RE.match(line)
        if syslog_m:
            month = MONTHS.get(syslog_m.group('month'), 1)
            day   = int(syslog_m.group('day'))
            tp    = syslog_m.group('time').split(':')
            ts    = datetime(self.default_year, month, day,
                             int(tp[0]), int(tp[1]), int(tp[2]))
            rest  = syslog_m.group('message')
        else:
            rest = line

        ipt_m = IPTABLES_KERNEL_RE.search(rest)
        if not ipt_m:
            return self._parse_generic(line, line_num)

        prefix   = ipt_m.group('prefix') or ''
        src_ip   = ipt_m.group('src_ip') or ''
        dst_ip   = ipt_m.group('dst_ip') or ''
        proto    = ipt_m.group('proto')  or ''
        src_port = ipt_m.group('spt')    or ''
        dst_port = ipt_m.group('dpt')    or ''
        in_if    = ipt_m.group('in_if')  or ''
        out_if   = ipt_m.group('out_if') or ''

        prefix_upper = prefix.upper()
        if any(k in prefix_upper for k in ['DROP', 'REJECT', 'DENY', 'BLOCK']):
            event_type = 'firewall_drop'
        elif any(k in prefix_upper for k in ['ACCEPT', 'ALLOW']):
            event_type = 'firewall_allow'
        elif 'FORWARD' in prefix_upper:
            event_type = 'firewall_forward'
        else:
            event_type = 'firewall_event'

        return {
            'timestamp':   ts.isoformat(),
            'event_type':  event_type,
            'source':      'iptables',
            'prefix':      prefix,
            'src_ip':      src_ip,
            'dst_ip':      dst_ip,
            'protocol':    proto,
            'src_port':    src_port,
            'dst_port':    dst_port,
            'in_interface':  in_if,
            'out_interface': out_if,
            'message':     (
                f"{prefix}: {proto} {src_ip}:{src_port} → {dst_ip}:{dst_port} "
                f"(in={in_if} out={out_if})"
            ),
            'raw_line':    line,
            'line_number': line_num,
        }

    def _parse_firewall_simple(self, line: str, line_num: int) -> Optional[Dict]:
        """Parst einfaches ALLOW/BLOCK Firewall-Format."""
        m = FIREWALL_SIMPLE_RE.match(line)
        if not m:
            return self._parse_generic(line, line_num)
        action = m.group('action').lower()
        return {
            'timestamp':   m.group('timestamp').replace(' ', 'T'),
            'event_type':  f"firewall_{action}",
            'source':      'firewall',
            'action':      m.group('action'),
            'protocol':    m.group('proto'),
            'message':     f"{m.group('action')} {m.group('proto')} {m.group('rest')}",
            'raw_line':    line,
            'line_number': line_num,
        }

    # ═══════════════════════════════════════════════════════════════════════
    # 4. Linux Audit Log
    # ═══════════════════════════════════════════════════════════════════════

    def _parse_audit(self, line: str, line_num: int) -> Optional[Dict]:
        """
        Parst Linux Audit-Logs (auditd).

        Relevante Record-Typen:
        - SYSCALL    — Systemaufruf mit Prozess-Kontext (execve, open, connect, ...)
        - EXECVE     — Ausgeführter Befehl + Argumente
        - USER_AUTH  — PAM-Authentifizierung
        - USER_LOGIN — Erfolgreicher Login
        - USER_CMD   — sudo-Befehl
        - SOCKADDR   — Netzwerkverbindungen
        - PATH       — Dateizugriffe
        - CWD        — Arbeitsverzeichnis
        - PROCTITLE  — Prozessname (lesbar)
        - CONFIG_CHANGE — auditd-Konfiguration geändert
        - SERVICE_START/STOP — Systemd-Dienste
        """
        m = AUDIT_RE.match(line)
        if not m:
            return self._parse_generic(line, line_num)

        record_type = m.group('type')
        epoch_str   = m.group('epoch')
        data_str    = m.group('data')

        # Unix-Timestamp aus Audit-Format
        try:
            ts = datetime.fromtimestamp(float(epoch_str), tz=timezone.utc)
        except (ValueError, OSError):
            ts = datetime.now(tz=timezone.utc)

        # Key=Value Paare extrahieren
        kv = self._parse_audit_kv(data_str)

        event_type, message = self._categorize_audit(record_type, kv, data_str)

        return {
            'timestamp':     ts.isoformat(),
            'event_type':    event_type,
            'source':        'audit',
            'audit_type':    record_type,
            'audit_serial':  m.group('serial'),
            'pid':           kv.get('pid'),
            'uid':           kv.get('uid'),
            'auid':          kv.get('auid'),      # Audit-UID (Original-Nutzer bei su/sudo)
            'euid':          kv.get('euid'),
            'user':          kv.get('acct') or kv.get('daddr'),
            'exe':           kv.get('exe', '').strip('"'),
            'comm':          kv.get('comm', '').strip('"'),
            'key':           kv.get('key', '').strip('"'),
            'syscall':       kv.get('syscall'),
            'result':        kv.get('res') or kv.get('success'),
            'message':       message,
            'metadata':      kv,
            'raw_line':      line,
            'line_number':   line_num,
        }

    def _parse_audit_kv(self, data_str: str) -> Dict[str, str]:
        """Extrahiert Key=Value-Paare aus Audit-Zeilen (inkl. Anführungszeichen)."""
        kv = {}
        # Paare mit Anführungszeichen: key="wert mit leerzeichen"
        for m in re.finditer(r'(\w+)="([^"]*)"', data_str):
            kv[m.group(1)] = m.group(2)
        # Einfache Paare: key=wert
        for m in re.finditer(r'(\w+)=(\S+)', data_str):
            if m.group(1) not in kv:
                kv[m.group(1)] = m.group(2)
        return kv

    def _categorize_audit(self, record_type: str, kv: Dict, data_str: str) -> Tuple[str, str]:
        """Bestimmt Event-Typ und Beschreibung für einen Audit-Record."""
        exe  = kv.get('exe', '').strip('"').lower()
        key  = kv.get('key', '').strip('"').lower()
        comm = kv.get('comm', '').strip('"').lower()
        uid  = kv.get('uid', '?')
        res  = kv.get('res') or kv.get('success', '')
        acct = kv.get('acct', '').strip('"')

        # ── Record-Typ-basierte Kategorisierung ───────────────────────────
        if record_type == 'SYSCALL':
            syscall = kv.get('syscall', '')
            # Bekannte kritische Syscalls
            critical_syscalls = {
                '59':  ('code_execution',    'execve() aufgerufen'),
                '322': ('code_execution',    'execveat() aufgerufen'),
                '41':  ('network_activity',  'socket() erstellt'),
                '42':  ('network_activity',  'connect() aufgerufen'),
                '43':  ('network_activity',  'accept() aufgerufen'),
                '105': ('privilege_change',  'setuid() aufgerufen'),
                '117': ('privilege_change',  'setresuid() aufgerufen'),
                '2':   ('file_access',       'open() aufgerufen'),
                '257': ('file_access',       'openat() aufgerufen'),
                '87':  ('file_deleted',      'unlink() aufgerufen'),
                '263': ('file_deleted',      'unlinkat() aufgerufen'),
                '82':  ('file_modified',     'rename() aufgerufen'),
                '90':  ('permission_change', 'chmod() aufgerufen'),
                '92':  ('permission_change', 'chown() aufgerufen'),
                '161': ('permission_change', 'chroot() aufgerufen'),
            }
            et, desc = critical_syscalls.get(syscall, ('system_call', f'Syscall {syscall}'))

            # Zusätzliche Keyword-Checks aus exe/comm
            if any(k in exe for k in ['nmap', 'masscan', 'ncat', 'nc ']):
                et = 'network_tool'
            elif any(k in exe for k in ['wget', 'curl']):
                et = 'file_download'
            elif any(k in exe for k in ['scp', 'rsync', 'sftp']):
                et = 'data_exfiltration'
            elif any(k in exe for k in ['sudo', 'su ']):
                et = 'privilege_escalation'

            return et, f"SYSCALL {syscall} von {exe or comm} (uid={uid})"

        elif record_type == 'EXECVE':
            # Befehlsargumente sammeln
            args = []
            for i in range(int(kv.get('argc', '0') or 0)):
                arg = kv.get(f'a{i}', '').strip('"')
                args.append(arg)
            cmd_str = ' '.join(args) if args else data_str

            # Gefährliche Befehle erkennen
            cmd_lower = cmd_str.lower()
            if any(k in cmd_lower for k in ['/bin/bash -i', '/dev/tcp', '/dev/udp',
                                             'python -c', 'perl -e', 'ruby -e']):
                return 'reverse_shell_attempt', f"Reverse Shell: {cmd_str[:100]}"
            if any(k in cmd_lower for k in ['base64 -d', 'base64 --decode']):
                return 'code_execution', f"Base64-Decode Ausführung: {cmd_str[:100]}"
            if any(k in cmd_lower for k in ['history -c', 'rm /var/log', 'shred ']):
                return 'anti_forensics', f"Anti-Forensics: {cmd_str[:100]}"
            if any(k in cmd_lower for k in ['useradd', 'adduser', 'usermod']):
                return 'account_modification', f"Account-Änderung: {cmd_str[:100]}"
            if any(k in cmd_lower for k in ['crontab', 'at ', 'systemctl enable']):
                return 'persistence_mechanism', f"Persistenz: {cmd_str[:100]}"

            return 'code_execution', f"EXECVE: {cmd_str[:150]}"

        elif record_type in ('USER_AUTH', 'USER_ACCT'):
            success = 'success' in res.lower() or res.lower() == 'yes'
            et = 'auth_success' if success else 'auth_failure'
            op = kv.get('op', 'auth').strip('"')
            return et, f"PAM {op}: Nutzer '{acct}' — {res}"

        elif record_type == 'USER_LOGIN':
            return 'auth_success', f"Login: Nutzer '{acct}' (uid={uid})"

        elif record_type == 'USER_LOGOUT':
            return 'session_closed', f"Logout: Nutzer '{acct}' (uid={uid})"

        elif record_type == 'USER_CMD':
            cmd = kv.get('cmd', '').strip('"')
            return 'privilege_escalation', f"sudo: '{cmd}' als uid={kv.get('euid', '?')}"

        elif record_type == 'SOCKADDR':
            # Netzwerkadresse aus Audit (laddr=, faddr=)
            saddr = kv.get('saddr', '')
            return 'network_activity', f"Netzwerk-Verbindung: {saddr}"

        elif record_type == 'PATH':
            name = kv.get('name', '').strip('"')
            nametype = kv.get('nametype', '')
            if '/etc/shadow' in name or '/etc/passwd' in name:
                return 'credential_access', f"Zugriff auf '{name}' ({nametype})"
            if '/var/log' in name and 'DELETE' in nametype.upper():
                return 'log_cleared', f"Log-Datei gelöscht: '{name}'"
            if '.ssh' in name:
                return 'ssh_key_modified', f"SSH-Datei: '{name}' ({nametype})"
            return 'file_access', f"Dateizugriff: '{name}' ({nametype})"

        elif record_type == 'CONFIG_CHANGE':
            return 'audit_config_change', f"Audit-Konfiguration geändert"

        elif record_type in ('SERVICE_START', 'SERVICE_STOP'):
            svc = kv.get('unit', kv.get('service', '?')).strip('"')
            action = 'gestartet' if 'START' in record_type else 'gestoppt'
            return 'service_event', f"Dienst '{svc}' {action}"

        elif record_type == 'PROCTITLE':
            title = kv.get('proctitle', '').strip('"')
            return 'process_event', f"Prozess: {title}"

        return 'audit_event', f"Audit [{record_type}]: {data_str[:120]}"

    # ═══════════════════════════════════════════════════════════════════════
    # 5. Systemd Journal (JSON-Export + Binär via journalctl)
    # ═══════════════════════════════════════════════════════════════════════

    def _parse_journal_json_line(self, line: str, line_num: int) -> Optional[Dict]:
        """Parst eine einzelne JSON-Zeile aus 'journalctl --output=json'."""
        if not line.startswith('{'):
            return None
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            return None

        # Timestamp aus __REALTIME_TIMESTAMP (Mikrosekunden seit Epoch)
        ts_us = entry.get('__REALTIME_TIMESTAMP')
        if ts_us:
            try:
                ts = datetime.fromtimestamp(int(ts_us) / 1_000_000, tz=timezone.utc)
            except (ValueError, OSError):
                ts = datetime.now(tz=timezone.utc)
        else:
            ts = datetime.now(tz=timezone.utc)

        message   = entry.get('MESSAGE', '')
        unit      = entry.get('_SYSTEMD_UNIT', entry.get('UNIT', ''))
        hostname  = entry.get('_HOSTNAME', '')
        comm      = entry.get('_COMM', '')
        pid       = entry.get('_PID', '')
        uid       = entry.get('_UID', '')
        priority  = entry.get('PRIORITY', '')

        # Kategorisierung wie Syslog
        event_type = self._categorize_syslog(comm or unit, message)

        # Schweregrad-Override bei kritischen Prioritäten (0=emerg, 1=alert, 2=crit, 3=err)
        if priority in ('0', '1', '2'):
            if event_type == 'system_event':
                event_type = 'system_alert'

        return {
            'timestamp':   ts.isoformat(),
            'event_type':  event_type,
            'source':      'journal',
            'hostname':    hostname,
            'process':     comm,
            'unit':        unit,
            'pid':         pid,
            'uid':         uid,
            'priority':    priority,
            'message':     message if isinstance(message, str) else str(message),
            'raw_line':    line[:200],  # Kürzen für Übersichtlichkeit
            'line_number': line_num,
        }

    def _parse_journal_via_journalctl(self, journal_path: Path) -> List[Dict]:
        """
        Liest eine binäre .journal-Datei via 'journalctl --file --output=json'.
        Benötigt journalctl (im System verfügbar).
        """
        events = []
        try:
            result = subprocess.run(
                ['journalctl', '--file', str(journal_path), '--output=json', '--no-pager'],
                capture_output=True, text=True, timeout=120
            )
            for i, line in enumerate(result.stdout.splitlines()):
                line = line.strip()
                if line:
                    event = self._parse_journal_json_line(line, i + 1)
                    if event:
                        events.append(event)
        except FileNotFoundError:
            logger.warning("journalctl nicht gefunden — Journal kann nicht gelesen werden.")
        except subprocess.TimeoutExpired:
            logger.error("journalctl Timeout nach 120s.")
        except Exception as e:
            logger.error(f"Journal-Fehler: {e}")
        return events

    # ═══════════════════════════════════════════════════════════════════════
    # 6. APT / dpkg Log
    # ═══════════════════════════════════════════════════════════════════════

    def _parse_apt(self, line: str, line_num: int) -> Optional[Dict]:
        """
        Parst APT-History-Log und dpkg.log.

        Beispiele:
          2025-01-15 08:00:01 install python3:amd64 <none> 3.11.0-1
          2025-01-15 08:00:02 upgrade libssl3:amd64 3.0.0-1 3.0.1-1
          2025-01-15 08:00:03 startup packages configure
        """
        m = APT_RE.match(line)
        if not m:
            return self._parse_generic(line, line_num)

        action  = m.group('action').lower()
        package = m.group('package')
        from_v  = m.group('from_ver') or ''
        to_v    = m.group('to_ver')   or ''

        # Verdächtige Pakete markieren
        suspicious_pkgs = [
            'netcat', 'ncat', 'nmap', 'masscan', 'hydra', 'john',
            'aircrack', 'metasploit', 'beef', 'setoolkit', 'sqlmap',
            'recon-ng', 'maltego', 'burpsuite', 'wireshark', 'tcpdump',
            'mimikatz', 'hashcat', 'ophcrack', 'nikto', 'dirb',
            'gobuster', 'ffuf', 'wfuzz',
        ]
        pkg_lower = package.lower()
        event_type = 'package_install' if action in ('install', 'upgrade') else 'package_event'
        if action in ('install', 'upgrade') and any(s in pkg_lower for s in suspicious_pkgs):
            event_type = 'suspicious_tool_installed'

        if action in ('remove', 'purge'):
            event_type = 'package_remove'

        msg = f"APT {action}: {package}"
        if from_v and to_v:
            msg += f" ({from_v} → {to_v})"
        elif to_v:
            msg += f" → {to_v}"

        return {
            'timestamp':   m.group('timestamp').replace(' ', 'T'),
            'event_type':  event_type,
            'source':      'apt',
            'action':      action,
            'package':     package,
            'from_version': from_v,
            'to_version':   to_v,
            'message':     msg,
            'raw_line':    line,
            'line_number': line_num,
        }

    # ═══════════════════════════════════════════════════════════════════════
    # 7. YUM / DNF Log
    # ═══════════════════════════════════════════════════════════════════════

    def _parse_yum(self, line: str, line_num: int) -> Optional[Dict]:
        """
        Parst YUM- und DNF-Logs (RHEL, CentOS, Fedora, Rocky Linux).

        YUM-Format:  "Jan 15 08:00:01 Installed: python3-3.9.0"
        DNF4-Format: "2025-01-15T08:00:01Z INFO Installed: python3"
        """
        # DNF4-Format versuchen
        m4 = DNF4_RE.match(line)
        if m4:
            ts_str = m4.group('timestamp')
            try:
                ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
            except ValueError:
                ts = datetime.now()
            msg = m4.group('message')
            action_match = re.match(r'(Installed|Updated|Erased|Removed):\s+(.+)', msg)
            if action_match:
                action  = action_match.group(1)
                package = action_match.group(2)
            else:
                action  = 'log_entry'
                package = msg

            event_type = 'package_install' if action in ('Installed', 'Updated') else 'package_event'
            return {
                'timestamp':   ts.isoformat(),
                'event_type':  event_type,
                'source':      'dnf',
                'action':      action,
                'package':     package,
                'message':     f"DNF {action}: {package}",
                'raw_line':    line,
                'line_number': line_num,
            }

        # Klassisches YUM-Format
        m = YUM_RE.match(line)
        if not m:
            return self._parse_generic(line, line_num)

        month = MONTHS.get(m.group('month'), 1)
        day   = int(m.group('day'))
        tp    = m.group('time').split(':')
        ts    = datetime(self.default_year, month, day,
                         int(tp[0]), int(tp[1]), int(tp[2]))

        action  = m.group('action')
        package = m.group('package').strip()
        event_type = 'package_install' if action in ('Installed', 'Updated', 'Dep-Installed') \
                     else 'package_remove'

        return {
            'timestamp':   ts.isoformat(),
            'event_type':  event_type,
            'source':      'yum',
            'action':      action,
            'package':     package,
            'message':     f"YUM {action}: {package}",
            'raw_line':    line,
            'line_number': line_num,
        }

    # ═══════════════════════════════════════════════════════════════════════
    # 8. wtmp / btmp (Binäres Login-Journal)
    # ═══════════════════════════════════════════════════════════════════════

    def _parse_wtmp(self, file_path: Path) -> List[Dict]:
        """
        Liest wtmp / btmp / utmpdb Binär-Dateien.

        Die Datei besteht aus fixen 384-Byte-Records im C-struct-Format:
            struct utmp {
                short  ut_type;       // Typ (USER_PROCESS=7, DEAD_PROCESS=8, ...)
                int    ut_pid;
                char   ut_line[32];   // Terminal (z.B. pts/0)
                char   ut_id[4];
                char   ut_user[32];   // Benutzername
                char   ut_host[256];  // Hostname / IP
                ...
                struct timeval ut_tv; // Timestamp (sec + usec)
                ...
            }

        Quellen:
        - /var/log/wtmp   — erfolgreiche Logins
        - /var/log/btmp   — fehlgeschlagene Login-Versuche
        - /var/log/utmpdb — Solaris-Variante
        - /run/utmp       — aktuelle Sessions
        """
        events = []
        UT_TYPES = {
            0: 'EMPTY',
            1: 'RUN_LVL',
            2: 'BOOT_TIME',
            5: 'INIT_PROCESS',
            6: 'LOGIN_PROCESS',
            7: 'USER_PROCESS',     # Normaler Login
            8: 'DEAD_PROCESS',     # Logout
        }
        is_btmp = 'btmp' in file_path.name.lower()

        try:
            data = file_path.read_bytes()
        except OSError as e:
            logger.error(f"wtmp/btmp nicht lesbar: {e}")
            return []

        offset = 0
        record_count = 0

        while offset + UTMP_STRUCT_SIZE <= len(data):
            try:
                record = struct.unpack_from(UTMP_STRUCT_FMT, data, offset)
                offset += UTMP_STRUCT_SIZE
                record_count += 1

                ut_type = record[0]
                ut_pid  = record[1]
                ut_line = record[2].split(b'\x00')[0].decode('utf-8', 'replace').strip()
                ut_user = record[4].split(b'\x00')[0].decode('utf-8', 'replace').strip()
                ut_host = record[5].split(b'\x00')[0].decode('utf-8', 'replace').strip()
                tv_sec  = record[9]   # Sekunden (ut_tv.tv_sec)

                # Uninteressante Record-Typen überspringen
                if ut_type not in (2, 7, 8) or not ut_user:
                    continue

                try:
                    ts = datetime.fromtimestamp(tv_sec, tz=timezone.utc)
                except (OSError, OverflowError, ValueError):
                    continue

                type_name = UT_TYPES.get(ut_type, f'TYPE_{ut_type}')

                if is_btmp:
                    event_type = 'auth_failure'
                    message    = f"Fehlgeschlagener Login: {ut_user} von {ut_host or ut_line}"
                elif ut_type == 7:
                    event_type = 'auth_success'
                    message    = f"Login: {ut_user} auf {ut_line} von '{ut_host}'"
                elif ut_type == 8:
                    event_type = 'session_closed'
                    message    = f"Logout: {ut_user} (pid={ut_pid})"
                elif ut_type == 2:
                    event_type = 'system_boot'
                    message    = f"System-Boot (Reboot)"
                else:
                    event_type = 'login_event'
                    message    = f"{type_name}: {ut_user}"

                # Quell-IP aus ut_host extrahieren (falls IP-Format)
                src_ip = ut_host if IP_RE.match(ut_host) else None

                events.append({
                    'timestamp':   ts.isoformat(),
                    'event_type':  event_type,
                    'source':      'btmp' if is_btmp else 'wtmp',
                    'user':        ut_user,
                    'terminal':    ut_line,
                    'hostname':    ut_host,
                    'src_ip':      src_ip,
                    'pid':         str(ut_pid),
                    'utmp_type':   type_name,
                    'message':     message,
                    'raw_line':    f"[wtmp record #{record_count}]",
                    'line_number': record_count,
                })

            except struct.error:
                break

        logger.info(f"wtmp/btmp: {len(events)} relevante Records aus {record_count} gelesen")
        return events

    # ═══════════════════════════════════════════════════════════════════════
    # 9. MySQL Error Log
    # ═══════════════════════════════════════════════════════════════════════

    def _parse_mysql_error(self, line: str, line_num: int) -> Optional[Dict]:
        """
        Parst MySQL/MariaDB Error Log.

        MySQL 8.x:   "2025-01-15T08:00:00Z 0 [Warning] [MY-010055] [Server] message"
        MySQL 5.7:   "2025-01-15T08:00:00Z Warning message"
        MariaDB:     "2025-01-15 08:00:00 0 [Warning] message"
        """
        # MySQL 8.x
        m = MYSQL_ERROR_8_RE.match(line)
        if m:
            level   = m.group('level').lower()
            message = m.group('message')
            event_type = self._categorize_mysql_error(level, message)
            return {
                'timestamp':   m.group('timestamp'),
                'event_type':  event_type,
                'source':      'mysql_error',
                'level':       level,
                'error_code':  m.group('code'),
                'subsystem':   m.group('subsys'),
                'message':     message,
                'raw_line':    line,
                'line_number': line_num,
            }

        # MySQL 5.7 / MariaDB
        m = MYSQL_ERROR_57_RE.match(line)
        if m:
            level   = m.group('level').lower()
            message = m.group('message')
            event_type = self._categorize_mysql_error(level, message)
            return {
                'timestamp':   m.group('timestamp'),
                'event_type':  event_type,
                'source':      'mysql_error',
                'level':       level,
                'message':     message,
                'raw_line':    line,
                'line_number': line_num,
            }

        return self._parse_generic(line, line_num)

    def _categorize_mysql_error(self, level: str, message: str) -> str:
        """Kategorisiert MySQL-Error-Log-Einträge."""
        msg_lower = message.lower()
        if "access denied" in msg_lower:
            return 'auth_failure'
        if any(k in msg_lower for k in ['aborted connection', 'got an error']):
            return 'db_connection_error'
        if 'could not be resolved' in msg_lower:
            return 'dns_lookup_failure'
        if any(k in msg_lower for k in ['table is full', 'disk full', 'no space']):
            return 'system_alert'
        if level in ('error', 'err'):
            return 'db_error'
        if level == 'warning':
            return 'db_warning'
        return 'db_event'

    # ═══════════════════════════════════════════════════════════════════════
    # 10. MySQL General Log
    # ═══════════════════════════════════════════════════════════════════════

    def _parse_mysql_general(self, line: str, line_num: int) -> Optional[Dict]:
        """
        Parst MySQL/MariaDB General Query Log.
        Enthält alle Verbindungen + Queries → wichtig für SQLi-Erkennung.
        """
        m = MYSQL_GENERAL_RE.match(line)
        if not m:
            return self._parse_generic(line, line_num)

        command = m.group('command').strip()
        message = (m.group('message') or '').strip()

        event_type = 'db_query'
        if command == 'Connect':
            event_type = 'db_connect'
        elif command == 'Quit':
            event_type = 'db_disconnect'

        # SQLi-Erkennung in Query-Text
        if command == 'Query':
            query_lower = message.lower()
            if any(k in query_lower for k in ["' or ", "' and ", "1=1", "1='1",
                                               "drop table", "union select",
                                               "information_schema", "sleep(",
                                               "benchmark(", "load_file"]):
                event_type = 'sqli_attempt'
            elif any(k in query_lower for k in ['select * from users', 'select password',
                                                 'select user', 'from mysql.user']):
                event_type = 'credential_access'

        return {
            'timestamp':   m.group('timestamp'),
            'event_type':  event_type,
            'source':      'mysql_general',
            'thread_id':   m.group('thread_id'),
            'db_command':  command,
            'message':     f"MySQL [{command}]: {message[:200]}",
            'raw_line':    line,
            'line_number': line_num,
        }

    # ═══════════════════════════════════════════════════════════════════════
    # 11. OpenVPN Log
    # ═══════════════════════════════════════════════════════════════════════

    def _parse_openvpn(self, line: str, line_num: int) -> Optional[Dict]:
        """
        Parst OpenVPN-Server-Logs.

        Relevante Events:
        - Client-Verbindungsaufbau / TLS-Handshake
        - Erfolgreicher VPN-Tunnel
        - Client-Trennung
        - Authentifizierungsfehler
        - IP-Zuweisungen (wichtig für Täterinfrastruktur-Analyse)
        """
        m = OPENVPN_RE.match(line)
        if not m:
            return self._parse_generic(line, line_num)

        month  = MONTHS.get(m.group('month'), 1)
        day    = int(m.group('day'))
        year   = int(m.group('year'))
        tp     = m.group('time').split(':')
        ts     = datetime(year, month, day, int(tp[0]), int(tp[1]), int(tp[2]))

        client_ip = m.group('client_ip') or ''
        message   = m.group('message')
        msg_lower = message.lower()

        # Event-Typ-Bestimmung
        if any(k in msg_lower for k in ['peer connection initiated',
                                         'client connected',
                                         'tls: initial packet from']):
            event_type = 'vpn_connection'
        elif any(k in msg_lower for k in ['peer connection closed',
                                           'connection reset',
                                           'client-instance exiting',
                                           'connection shutdown']):
            event_type = 'vpn_disconnect'
        elif 'auth_failed' in msg_lower or 'authentication failed' in msg_lower:
            event_type = 'auth_failure'
        elif any(k in msg_lower for k in ['tls error', 'tls_error',
                                           'cannot load certificate']):
            event_type = 'vpn_tls_error'
        elif any(k in msg_lower for k in ['ifconfig', 'pushed', 'ip pool']):
            event_type = 'vpn_ip_assigned'
        else:
            event_type = 'vpn_event'

        return {
            'timestamp':   ts.isoformat(),
            'event_type':  event_type,
            'source':      'openvpn',
            'client_ip':   client_ip,
            'src_ip':      client_ip,
            'client_port': m.group('client_port') or '',
            'message':     message,
            'raw_line':    line,
            'line_number': line_num,
        }

    # ═══════════════════════════════════════════════════════════════════════
    # 12. sysmon for Linux (XML in Syslog)
    # ═══════════════════════════════════════════════════════════════════════

    def _parse_sysmon_xml(self, xml_str: str, ts: datetime, hostname: str,
                           line_num: int) -> Optional[Dict]:
        """
        Parst Sysmon for Linux XML-Events (Sysinternals).
        Sysmon schreibt Events als XML-Strings in den Syslog.

        Relevante Event-IDs:
        1  — ProcessCreate
        3  — NetworkConnect
        5  — ProcessTerminate
        8  — CreateRemoteThread
        11 — FileCreate
        22 — DNSEvent
        23 — FileDelete
        """
        try:
            import xml.etree.ElementTree as ET
            # Sysmon-XML kann <Event>...</Event> enthalten
            if not xml_str.strip().startswith('<'):
                return None
            root = ET.fromstring(xml_str)

            # Namespace-agnostisches Parsen
            def find_text(tag):
                for elem in root.iter():
                    if elem.tag.endswith(tag):
                        return elem.text or ''
                    for child in elem:
                        if child.get('Name') == tag:
                            return child.text or ''
                return ''

            event_id    = find_text('EventID') or find_text('ID')
            image       = find_text('Image')
            cmd_line    = find_text('CommandLine')
            parent_img  = find_text('ParentImage')
            dst_ip      = find_text('DestinationIp')
            dst_port    = find_text('DestinationPort')
            query_name  = find_text('QueryName')
            target_file = find_text('TargetFilename')
            user        = find_text('User')

            eid = int(event_id) if event_id.isdigit() else 0

            SYSMON_EVENT_TYPES = {
                1:  ('process_create',      f"Prozess erstellt: {image} '{cmd_line[:80]}'"),
                3:  ('network_connect',     f"Netzwerk: {image} → {dst_ip}:{dst_port}"),
                5:  ('process_terminate',   f"Prozess beendet: {image}"),
                8:  ('remote_thread_create',f"Remote-Thread in {image} erstellt (von {parent_img})"),
                11: ('file_create',         f"Datei erstellt: {target_file}"),
                22: ('dns_query',           f"DNS: {image} fragt '{query_name}'"),
                23: ('file_delete',         f"Datei gelöscht: {target_file}"),
            }

            event_type, message = SYSMON_EVENT_TYPES.get(eid, ('sysmon_event', f"Sysmon EventID={eid}"))

            # Zusätzliche Kategorisierung für Täterinfrastruktur
            if eid == 3 and dst_port in ('4444', '4443', '8080', '443', '80'):
                if image and any(s in image.lower() for s in ['bash', 'sh', 'python', 'perl']):
                    event_type = 'c2_beacon'
                    message    = f"Möglicher C2-Beacon: {image} → {dst_ip}:{dst_port}"

            if eid == 1 and any(s in (cmd_line or '').lower() for s in
                                ['/dev/tcp', 'bash -i', 'nc -e', 'mkfifo']):
                event_type = 'reverse_shell_attempt'
                message    = f"Reverse Shell: {cmd_line[:100]}"

            return {
                'timestamp':     ts.isoformat(),
                'event_type':    event_type,
                'source':        'sysmon',
                'hostname':      hostname,
                'sysmon_event_id': str(eid),
                'image':         image,
                'cmd_line':      cmd_line,
                'user':          user,
                'dst_ip':        dst_ip,
                'dst_port':      dst_port,
                'message':       message,
                'raw_line':      xml_str[:200],
                'line_number':   line_num,
            }
        except Exception as e:
            logger.debug(f"Sysmon-XML Parse-Fehler: {e}")
            return None

    # ═══════════════════════════════════════════════════════════════════════
    # 13–15. Fallback-Parser
    # ═══════════════════════════════════════════════════════════════════════

    def _parse_pipe(self, line: str, line_num: int) -> Optional[Dict]:
        """Parst Pipe-delimited Timeline-Format."""
        parts = line.split('|')
        if len(parts) < 4:
            return self._parse_generic(line, line_num)
        return {
            'timestamp':   parts[0].strip(),
            'event_type':  parts[1].strip().lower() if len(parts) > 1 else 'unknown',
            'source':      parts[2].strip() if len(parts) > 2 else 'unknown',
            'message':     parts[3].strip() if len(parts) > 3 else line,
            'hostname':    parts[4].strip() if len(parts) > 4 else None,
            'user':        parts[5].strip() if len(parts) > 5 else None,
            'raw_line':    line,
            'line_number': line_num,
        }

    def _parse_iso(self, line: str, line_num: int) -> Optional[Dict]:
        """Parst Zeilen mit ISO-Timestamp + Key=Value (Windows Event Log Text)."""
        m = ISO_TS_RE.match(line)
        if not m:
            return self._parse_generic(line, line_num)

        rest    = m.group('rest')
        kv_pairs = dict(re.findall(r'(\w+)=(\S+)', rest))

        event_type = 'log_entry'
        if 'EventID' in kv_pairs:
            eid = kv_pairs['EventID']
            event_type = f"windows_event_{eid}"

        return {
            'timestamp':   m.group('timestamp'),
            'event_type':  event_type,
            'source':      'event_log',
            'message':     rest,
            'metadata':    kv_pairs,
            'raw_line':    line,
            'line_number': line_num,
        }

    def _parse_generic(self, line: str, line_num: int) -> Optional[Dict]:
        """Letzter Fallback-Parser für unbekannte Formate."""
        if not line or len(line) < 5:
            return None
        return {
            'timestamp':   datetime.now().isoformat(),
            'event_type':  'log_entry',
            'source':      'text_log',
            'message':     line,
            'raw_line':    line,
            'line_number': line_num,
        }
