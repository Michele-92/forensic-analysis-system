"""
================================================================================
ANTI-FORENSICS CHECKER — Erkennung von Manipulations- und Verschleierungsindizien
================================================================================
Prüft die normalisierte Timeline und extrahierte Artefakte auf Hinweise, dass
ein Angreifer versucht hat, forensische Spuren zu verwischen oder die Analyse
zu erschweren. Der Checker deckt neun eigenständige Prüfkategorien ab.

Aufgaben (neun Checks in sequenzieller Reihenfolge):
    1. Timestomping       — mtime liegt > 24h vor ctime (Zeitstempel-Manipulation)
    2. Log-Lücken         — unerwartet große Pausen (> 6h) in kontinuierlichen Logs
    3. Timestamp-Cluster  — ≥ 20 Dateien mit exakt gleichem Sekundentimestamp
    4. Wipe-Tools         — shred, wipe, srm, dd if=/dev/zero u.a. in Events
    5. Log-Löschung       — truncate, history -c, journalctl --vacuum in Logs
    6. Systemzeit-Änderung— settimeofday, timedatectl, hwclock in Events
    7. Rootkit-Indikatoren— LD_PRELOAD, insmod aus /tmp, /proc-Zugriffe
    8. Truncated Logs     — Dateien unter /var/log mit Größe 0
    9. Lösch-Operationen  — rm -rf auf forensisch relevante Pfade

Checks 1–3 werden nur bei ≥ MIN_EVENTS_FOR_STATS (20) Events ausgeführt,
da sie statistische Auswertungen benötigen.

Ausgabe von check():
    {
      'findings':       [{'category', 'severity', 'description', 'evidence', 'mitre'}, ...],
      'stats':          {'timestomp_checked': N, 'log_gaps_found': M, ...},
      'risk_score':     0–100,
      'risk_level':     'none' | 'low' | 'medium' | 'high' | 'critical',
      'total_checks':   9,
      'findings_count': N,
      'summary':        'lesbarer Zusammenfassungstext',
    }

Verwendung:
    checker = AntiForensicsChecker()
    result  = checker.check(timeline=events, artifacts=arts, system_profile=prof)
    if result['risk_level'] in ('high', 'critical'):
        # Findings manuell prüfen oder LLM-Agenten damit anreichern

Pipeline-Position:
    Stage 5c — nach SystemProfiler (Stage 5b), vor AnomalyDetector (Stage 6).

Wichtige Konstanten (am Dateianfang, leicht anpassbar):
    WIPE_TOOLS:                 Bekannte Datei-Wipe-Tool-Namen
    DD_WIPE_RE:                 Regex für dd-basierte Wipe-Kommandos
    TIMESTOMP_TOOLS:            Zeitstempel-Manipulations-Tools
    TIMESET_TOOLS:              Systemzeit-Änderungs-Tools
    LOG_CLEAR_PATTERNS:         Regex-Liste für Log-/History-Löschung
    ROOTKIT_PATTERNS:           Regex-Liste für Rootkit-Indikatoren
    LOG_GAP_THRESHOLD_HOURS:    Schwellwert für Log-Lücken (Standard: 6h)
    TIMESTOMP_DELTA_THRESHOLD:  mtime-ctime-Differenz in Sekunden (Standard: 86400 = 24h)
    MIN_EVENTS_FOR_STATS:       Mindest-Event-Anzahl für statistische Checks (Standard: 20)

Abhängigkeiten:
    - re, logging, datetime, pathlib, typing (alle stdlib)

Kontext: LFX Forensic Analysis System — backend/pipeline.py
"""

import re
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional

logger = logging.getLogger(__name__)


# ── Konstanten / Bekannte Tool-Muster ─────────────────────────────────────────

# Shell-Befehle / Prozesse die auf sicheres Loeschen hinweisen
WIPE_TOOLS = {
    'shred', 'wipe', 'srm', 'sdelete', 'bleachbit', 'eraser',
    'secure-delete', 'nwipe', 'dban', 'dcfldd',
}

# dd-Muster: dd if=/dev/zero, dd if=/dev/urandom
DD_WIPE_RE = re.compile(
    r'\bdd\b.*\bif=/dev/(zero|urandom|null)\b', re.IGNORECASE
)

# Zeitstempel-Tools
TIMESTOMP_TOOLS = {
    'touch', 'timestomp', 'metasploit', 'meterpreter',
    'setattr', 'utouchd',
}

# Systemzeit-Manipulation
TIMESET_TOOLS = {
    'settimeofday', 'adjtimex', 'timedatectl', 'ntpdate',
    'hwclock', 'date',
}

# Logloeschung / -truncation
LOG_CLEAR_PATTERNS = [
    re.compile(r'\b(truncate|>\s*/var/log|cat /dev/null\s*>)\b', re.IGNORECASE),
    re.compile(r'\b(logrotate|journalctl\s+--rotate|journalctl\s+--vacuum)\b', re.IGNORECASE),
    re.compile(r'\b(history\s+-c|unset HISTFILE|HISTSIZE=0)\b', re.IGNORECASE),
]

# Rootkit / Kernel-Modul-Verdacht
ROOTKIT_PATTERNS = [
    re.compile(r'\b(insmod|modprobe|rmmod)\b.+(/tmp/|/dev/shm/|/var/tmp/)', re.IGNORECASE),
    re.compile(r'/proc/(kallsyms|kcore|kmem)\b', re.IGNORECASE),
    re.compile(r'\bLD_PRELOAD\b', re.IGNORECASE),
    re.compile(r'\b(hide|hidden|stealth|invisible)\b', re.IGNORECASE),
]

# Verdächtige /var/log Pfade für Truncation-Check
VAR_LOG_RE = re.compile(r'^/var/log/.+$')

# Max. akzeptable Zeitluecke in Stunden fuer kontinuierliche Logs
LOG_GAP_THRESHOLD_HOURS = 6

# Timestomp-Schwelle: Zeitunterschied zwischen mtime und ctime in Sekunden
# (mtime < ctime mit grossem Abstand ist verdaechtig)
TIMESTOMP_DELTA_THRESHOLD = 86400  # 24 Stunden

# Minimum Events fuer statistische Auswertung
MIN_EVENTS_FOR_STATS = 20


class AntiForensicsChecker:
    """
    Erkennt Hinweise auf Anti-Forensics-Aktivitaeten in der Timeline.

    Die Klasse führt neun thematisch getrennte Checks durch und sammelt alle
    Findings in einer einheitlichen Struktur. Der abschließende Risiko-Score
    (0–100) gewichtet high-Findings mit 20, medium mit 10 und low mit 5 Punkten.

    Jedes Finding hat folgende Felder:
      - category:    Kurzname der Kategorie (timestomping, log_gap, wiping, ...)
      - severity:    'high' | 'medium' | 'low'
      - description: Lesbare Beschreibung mit Anzahl der Treffer
      - evidence:    Liste konkreter Belege (Pfade, Timestamps, Kommandos)
      - mitre:       Zugehoerige MITRE-Technik-ID (z.B. 'T1070.006') oder None

    Typischer Einsatz:
        checker = AntiForensicsChecker()
        result  = checker.check(timeline, artifacts, system_profile)
        for finding in result['findings']:
            print(f"[{finding['severity'].upper()}] {finding['description']}")
    """

    def __init__(self):
        self.findings: List[Dict[str, Any]] = []
        self._stats: Dict[str, Any] = {}

    # ── Oeffentliche API ──────────────────────────────────────────────────────

    def check(
        self,
        timeline: List[Dict],
        artifacts: List[Dict],
        system_profile: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """
        Fuehrt alle neun Anti-Forensics-Checks durch und gibt ein strukturiertes
        Ergebnis-Dict zurück.

        Die Methode setzt findings und _stats bei jedem Aufruf zurück, sodass
        dieselbe Instanz mehrfach verwendet werden kann.

        Args:
            timeline:       Normalisierte Timeline-Events (Liste von Dicts).
            artifacts:      Extrahierte Artefakte (Dissect, UAC, etc.).
            system_profile: Optionales Systemprofil aus SystemProfiler —
                            aktuell nicht direkt genutzt, aber für zukünftige
                            OS-spezifische Schwellwerte vorgesehen.

        Returns:
            Dict mit Schlüsseln:
              'findings'      — Liste aller gefundenen Indizien
              'stats'         — Interne Zähler der statistischen Checks
              'risk_score'    — Numerischer Score 0–100
              'risk_level'    — 'none' | 'low' | 'medium' | 'high' | 'critical'
              'total_checks'  — Anzahl durchgeführter Checks (immer 9)
              'findings_count'— Anzahl der Findings
              'summary'       — Lesbarer Zusammenfassungstext
        """
        self.findings = []
        self._stats = {}

        if len(timeline) >= MIN_EVENTS_FOR_STATS:
            self._check_timestomping(timeline)
            self._check_log_gaps(timeline)
            self._check_identical_timestamps(timeline)

        self._check_wipe_tools(timeline)
        self._check_log_clearing(timeline)
        self._check_time_manipulation(timeline)
        self._check_rootkit_indicators(timeline)
        self._check_truncated_logs(timeline, artifacts)
        self._check_suspicious_deletions(timeline)

        risk_score = self._compute_risk_score()

        result = {
            'findings':    self.findings,
            'stats':       self._stats,
            'risk_score':  risk_score,
            'risk_level':  self._risk_level(risk_score),
            'total_checks': 9,
            'findings_count': len(self.findings),
            'summary':     self._build_summary(risk_score),
        }

        logger.info(
            f"✓ Anti-Forensics-Check: {len(self.findings)} Hinweise, "
            f"Risiko={risk_score}/100 ({self._risk_level(risk_score)})"
        )
        return result

    # ── Check 1: Timestomping (mtime < ctime) ─────────────────────────────────

    def _check_timestomping(self, timeline: List[Dict]) -> None:
        """
        Erkennt Timestomping: mtime liegt um mehr als TIMESTOMP_DELTA_THRESHOLD
        Sekunden (Standard: 24h) vor ctime.

        Forensischer Hintergrund:
            Beim normalen Erstellen oder Ändern einer Datei ist die ctime (Change
            Time, wird vom Betriebssystem gesetzt) immer >= mtime (Modification
            Time). Manipuliert ein Angreifer nachträglich die mtime mit 'touch'
            oder dem Metasploit-Modul 'timestomp', kann mtime weit vor ctime
            liegen — ein zuverlässiges forensisches Artefakt.

        Statistik: Speichert 'timestomp_checked' und 'timestomp_suspicious' in _stats.

        Args:
            timeline: Muss 'mtime' (oder 'timestamp') und 'ctime'-Felder enthalten.
                      Events ohne beide Zeitstempel werden übersprungen.
        """
        suspicious = []
        checked = 0

        for event in timeline:
            mtime_raw = event.get('mtime') or event.get('timestamp')
            ctime_raw = event.get('ctime')
            path = event.get('path') or event.get('name', '')

            if not mtime_raw or not ctime_raw:
                continue

            try:
                mtime = _parse_ts(mtime_raw)
                ctime = _parse_ts(ctime_raw)
                if mtime is None or ctime is None:
                    continue

                checked += 1
                delta = (ctime - mtime).total_seconds()
                # mtime liegt deutlich VOR ctime → Manipulation wahrscheinlich
                if delta > TIMESTOMP_DELTA_THRESHOLD:
                    suspicious.append({
                        'path':   str(path),
                        'mtime':  mtime_raw,
                        'ctime':  ctime_raw,
                        'delta_h': round(delta / 3600, 1),
                    })
            except Exception:
                continue

        self._stats['timestomp_checked'] = checked
        self._stats['timestomp_suspicious'] = len(suspicious)

        if suspicious:
            self._add_finding(
                category='timestomping',
                severity='high' if len(suspicious) >= 5 else 'medium',
                description=(
                    f"{len(suspicious)} Datei(en) mit manipuliertem Zeitstempel erkannt "
                    f"(mtime liegt > {TIMESTOMP_DELTA_THRESHOLD // 3600}h vor ctime)."
                ),
                evidence=[f"{s['path']} (delta={s['delta_h']}h)" for s in suspicious[:10]],
                mitre='T1070.006',  # Indicator Removal: Timestomp
            )

    # ── Check 2: Log-Luecken (unerwartete Pausen in der Timeline) ─────────────

    def _check_log_gaps(self, timeline: List[Dict]) -> None:
        """
        Erkennt grosse Zeitluecken in der Timeline, die auf geloeschte
        oder manipulierte Log-Eintraege hindeuten koennen.

        Strategie: Sortiert alle extrahierbaren Timestamps und berechnet
        die zeitliche Differenz zwischen aufeinanderfolgenden Events.
        Übersteigt eine Differenz LOG_GAP_THRESHOLD_HOURS (Standard: 6h),
        wird sie als verdächtige Lücke markiert.

        Einschränkung: Legitime Wartungsfenster, Neustarts oder einfach
        inaktive Systeme erzeugen ebenfalls Lücken. Das Finding ist daher
        im Kontext zu bewerten.

        Statistik: Speichert 'log_gaps_found' in _stats.

        Args:
            timeline: Events mit 'timestamp'- oder 'mtime'-Feldern.
        """
        timestamps = []
        for event in timeline:
            ts_raw = event.get('timestamp') or event.get('mtime')
            if not ts_raw:
                continue
            ts = _parse_ts(ts_raw)
            if ts:
                timestamps.append(ts)

        if len(timestamps) < 10:
            return

        timestamps.sort()
        gaps: List[Tuple[datetime, datetime, float]] = []

        for i in range(1, len(timestamps)):
            gap_h = (timestamps[i] - timestamps[i - 1]).total_seconds() / 3600
            if gap_h >= LOG_GAP_THRESHOLD_HOURS:
                gaps.append((timestamps[i - 1], timestamps[i], round(gap_h, 1)))

        self._stats['log_gaps_found'] = len(gaps)

        if gaps:
            # Groeßte Luecke als Hauptbeleg
            biggest = max(gaps, key=lambda g: g[2])
            self._add_finding(
                category='log_gap',
                severity='medium' if len(gaps) == 1 else 'high',
                description=(
                    f"{len(gaps)} unerwartete Zeitluecke(n) in der Timeline gefunden "
                    f"(> {LOG_GAP_THRESHOLD_HOURS}h). Groesste Luecke: {biggest[2]}h "
                    f"({biggest[0].date()} → {biggest[1].date()})."
                ),
                evidence=[
                    f"{g[0].isoformat()} → {g[1].isoformat()} ({g[2]}h)" for g in gaps[:5]
                ],
                mitre='T1070',  # Indicator Removal on Host
            )

    # ── Check 3: Massenweise identische Timestamps (Cluster) ─────────────────

    def _check_identical_timestamps(self, timeline: List[Dict]) -> None:
        """
        Erkennt grosse Cluster von Dateien mit exakt gleichem Timestamp.

        Hintergrund: Wenn ein Angreifer per Skript massenhaft Zeitstempel
        überschreibt (z.B. 'touch -t 200001010000 /var/log/*'), entstehen
        auffällige Cluster — viele Dateien mit exakt derselben Sekunde.
        Die Schwelle von 20 Dateien pro Sekunde ist konservativ gewählt.

        Verwendet collections.Counter für effiziente Häufigkeitszählung.
        Timestamps werden auf Sekundengenauigkeit gerundet (microsecond=0).

        Statistik: Speichert 'identical_ts_clusters' in _stats.

        Args:
            timeline: Events mit 'mtime'- oder 'timestamp'-Feldern.
        """
        from collections import Counter

        ts_counter: Counter = Counter()
        for event in timeline:
            ts_raw = event.get('mtime') or event.get('timestamp')
            if ts_raw:
                # Auf Sekunden runden
                ts = _parse_ts(ts_raw)
                if ts:
                    ts_counter[ts.replace(microsecond=0)] += 1

        # Timestamps mit >= 20 Dateien zur selben Sekunde
        suspect_clusters = [(ts, cnt) for ts, cnt in ts_counter.items() if cnt >= 20]
        self._stats['identical_ts_clusters'] = len(suspect_clusters)

        if suspect_clusters:
            largest = max(suspect_clusters, key=lambda x: x[1])
            self._add_finding(
                category='timestamp_cluster',
                severity='medium',
                description=(
                    f"{len(suspect_clusters)} Timestamp-Cluster gefunden "
                    f"(>= 20 Dateien mit identischer Sekunde). "
                    f"Groesster Cluster: {largest[1]} Dateien um {largest[0].isoformat()}."
                ),
                evidence=[
                    f"{ts.isoformat()}: {cnt} Dateien" for ts, cnt in
                    sorted(suspect_clusters, key=lambda x: -x[1])[:5]
                ],
                mitre='T1070.006',
            )

    # ── Check 4: Wipe-Tools in der Timeline ───────────────────────────────────

    def _check_wipe_tools(self, timeline: List[Dict]) -> None:
        """
        Erkennt bekannte Datei-Wipe- und Überschreib-Tools in Prozess- und
        Log-Events anhand der WIPE_TOOLS-Menge und des DD_WIPE_RE-Regex.

        Geprüfte Quellen je Event: 'message', 'description', 'process', 'command'.
        Bei einem Treffer in einem Event wird nur der erste passende Tool-Name
        gemeldet (break nach erstem Match), um Duplikate zu vermeiden.

        dd if=/dev/zero wird gesondert über DD_WIPE_RE geprüft, da 'dd' allein
        zu allgemein wäre und Wipe-Nutzung erst durch das if-Parameter erkennbar ist.

        Args:
            timeline: Alle normalisierten Events.
        """
        hits = []
        for event in timeline:
            msg = str(event.get('message', '') or event.get('description', '') or '')
            proc = str(event.get('process', '') or event.get('command', '') or '')
            combined = (msg + ' ' + proc).lower()

            for tool in WIPE_TOOLS:
                if re.search(r'\b' + re.escape(tool) + r'\b', combined):
                    hits.append({
                        'tool': tool,
                        'context': (msg or proc)[:120],
                        'timestamp': event.get('timestamp', ''),
                    })
                    break

            if DD_WIPE_RE.search(msg) or DD_WIPE_RE.search(proc):
                hits.append({
                    'tool': 'dd (wipe)',
                    'context': (msg or proc)[:120],
                    'timestamp': event.get('timestamp', ''),
                })

        if hits:
            self._add_finding(
                category='wiping',
                severity='high',
                description=(
                    f"{len(hits)} Aufruf(e) von Datei-Wipe-Tools erkannt "
                    f"(shred, wipe, srm, dd if=/dev/zero, ...)."
                ),
                evidence=[
                    f"[{h['timestamp']}] {h['tool']}: {h['context']}" for h in hits[:10]
                ],
                mitre='T1485',  # Data Destruction
            )

    # ── Check 5: Log-Loeschung / History-Manipulation ─────────────────────────

    def _check_log_clearing(self, timeline: List[Dict]) -> None:
        """
        Erkennt Befehle, die Logs oder die Shell-Befehlshistorie
        loeschen oder manipulieren.

        Verwendet LOG_CLEAR_PATTERNS (drei Regex-Muster):
          1. truncate / cat /dev/null > /var/log/...
          2. logrotate / journalctl --rotate / journalctl --vacuum
          3. history -c / unset HISTFILE / HISTSIZE=0

        Args:
            timeline: Events mit 'message'-, 'description'-, 'command'-
                      oder 'process'-Feldern.
        """
        hits = []
        for event in timeline:
            msg = str(event.get('message', '') or event.get('description', '') or '')
            cmd = str(event.get('command', '') or event.get('process', '') or '')
            text = msg + ' ' + cmd

            for pattern in LOG_CLEAR_PATTERNS:
                m = pattern.search(text)
                if m:
                    hits.append({
                        'match': m.group(0),
                        'context': text[:120].strip(),
                        'timestamp': event.get('timestamp', ''),
                    })
                    break

        if hits:
            self._add_finding(
                category='log_clearing',
                severity='high',
                description=(
                    f"{len(hits)} Hinweis(e) auf Log- oder History-Loeschung gefunden "
                    f"(truncate, history -c, journalctl --vacuum, ...)."
                ),
                evidence=[
                    f"[{h['timestamp']}] '{h['match']}': {h['context']}" for h in hits[:10]
                ],
                mitre='T1070.002',  # Clear Linux or Mac System Logs
            )

    # ── Check 6: Systemzeit-Manipulation ──────────────────────────────────────

    def _check_time_manipulation(self, timeline: List[Dict]) -> None:
        """
        Erkennt Systemzeit-Aenderungen via bekannter Befehle aus TIMESET_TOOLS.

        Sonderfall 'date': Das Programm 'date' ist ein normaler Systembefehl
        und wird nur gemeldet, wenn es mindestens dreimal auftaucht, um
        False-Positives zu vermeiden.

        Args:
            timeline: Events mit 'message'-, 'description'-, 'command'-
                      oder 'process'-Feldern.
        """
        hits = []
        for event in timeline:
            msg = str(event.get('message', '') or event.get('description', '') or '')
            cmd = str(event.get('command', '') or event.get('process', '') or '')
            text = (msg + ' ' + cmd).lower()

            for tool in TIMESET_TOOLS:
                if re.search(r'\b' + re.escape(tool) + r'\b', text):
                    hits.append({
                        'tool': tool,
                        'context': (msg or cmd)[:120],
                        'timestamp': event.get('timestamp', ''),
                    })
                    break

        if hits:
            # 'date' alleine ist zu allgemein → nur bei mehrfachem Vorkommen melden
            date_only = all(h['tool'] == 'date' for h in hits)
            if date_only and len(hits) < 3:
                return
            self._add_finding(
                category='time_manipulation',
                severity='medium',
                description=(
                    f"{len(hits)} Systemzeit-Aenderung(en) erkannt "
                    f"(settimeofday, timedatectl, hwclock, ...)."
                ),
                evidence=[
                    f"[{h['timestamp']}] {h['tool']}: {h['context']}" for h in hits[:10]
                ],
                mitre='T1070.006',
            )

    # ── Check 7: Rootkit / Kernel-Modul-Indikatoren ───────────────────────────

    def _check_rootkit_indicators(self, timeline: List[Dict]) -> None:
        """
        Erkennt Hinweise auf Rootkit-Aktivität anhand von ROOTKIT_PATTERNS.

        Geprüfte Muster (vier Regex):
          1. insmod/modprobe/rmmod aus verdächtigen Verzeichnissen (/tmp, /dev/shm)
          2. Direkte /proc-Zugriffe auf kallsyms, kcore, kmem
          3. LD_PRELOAD-Setzung (klassische Preload-Rootkit-Technik)
          4. Schlüsselwörter: hide, hidden, stealth, invisible

        Prüft sowohl Nachrichten- als auch Pfad-Felder, da Rootkit-Spuren
        sowohl in Log-Nachrichten als auch als Dateipfade auftauchen können.

        Args:
            timeline: Alle normalisierten Events.
        """
        hits = []
        for event in timeline:
            msg = str(event.get('message', '') or event.get('description', '') or '')
            path = str(event.get('path', '') or event.get('name', '') or '')
            text = msg + ' ' + path

            for pattern in ROOTKIT_PATTERNS:
                m = pattern.search(text)
                if m:
                    hits.append({
                        'match': m.group(0),
                        'context': text[:120].strip(),
                        'timestamp': event.get('timestamp', ''),
                    })
                    break

        if hits:
            self._add_finding(
                category='rootkit_indicator',
                severity='high',
                description=(
                    f"{len(hits)} moegliche Rootkit-Indikatoren gefunden "
                    f"(LD_PRELOAD, insmod aus /tmp, /proc-Zugriffe, ...)."
                ),
                evidence=[
                    f"[{h['timestamp']}] '{h['match']}': {h['context']}" for h in hits[:10]
                ],
                mitre='T1014',  # Rootkit
            )

    # ── Check 8: Truncated/Leere Log-Dateien ──────────────────────────────────

    def _check_truncated_logs(self, timeline: List[Dict], artifacts: List[Dict]) -> None:
        """
        Erkennt Dateien unter /var/log mit Dateigroesse 0 (moegliche Truncation).

        Prüft sowohl Timeline-Events als auch Artefakte. Die Größe wird aus
        'size' oder 'st_size'-Feldern gelesen. VAR_LOG_RE stellt sicher, dass
        nur Pfade direkt unter /var/log/ berücksichtigt werden.

        Einschränkung: Neu angelegte Log-Dateien (vor dem ersten Schreibzugriff)
        haben legitim Größe 0. Das Finding ist daher im Kontext der Timeline
        zu bewerten.

        Args:
            timeline:  Normalisierte Events mit optionalen 'path'/'size'-Feldern.
            artifacts: Artefakt-Dicts — werden zusammen mit der Timeline geprüft.
        """
        truncated = []
        all_items = timeline + artifacts

        for item in all_items:
            path = str(item.get('path', '') or item.get('name', '') or '')
            size = item.get('size', -1)
            if size is None:
                try:
                    size = int(item.get('st_size', -1))
                except (TypeError, ValueError):
                    size = -1

            if VAR_LOG_RE.match(path) and size == 0:
                truncated.append(path)

        if truncated:
            self._add_finding(
                category='truncated_logs',
                severity='medium',
                description=(
                    f"{len(truncated)} leere Datei(en) unter /var/log erkannt "
                    f"(moegliche Log-Truncation)."
                ),
                evidence=truncated[:15],
                mitre='T1070.002',
            )

    # ── Check 9: Verdaechtige Loeschoperationen ────────────────────────────────

    def _check_suspicious_deletions(self, timeline: List[Dict]) -> None:
        """
        Erkennt systematische Loeschoperationen auf forensisch relevante
        Verzeichnisse und Dateien.

        RM_RE matcht 'rm' mit optionalen Flags (-r, -R, -f und Kombinationen)
        auf forensisch relevante Ziele:
          - /var/log              — System-Logs
          - /home/*/.bash_history — Benutzer-Shell-History
          - /root/.bash_history   — Root-Shell-History
          - /tmp/                 — Temporäre Dateien
          - .ssh/ / authorized_keys — SSH-Konfiguration

        Args:
            timeline: Events mit 'message'-, 'description'-, 'command'-
                      oder 'process'-Feldern.
        """
        RM_RE = re.compile(
            r'\brm\s+(-[rRf]+\s+)*(/var/log|/home/\S+/.bash_history|'
            r'/root/.bash_history|/tmp/|\.ssh/|authorized_keys)\b',
            re.IGNORECASE,
        )
        hits = []
        for event in timeline:
            msg = str(event.get('message', '') or event.get('description', '') or '')
            cmd = str(event.get('command', '') or event.get('process', '') or '')
            text = msg + ' ' + cmd

            m = RM_RE.search(text)
            if m:
                hits.append({
                    'match': m.group(0),
                    'context': text[:120].strip(),
                    'timestamp': event.get('timestamp', ''),
                })

        if hits:
            self._add_finding(
                category='suspicious_deletion',
                severity='high',
                description=(
                    f"{len(hits)} verdaechtige Loeschoperation(en) auf "
                    f"forensisch relevante Dateien/Verzeichnisse erkannt."
                ),
                evidence=[
                    f"[{h['timestamp']}] '{h['match']}': {h['context']}" for h in hits[:10]
                ],
                mitre='T1070.004',  # File Deletion
            )

    # ── Risiko-Berechnung und Zusammenfassung ─────────────────────────────────

    def _compute_risk_score(self) -> int:
        """
        Berechnet einen Risiko-Score (0–100) basierend auf den Findings.

        Gewichtung:
          'high'   → 20 Punkte pro Finding
          'medium' → 10 Punkte pro Finding
          'low'    →  5 Punkte pro Finding

        Der Score wird bei 100 gedeckelt, da mehrere high-Findings schnell
        über 100 gehen würden.

        Returns:
            Ganzzahliger Score zwischen 0 und 100 (inklusiv).
        """
        weights = {'high': 20, 'medium': 10, 'low': 5}
        score = sum(weights.get(f['severity'], 5) for f in self.findings)
        return min(score, 100)

    @staticmethod
    def _risk_level(score: int) -> str:
        """
        Klassifiziert den numerischen Risiko-Score in ein Risiko-Level.

        Schwellwerte:
          >= 60 → 'critical'
          >= 40 → 'high'
          >= 20 → 'medium'
          >  0  → 'low'
          == 0  → 'none'

        Args:
            score: Numerischer Risiko-Score (0–100).

        Returns:
            Risiko-Level als String.
        """
        if score >= 60:
            return 'critical'
        elif score >= 40:
            return 'high'
        elif score >= 20:
            return 'medium'
        elif score > 0:
            return 'low'
        return 'none'

    def _build_summary(self, risk_score: int) -> str:
        """
        Erzeugt einen lesbaren Zusammenfassungstext für den Bericht.

        Args:
            risk_score: Bereits berechneter numerischer Risiko-Score.

        Returns:
            Einzeiliger Zusammenfassungstext mit Anzahl der Findings,
            erkannten Kategorien und Risiko-Score.
        """
        if not self.findings:
            return "Keine Anti-Forensics-Indikatoren erkannt."
        categories = list({f['category'] for f in self.findings})
        return (
            f"{len(self.findings)} Anti-Forensics-Hinweis(e) erkannt "
            f"(Kategorien: {', '.join(categories)}). "
            f"Risiko-Score: {risk_score}/100 ({self._risk_level(risk_score)})."
        )

    def _add_finding(
        self,
        category: str,
        severity: str,
        description: str,
        evidence: List[str],
        mitre: Optional[str] = None,
    ) -> None:
        """
        Fügt ein strukturiertes Finding zur internen Findings-Liste hinzu.

        Args:
            category:    Kurzname der Kategorie (z.B. 'timestomping').
            severity:    Schweregra 'high' | 'medium' | 'low'.
            description: Lesbare Beschreibung des Befunds.
            evidence:    Liste konkreter Belege (max. 10–15 Einträge empfohlen).
            mitre:       MITRE ATT&CK Technik-ID (z.B. 'T1070.004') oder None.
        """
        self.findings.append({
            'category':    category,
            'severity':    severity,
            'description': description,
            'evidence':    evidence,
            'mitre':       mitre,
        })


# ── Hilfsfunktionen ───────────────────────────────────────────────────────────

def _parse_ts(raw) -> Optional[datetime]:
    """
    Versucht einen Timestamp aus verschiedenen Formaten zu parsen.

    Unterstützte Eingabetypen und Formate:
      - int/float: Unix-Timestamp (Sekunden seit Epoch, UTC)
      - str:       ISO 8601 mit/ohne Mikrosekunden und Timezone,
                   sowie 'YYYY-MM-DD HH:MM:SS' und 'YYYY-MM-DD'

    Timestamps ohne Zeitzoneninformation werden als UTC interpretiert.
    Ungültige oder leere Eingaben geben None zurück (kein Exception-Raise).

    Args:
        raw: Roher Timestamp-Wert aus einem Event-Dict.

    Returns:
        timezone-aware datetime-Objekt (UTC) oder None bei Parse-Fehler.
    """
    if raw is None:
        return None
    if isinstance(raw, (int, float)):
        try:
            return datetime.fromtimestamp(float(raw), tz=timezone.utc)
        except (OSError, ValueError, OverflowError):
            return None
    raw_str = str(raw).strip()
    if not raw_str or raw_str in ('-', 'None', 'nan'):
        return None
    # ISO 8601
    for fmt in (
        '%Y-%m-%dT%H:%M:%S.%f%z',
        '%Y-%m-%dT%H:%M:%S%z',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%d',
    ):
        try:
            dt = datetime.strptime(raw_str[:26], fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None
