"""
================================================================================
ANOMALY DETECTOR — ML-basierte Erkennung verdächtiger forensischer Events
================================================================================
Implementiert unüberwachtes maschinelles Lernen (Isolation Forest) zur
automatischen Identifikation statistisch ungewöhnlicher Events in einer
forensischen Timeline.

Funktionsprinzip:
    Der Isolation Forest isoliert Datenpunkte durch zufällige Partitionierung.
    Anomalien lassen sich mit wenigen Schnitten isolieren (kurze Pfadlänge),
    normale Punkte benötigen viele Schnitte (lange Pfadlänge). Das Modell
    gibt für jeden Event einen Score zurück, der zu 0–1 normalisiert wird.

Unterstützte Event-Quellen:
    - Filesystem-Events (Dissect / Sleuth Kit): size, path, inode
    - Log-geparste Events (Syslog, Apache, Firewall, etc.): event_type, message, src_ip

Feature-Vektor (8 Dimensionen pro Event):
    [hour, day_of_week, event_type_score, is_off_hours,
     suspicious_keyword_count, has_external_ip, message_length, file_size_log]

Verwendung:
    detector = AnomalyDetector(contamination=0.1)
    timeline_with_scores = detector.fit_detect(normalized_events)
    top_10 = detector.get_top_anomalies(timeline_with_scores, top_n=10)

Konfiguration:
    contamination=0.1  → Annahme: ~10% der Events sind anomal
    n_estimators=100   → 100 Entscheidungsbäume im Ensemble
    random_state=42    → Reproduzierbare Ergebnisse

Abhängigkeiten:
    - scikit-learn (IsolationForest, StandardScaler)
    - numpy
    - pandas (Timestamp-Parsing)

Kontext: LFX Forensic Analysis System — Pipeline Stage 6 (Anomalie-Erkennung)
"""

import logging
import re
from typing import List, Dict, Tuple
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pandas as pd

# ── Modul-Logger ───────────────────────────────────────────────────────────────
logger = logging.getLogger(__name__)

# ── Event-Typ Scores (Verdächtigkeits-Gewichtung) ─────────────────────────────
# Weist jedem Event-Typ einen numerischen Score von 1 (unauffällig) bis
# 10 (hochverdächtig) zu. Dieser Wert fließt als Feature in den ML-Algorithmus
# ein und beeinflusst zusätzlich die textuelle Anomalie-Erklärung.
EVENT_TYPE_SCORES = {
    # Hoch verdaechtig (Angriffsindikatoren)
    'auth_failure': 8, 'sqli_attempt': 10, 'xss_attempt': 10,
    'credential_access': 9, 'data_exfiltration': 9, 'anti_forensics': 10,
    'network_attack': 9, 'privilege_escalation': 7,
    # Mittel verdaechtig
    'suspicious_request': 6, 'network_tool': 6, 'account_modification': 5,
    'file_download': 5, 'permission_change': 5, 'firewall_block': 5,
    'firewall_drop': 5, 'firewall_deny': 5, 'http_error': 4,
    # Niedrig (normal aber beobachtenswert)
    'auth_success': 2, 'ssh_event': 3, 'scheduled_task': 1,
    'firewall_allow': 1, 'http_request': 1, 'kernel_event': 2,
    'system_alert': 4, 'system_event': 1, 'log_entry': 1,
    # Standard
    'file_system': 1, 'windows_event': 2, 'unknown': 1,
}

# ── Verdächtige Schlüsselwörter ────────────────────────────────────────────────
# Liste von Begriffen, die in Log-Nachrichten auf verdächtige Aktivitäten
# hinweisen. Das Feature 'suspicious_keyword_count' zählt, wie viele dieser
# Begriffe in der Event-Beschreibung vorkommen.
SUSPICIOUS_KEYWORDS = [
    'failed', 'invalid', 'root', 'sudo', 'admin', 'shadow', 'passwd',
    'wget', 'curl', 'nmap', 'netcat', 'ncat', 'base64', 'chmod 777',
    'reverse', 'shell', 'exploit', 'overflow', 'injection', 'brute',
    'exfil', 'backdoor', 'trojan', 'malware', 'c2', 'beacon',
    'history -c', 'rm -rf', '/tmp/', 'crontab', 'authorized_keys',
]

# ── Regex für private IP-Bereiche (RFC 1918 + Loopback) ───────────────────────
# Private IPs gelten als nicht-anomal bzgl. des has_external_ip-Features.
# Abgedeckte Bereiche: 10.x.x.x, 172.16–31.x.x, 192.168.x.x, 127.x.x.x
PRIVATE_IP_RE = re.compile(r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)')


# ── Haupt-Klasse ───────────────────────────────────────────────────────────────

class AnomalyDetector:
    """
    ML-basierte Anomalie-Erkennung für forensische Timeline-Daten.

    Verwendet einen Isolation Forest als unüberwachtes Lernverfahren.
    Das Modell wird pro Analyse neu trainiert (transduktiv), da kein
    persistentes Modell benötigt wird — alle Daten liegen bei fit_detect()
    vor.

    Attribute:
        contamination (float): Erwarteter Anteil anomaler Events (0.0–0.5).
        model:          Scikit-learn IsolationForest-Instanz.
        scaler:         StandardScaler zur Feature-Normalisierung.
        feature_names:  Liste der Feature-Namen (für Debugging / Erklärungen).
    """

    def __init__(self, contamination: float = 0.1):
        """
        Initialisiert den AnomalyDetector mit konfigurierbarer Contamination-Rate.

        Args:
            contamination: Erwarteter Anteil anomaler Datenpunkte (Standard: 0.1 = 10%).
                           Beeinflusst den internen Score-Schwellwert des IsolationForest.
        """
        self.contamination = contamination
        # IsolationForest: 100 Bäume, fester Seed für Reproduzierbarkeit
        self.model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100
        )
        # StandardScaler normalisiert Features auf Mittelwert=0, Standardabweichung=1
        self.scaler = StandardScaler()
        # Wird in extract_features() befüllt; dient der Nachvollziehbarkeit
        self.feature_names = []

    def extract_features(self, timeline: List[Dict]) -> np.ndarray:
        """
        Extrahiert einen numerischen Feature-Vektor aus jedem Timeline-Event.

        Konvertiert heterogene Event-Dicts in eine einheitliche Matrix,
        die vom IsolationForest verarbeitet werden kann. Pro Event wird
        ein 8-dimensionaler Vektor erstellt.

        Feature-Beschreibung:
            hour                   — Stunde des Events (0–23), Nachtaktivität ist verdächtig
            day_of_week            — Wochentag (0=Mo, 6=So), Wochenend-Aktivität ggf. anomal
            event_type_score       — Verdächtigkeitsscore aus EVENT_TYPE_SCORES (1–10)
            is_off_hours           — 1.0 wenn außerhalb Geschäftszeiten (22:00–06:00)
            suspicious_keyword_count — Anzahl verdächtiger Keywords in der Nachricht
            has_external_ip        — 1.0 wenn eine öffentliche (nicht-private) IP vorkommt
            message_length         — normalisierte Nachrichtenlänge (gecappt bei 1000 Zeichen)
            file_size_log          — log10(Dateigröße) für Filesystem-Events, sonst 0.0

        Args:
            timeline: Liste normalisierter Event-Dicts.

        Returns:
            numpy.ndarray der Form (n_events, 8).
            Bei Verarbeitungsfehlern einzelner Events wird ein Null-Vektor eingesetzt.
        """
        features = []
        self.feature_names = [
            'hour', 'day_of_week', 'event_type_score', 'is_off_hours',
            'suspicious_keyword_count', 'has_external_ip', 'message_length',
            'file_size_log'
        ]

        for event in timeline:
            try:
                # ── Timestamp-Features ────────────────────────────────────────
                timestamp = pd.to_datetime(event.get('timestamp', 'now'))
                hour = timestamp.hour
                day_of_week = timestamp.dayofweek
                # Außerhalb üblicher Geschäftszeiten: erhöhte Verdächtigkeit
                is_off_hours = 1.0 if (hour >= 22 or hour < 6) else 0.0

                # ── Event-Typ Score ───────────────────────────────────────────
                # Suche in event direkt und in metadata (je nach Quelle verschieden)
                meta = event.get('metadata', {}) if isinstance(event.get('metadata'), dict) else {}
                event_type = event.get('event_type', meta.get('event_type', 'unknown'))
                event_type_score = EVENT_TYPE_SCORES.get(event_type, 1)

                # ── Message-Features ──────────────────────────────────────────
                # Kombiniere alle Textfelder: description, message, raw_line
                message = (event.get('description', '') or
                           meta.get('message', '') or
                           meta.get('raw_line', '') or '').lower()
                # Normalisierung: 200 Zeichen entsprechen Feature-Wert 1.0; Cap bei 5.0
                message_length = min(len(message) / 200.0, 5.0)  # Cap bei 1000 chars

                # Verdaechtige Keywords zaehlen
                suspicious_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in message)

                # ── IP-Features ───────────────────────────────────────────────
                has_external_ip = 0.0
                src_ip = meta.get('src_ip', '')
                if src_ip and not PRIVATE_IP_RE.match(src_ip):
                    has_external_ip = 1.0
                # Auch in message nach externen IPs suchen
                if not has_external_ip:
                    ips_in_msg = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', message)
                    for ip in ips_in_msg:
                        if not PRIVATE_IP_RE.match(ip):
                            has_external_ip = 1.0
                            break

                # ── Dateigrößen-Feature (Filesystem-Events) ───────────────────
                # Logarithmische Skalierung verhindert, dass sehr große Dateien
                # den Feature-Raum dominieren
                size = meta.get('size', 0)
                if isinstance(size, (int, float)) and size > 0:
                    file_size_log = np.log10(max(size, 1))
                else:
                    file_size_log = 0.0

                features.append([
                    hour, day_of_week, event_type_score, is_off_hours,
                    suspicious_count, has_external_ip, message_length,
                    file_size_log
                ])

            except Exception as e:
                logger.debug(f"Feature-Extraktion fehlgeschlagen: {e}")
                # Null-Vektor als sicherer Fallback bei fehlerhaften Events
                features.append([0, 0, 1, 0, 0, 0, 0, 0])

        return np.array(features)

    def fit_detect(self, timeline: List[Dict]) -> List[Dict]:
        """
        Trainiert das IsolationForest-Modell und erkennt Anomalien in einem Schritt.

        Ablauf:
            1. Feature-Extraktion (8 Features pro Event)
            2. StandardScaler-Normalisierung (Mittelwert=0, Std=1)
            3. IsolationForest Training + Prediction (-1=anomal, 1=normal)
            4. Score-Normalisierung auf 0.0–1.0 (höher = anomaler)
            5. Anreicherung der Events mit 'anomaly_score' und 'is_anomaly'

        Args:
            timeline: Liste normalisierter Events (nach Pipeline Stage 5).

        Returns:
            Timeline mit zwei neuen Feldern pro Event:
                'anomaly_score' (float, 0.0–1.0): Wie stark anomal ist das Event?
                'is_anomaly'    (bool):            True wenn vom Modell als Anomalie klassifiziert.

        Raises:
            Exception: Bei Fehlern in sklearn-Operationen (z.B. leere Feature-Matrix).
        """
        if not timeline:
            logger.warning("⚠ Leere Timeline - keine Anomalieerkennung möglich")
            return []

        logger.info(f"→ Starte ML-Anomalieerkennung für {len(timeline)} Events")

        try:
            # Feature-Extraktion
            logger.debug(f"  1. Feature-Extraktion...")
            X = self.extract_features(timeline)
            logger.debug(f"     ✓ {X.shape[0]} Events x {X.shape[1]} Features")

            # Skalierung
            logger.debug(f"  2. Feature-Skalierung...")
            X_scaled = self.scaler.fit_transform(X)
            logger.debug(f"     ✓ StandardScaler angewendet")

            # Training & Prediction
            logger.debug(f"  3. Isolation Forest Training...")
            predictions = self.model.fit_predict(X_scaled)
            # score_samples() gibt rohe Anomalie-Scores zurück (negativ = anomaler)
            anomaly_scores = self.model.score_samples(X_scaled)
            logger.debug(f"     ✓ Modell trainiert")

            # Normalisiere Scores zu 0-1
            logger.debug(f"  4. Normalisiere Scores...")
            scores_normalized = self._normalize_scores(anomaly_scores)
            logger.debug(f"     ✓ Scores normalisiert (Range: {scores_normalized.min():.3f} - {scores_normalized.max():.3f})")

            # Füge Scores zu Timeline hinzu
            for i, event in enumerate(timeline):
                event['anomaly_score'] = float(scores_normalized[i])
                # IsolationForest: -1 = Anomalie, +1 = Normal
                event['is_anomaly'] = predictions[i] == -1

            anomaly_count = sum(predictions == -1)
            anomaly_percentage = (anomaly_count/len(timeline)*100)
            logger.info(f"✓ Anomalieerkennung abgeschlossen:")
            logger.info(f"  → {anomaly_count} von {len(timeline)} Events anomal ({anomaly_percentage:.1f}%)")

            return timeline
        except Exception as e:
            logger.error(f"✗ Fehler bei Anomalieerkennung: {e}")
            raise

    def _normalize_scores(self, scores: np.ndarray) -> np.ndarray:
        """
        Normalisiert rohe IsolationForest-Scores auf den Bereich [0.0, 1.0].

        Der IsolationForest liefert negative Scores, bei denen gilt:
        Je kleiner (negativer) der Score, desto anomaler der Punkt.
        Diese Methode invertiert und skaliert die Scores so, dass
        1.0 = maximal anomal und 0.0 = maximal normal bedeutet.

        Args:
            scores: Rohe Score-Werte aus IsolationForest.score_samples().

        Returns:
            Normalisiertes numpy-Array mit Werten in [0.0, 1.0].
        """
        # Isolation Forest gibt negative Scores (niedriger = anomaler)
        # Invertiere und normalisiere
        inverted = -scores
        min_score = inverted.min()
        max_score = inverted.max()

        # Sonderfall: alle Scores identisch → kein Anomalie-Gradient erkennbar
        if max_score == min_score:
            return np.zeros_like(scores)

        # Min-Max-Normalisierung auf [0, 1]
        normalized = (inverted - min_score) / (max_score - min_score)
        return normalized

    def get_top_anomalies(self,
                         timeline: List[Dict],
                         top_n: int = 10) -> List[Dict]:
        """
        Gibt die N Events mit den höchsten Anomalie-Scores zurück.

        Sortiert die Timeline absteigend nach 'anomaly_score' und reichert
        jeden Treffer mit einer textuellen Erklärung an (warum ist dieses
        Event anomal?).

        Args:
            timeline: Timeline mit bereits berechneten anomaly_scores.
            top_n:    Anzahl zurückzugebender Top-Anomalien (Standard: 10).

        Returns:
            Liste der top_n verdächtigsten Events, absteigend nach Score sortiert.
            Jedes Event enthält zusätzlich ein 'explanation'-Feld.
        """
        sorted_timeline = sorted(
            timeline,
            key=lambda x: x.get('anomaly_score', 0),
            reverse=True
        )

        top_anomalies = sorted_timeline[:top_n]

        # Erklaerungen hinzufuegen
        for anomaly in top_anomalies:
            if 'explanation' not in anomaly:
                anomaly['explanation'] = self.explain_anomaly(anomaly)

        logger.info(f"Top-{top_n} Anomalien extrahiert (Scores: {[round(a.get('anomaly_score', 0), 3) for a in top_anomalies]})")
        return top_anomalies

    def explain_anomaly(self, event: Dict) -> str:
        """
        Generiert eine menschenlesbare Begründung für die Anomalie-Klassifikation.

        Analysiert das Event anhand mehrerer Heuristiken und formuliert
        verständliche Erklärungen. Diese werden im Frontend (Intelligence-Panel)
        und im LLM-Kontext verwendet.

        Geprüfte Kriterien:
            - Ungewöhnliche Uhrzeit (außerhalb 06:00–22:00)
            - Hochverdächtiger Event-Typ (Score ≥ 7 oder ≥ 5)
            - Verdächtige Schlüsselwörter in der Nachricht
            - Öffentliche (externe) Quell-IP-Adresse
            - Ungewöhnlich große Datei (> 100 MB)
            - Verdächtiger Dateipfad (Temp-Verzeichnisse)

        Args:
            event: Event-Dict mit 'timestamp', 'event_type', 'metadata', etc.

        Returns:
            Pipe-separierter String mit allen Anomalie-Gründen,
            z.B. "Ungewoehnliche Uhrzeit: 03:00 | Externe IP: 185.220.101.42"
            Fallback: "Statistisch ungewoehnlich (ML-basiert)"
        """
        reasons = []
        meta = event.get('metadata', {}) if isinstance(event.get('metadata'), dict) else {}

        # ── Zeitstempel-Analyse ───────────────────────────────────────────────
        try:
            timestamp = pd.to_datetime(event.get('timestamp', 'now'))
            hour = timestamp.hour
            if hour < 6 or hour >= 22:
                reasons.append(f"Ungewoehnliche Uhrzeit: {hour:02d}:00")
        except Exception:
            pass

        # ── Event-Typ Verdächtigkeit ──────────────────────────────────────────
        event_type = event.get('event_type', meta.get('event_type', 'unknown'))
        score = EVENT_TYPE_SCORES.get(event_type, 1)
        if score >= 7:
            reasons.append(f"Hochverdaechtiger Event-Typ: {event_type}")
        elif score >= 5:
            reasons.append(f"Verdaechtiger Event-Typ: {event_type}")

        # ── Schlüsselwort-Analyse ─────────────────────────────────────────────
        message = (event.get('description', '') or meta.get('message', '') or '').lower()
        found_kws = [kw for kw in SUSPICIOUS_KEYWORDS if kw in message]
        if found_kws:
            # Maximal 3 Keywords anzeigen, um die Ausgabe lesbar zu halten
            reasons.append(f"Verdaechtige Keywords: {', '.join(found_kws[:3])}")

        # ── Externe IP-Adresse ────────────────────────────────────────────────
        src_ip = meta.get('src_ip', '')
        if src_ip and not PRIVATE_IP_RE.match(src_ip):
            reasons.append(f"Externe IP: {src_ip}")

        # ── Dateigröße (Filesystem-Events) ────────────────────────────────────
        size = meta.get('size', 0)
        if isinstance(size, (int, float)) and size > 100_000_000:
            reasons.append(f"Grosse Datei: {size / 1_000_000:.1f}MB")

        # ── Verdächtiger Dateipfad ────────────────────────────────────────────
        # Temp-Verzeichnisse sind häufige Ablageorte für Malware und Dropper
        path = meta.get('path', '') or meta.get('name', '')
        if path and ('/tmp/' in path or '\\Temp\\' in path):
            reasons.append("Verdaechtiger Pfad: Temp-Verzeichnis")

        # Fallback, wenn keine regelbasierten Gründe gefunden wurden
        if not reasons:
            reasons.append("Statistisch ungewoehnlich (ML-basiert)")

        explanation = " | ".join(reasons)
        logger.debug(f"Anomalie-Erklaerung: {explanation}")
        return explanation
