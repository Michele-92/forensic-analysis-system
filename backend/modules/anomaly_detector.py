"""
Anomaly Detector — ML-basierte Anomalie-Erkennung (Isolation Forest).

Unterstuetzt sowohl Filesystem-Events (Dissect/SleuthKit) als auch
Log-parsed Events (Syslog, Apache, Firewall, etc.).
"""

import logging
import re
from typing import List, Dict, Tuple
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pandas as pd

logger = logging.getLogger(__name__)

# ── Event-Typ Kategorien (hoeher = verdaechtiger) ────────────────────────────
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

# Verdaechtige Schluesselwoerter in Nachrichten
SUSPICIOUS_KEYWORDS = [
    'failed', 'invalid', 'root', 'sudo', 'admin', 'shadow', 'passwd',
    'wget', 'curl', 'nmap', 'netcat', 'ncat', 'base64', 'chmod 777',
    'reverse', 'shell', 'exploit', 'overflow', 'injection', 'brute',
    'exfil', 'backdoor', 'trojan', 'malware', 'c2', 'beacon',
    'history -c', 'rm -rf', '/tmp/', 'crontab', 'authorized_keys',
]

# Bekannte private IP-Bereiche (nicht anomal)
PRIVATE_IP_RE = re.compile(r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)')


class AnomalyDetector:
    """ML-basierte Anomalie-Erkennung fuer forensische Daten."""

    def __init__(self, contamination: float = 0.1):
        self.contamination = contamination
        self.model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100
        )
        self.scaler = StandardScaler()
        self.feature_names = []

    def extract_features(self, timeline: List[Dict]) -> np.ndarray:
        """
        Extrahiert Features aus Timeline fuer ML.

        Unterstuetzt zwei Event-Typen:
        1. Filesystem-Events (Dissect/TSK): size, path, inode
        2. Log-parsed Events (Syslog/Apache/etc.): event_type, message, src_ip

        Features:
        - hour: Stunde des Events (0-23)
        - day_of_week: Wochentag (0-6)
        - event_type_score: Verdaechtigkeitsscore des Event-Typs (1-10)
        - is_off_hours: 1 wenn ausserhalb Geschaeftszeiten (22-06)
        - suspicious_keyword_count: Anzahl verdaechtiger Keywords in message
        - has_external_ip: 1 wenn eine oeffentliche IP vorkommt
        - message_length: Laenge der Nachricht (normalisiert)
        - file_size_log: log10(Dateigroesse) fuer Filesystem-Events
        """
        features = []
        self.feature_names = [
            'hour', 'day_of_week', 'event_type_score', 'is_off_hours',
            'suspicious_keyword_count', 'has_external_ip', 'message_length',
            'file_size_log'
        ]

        for event in timeline:
            try:
                # Timestamp-Features
                timestamp = pd.to_datetime(event.get('timestamp', 'now'))
                hour = timestamp.hour
                day_of_week = timestamp.dayofweek
                is_off_hours = 1.0 if (hour >= 22 or hour < 6) else 0.0

                # Event-Typ Score
                meta = event.get('metadata', {}) if isinstance(event.get('metadata'), dict) else {}
                event_type = event.get('event_type', meta.get('event_type', 'unknown'))
                event_type_score = EVENT_TYPE_SCORES.get(event_type, 1)

                # Message-Features
                message = (event.get('description', '') or
                           meta.get('message', '') or
                           meta.get('raw_line', '') or '').lower()
                message_length = min(len(message) / 200.0, 5.0)  # Cap bei 1000 chars

                # Verdaechtige Keywords zaehlen
                suspicious_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in message)

                # IP-Features
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

                # Dateigroesse (fuer Filesystem-Events)
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
                features.append([0, 0, 1, 0, 0, 0, 0, 0])

        return np.array(features)
    
    def fit_detect(self, timeline: List[Dict]) -> List[Dict]:
        """
        REPARATUR #56: Trainiert Modell und detektiert Anomalien mit besserem Logging.
        
        Args:
            timeline: Timeline-Events
        
        Returns:
            Timeline mit Anomalie-Scores und is_anomaly-Flag
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
            anomaly_scores = self.model.score_samples(X_scaled)
            logger.debug(f"     ✓ Modell trainiert")
            
            # Normalisiere Scores zu 0-1
            logger.debug(f"  4. Normalisiere Scores...")
            scores_normalized = self._normalize_scores(anomaly_scores)
            logger.debug(f"     ✓ Scores normalisiert (Range: {scores_normalized.min():.3f} - {scores_normalized.max():.3f})")
            
            # Füge Scores zu Timeline hinzu
            for i, event in enumerate(timeline):
                event['anomaly_score'] = float(scores_normalized[i])
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
        """Normalisiert Anomalie-Scores zu 0-1 Range."""
        # Isolation Forest gibt negative Scores (niedriger = anomaler)
        # Invertiere und normalisiere
        inverted = -scores
        min_score = inverted.min()
        max_score = inverted.max()
        
        if max_score == min_score:
            return np.zeros_like(scores)
        
        normalized = (inverted - min_score) / (max_score - min_score)
        return normalized
    
    def get_top_anomalies(self,
                         timeline: List[Dict],
                         top_n: int = 10) -> List[Dict]:
        """
        Gibt Top-N Anomalien zurueck, angereichert mit Erklaerungen.
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
        Erklaert warum ein Event als anomal eingestuft wurde.

        Unterstuetzt sowohl Filesystem- als auch Log-parsed Events.
        """
        reasons = []
        meta = event.get('metadata', {}) if isinstance(event.get('metadata'), dict) else {}

        # Timestamp-Analyse
        try:
            timestamp = pd.to_datetime(event.get('timestamp', 'now'))
            hour = timestamp.hour
            if hour < 6 or hour >= 22:
                reasons.append(f"Ungewoehnliche Uhrzeit: {hour:02d}:00")
        except Exception:
            pass

        # Event-Typ Verdaechtigkeit
        event_type = event.get('event_type', meta.get('event_type', 'unknown'))
        score = EVENT_TYPE_SCORES.get(event_type, 1)
        if score >= 7:
            reasons.append(f"Hochverdaechtiger Event-Typ: {event_type}")
        elif score >= 5:
            reasons.append(f"Verdaechtiger Event-Typ: {event_type}")

        # Message-Keywords
        message = (event.get('description', '') or meta.get('message', '') or '').lower()
        found_kws = [kw for kw in SUSPICIOUS_KEYWORDS if kw in message]
        if found_kws:
            reasons.append(f"Verdaechtige Keywords: {', '.join(found_kws[:3])}")

        # Externe IP
        src_ip = meta.get('src_ip', '')
        if src_ip and not PRIVATE_IP_RE.match(src_ip):
            reasons.append(f"Externe IP: {src_ip}")

        # Grosse Datei (Filesystem)
        size = meta.get('size', 0)
        if isinstance(size, (int, float)) and size > 100_000_000:
            reasons.append(f"Grosse Datei: {size / 1_000_000:.1f}MB")

        # Verdaechtiger Pfad
        path = meta.get('path', '') or meta.get('name', '')
        if path and ('/tmp/' in path or '\\Temp\\' in path):
            reasons.append("Verdaechtiger Pfad: Temp-Verzeichnis")

        if not reasons:
            reasons.append("Statistisch ungewoehnlich (ML-basiert)")

        explanation = " | ".join(reasons)
        logger.debug(f"Anomalie-Erklaerung: {explanation}")
        return explanation