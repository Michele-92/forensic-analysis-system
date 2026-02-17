"""
REPARATUR #54: Anomaly Detector mit verbessertem Logging.

ML-basierte Anomalie-Erkennung (Isolation Forest, etc.).
"""

import logging
from typing import List, Dict, Tuple
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pandas as pd

# REPARATUR #55: Besseres Logging für Anomaly Detector
logger = logging.getLogger(__name__)


class AnomalyDetector:
    """ML-basierte Anomalie-Erkennung für forensische Daten."""
    
    def __init__(self, contamination: float = 0.1):
        """
        Args:
            contamination: Erwarteter Anteil an Anomalien (0.1 = 10%)
        """
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
        Extrahiert Features aus Timeline für ML.
        
        Features:
        - Hour of day
        - Day of week
        - File size (log)
        - Path depth
        - Extension hash
        
        Args:
            timeline: Timeline-Events
        
        Returns:
            Feature-Matrix (n_events x n_features)
        """
        features = []
        self.feature_names = ['hour', 'day_of_week', 'file_size_log', 'path_depth']
        
        for event in timeline:
            try:
                # Timestamp-Features
                timestamp = pd.to_datetime(event.get('timestamp', 'now'))
                hour = timestamp.hour
                day_of_week = timestamp.dayofweek
                
                # File-Features
                size = event.get('metadata', {}).get('size', 1)
                file_size_log = np.log10(max(size, 1))
                
                path = event.get('metadata', {}).get('path', '/')
                path_depth = len(path.split('/'))
                
                features.append([hour, day_of_week, file_size_log, path_depth])
            
            except Exception as e:
                logger.debug(f"Feature-Extraktion fehlgeschlagen: {e}")
                features.append([0, 0, 0, 0])
        
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
        REPARATUR #57: Gibt Top-N Anomalien zurück mit Logging.
        
        Args:
            timeline: Timeline mit Scores
            top_n: Anzahl Top-Anomalien
        
        Returns:
            Top-N anomale Events
        """
        sorted_timeline = sorted(
            timeline,
            key=lambda x: x.get('anomaly_score', 0),
            reverse=True
        )
        
        top_anomalies = sorted_timeline[:top_n]
        logger.info(f"✓ Top-{top_n} Anomalien extrahiert (Scores: {[round(a.get('anomaly_score', 0), 3) for a in top_anomalies]})")
        
        return top_anomalies
    
    def explain_anomaly(self, event: Dict) -> str:
        """
        REPARATUR #58: Erklärt warum Event anomal ist mit Logging.
        
        Args:
            event: Anomales Event
        
        Returns:
            Erklärung
        """
        reasons = []
        
        timestamp = pd.to_datetime(event.get('timestamp', 'now'))
        hour = timestamp.hour
        
        # Ungewöhnliche Zeit
        if hour < 6 or hour > 22:
            reasons.append(f"Ungewöhnliche Uhrzeit: {hour:02d}:00")
        
        # Große Datei
        size = event.get('metadata', {}).get('size', 0)
        if size > 100_000_000:  # >100MB
            reasons.append(f"Große Datei: {size/1_000_000:.1f}MB")
        
        # Verdächtiger Pfad
        path = event.get('metadata', {}).get('path', '')
        if '/tmp/' in path or '\\Temp\\' in path:
            reasons.append("Verdächtiger Pfad: Temp-Verzeichnis")
        
        if not reasons:
            reasons.append("Statistisch ungewöhnlich")
        
        explanation = " | ".join(reasons)
        logger.debug(f"Anomalie-Erklärung: {explanation}")
        
        return explanation