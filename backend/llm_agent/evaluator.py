"""
Evaluator für LLM-Agent Performance.
Basierend auf Metriken aus "LLM-based Digital Forensic Timeline Analysis" (2025).
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
import pandas as pd
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns

logger = logging.getLogger(__name__)


@dataclass
class EvaluationMetrics:
    """Container für Evaluations-Metriken."""
    precision: float
    recall: float
    f1_score: float
    accuracy: float
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    
    def to_dict(self) -> Dict:
        """Konvertiert zu Dictionary."""
        return {
            'precision': round(self.precision, 3),
            'recall': round(self.recall, 3),
            'f1_score': round(self.f1_score, 3),
            'accuracy': round(self.accuracy, 3),
            'true_positives': self.true_positives,
            'false_positives': self.false_positives,
            'true_negatives': self.true_negatives,
            'false_negatives': self.false_negatives
        }


class LLMEvaluator:
    """
    Evaluiert LLM-Agent Performance gegen Ground Truth.
    
    Metriken:
    - Precision: TP / (TP + FP) - Wie viele erkannte Anomalien sind echt?
    - Recall: TP / (TP + FN) - Wie viele echte Anomalien wurden erkannt?
    - F1-Score: Harmonisches Mittel von Precision & Recall
    - Accuracy: (TP + TN) / Total - Gesamtgenauigkeit
    """
    
    def __init__(self, ground_truth_path: Optional[Path] = None):
        """
        Args:
            ground_truth_path: Pfad zu Ground-Truth-Labels (JSON)
        """
        self.ground_truth = self._load_ground_truth(ground_truth_path)
        self.results_history = []
    
    def _load_ground_truth(self, path: Optional[Path]) -> Dict:
        """Lädt Ground-Truth-Daten."""
        if path and path.exists():
            with open(path) as f:
                return json.load(f)
        return {}
    
    def evaluate_anomaly_detection(self, 
                                   predictions: List[Dict],
                                   ground_truth: List[Dict]) -> EvaluationMetrics:
        """
        Evaluiert Anomalie-Erkennungs-Performance.
        
        Args:
            predictions: LLM-Output [{"event_id": "...", "anomaly_score": 0.8, ...}]
            ground_truth: Labels [{"event_id": "...", "is_anomaly": True, ...}]
        
        Returns:
            EvaluationMetrics mit Precision, Recall, F1
        """
        logger.info(f"Evaluiere {len(predictions)} Predictions gegen {len(ground_truth)} Ground Truth")
        
        # Erstelle Mappings
        pred_dict = {p["event_id"]: p["anomaly_score"] for p in predictions}
        gt_dict = {g["event_id"]: g["is_anomaly"] for g in ground_truth}
        
        # Finde gemeinsame Event-IDs
        common_ids = set(pred_dict.keys()) & set(gt_dict.keys())
        
        if not common_ids:
            logger.warning("Keine übereinstimmenden Event-IDs zwischen Predictions und Ground Truth")
            return EvaluationMetrics(0, 0, 0, 0, 0, 0, 0, 0)
        
        # Konvertiere zu Binary (Threshold: 0.5)
        y_true = [1 if gt_dict[eid] else 0 for eid in common_ids]
        y_pred = [1 if pred_dict[eid] >= 0.5 else 0 for eid in common_ids]
        
        # Berechne Metriken
        precision = precision_score(y_true, y_pred, zero_division=0)
        recall = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        
        # Confusion Matrix
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
        accuracy = (tp + tn) / len(common_ids)
        
        metrics = EvaluationMetrics(
            precision=precision,
            recall=recall,
            f1_score=f1,
            accuracy=accuracy,
            true_positives=int(tp),
            false_positives=int(fp),
            true_negatives=int(tn),
            false_negatives=int(fn)
        )
        
        logger.info(f"Metrics: P={precision:.3f}, R={recall:.3f}, F1={f1:.3f}")
        
        # Speichere in History
        self.results_history.append({
            'timestamp': pd.Timestamp.now().isoformat(),
            'metrics': metrics.to_dict(),
            'num_predictions': len(predictions),
            'num_ground_truth': len(ground_truth)
        })
        
        return metrics
    
    def evaluate_risk_scoring(self,
                             predictions: List[Dict],
                             ground_truth: List[Dict],
                             tolerance: float = 0.2) -> Dict:
        """
        Evaluiert Risiko-Score-Genauigkeit (kontinuierlich 0-1).
        
        Args:
            predictions: [{"event_id": "...", "risk": 0.85, ...}]
            ground_truth: [{"event_id": "...", "true_risk": 0.9, ...}]
            tolerance: Akzeptable Abweichung (±0.2 = korrekt)
        
        Returns:
            Dict mit MAE, RMSE, Within-Tolerance-Rate
        """
        logger.info("Evaluiere Risk-Scoring")
        
        pred_dict = {p["event_id"]: p.get("risk", p.get("anomaly_score", 0)) for p in predictions}
        gt_dict = {g["event_id"]: g.get("true_risk", 0.5) for g in ground_truth}
        
        common_ids = set(pred_dict.keys()) & set(gt_dict.keys())
        
        if not common_ids:
            return {"mae": 1.0, "rmse": 1.0, "within_tolerance": 0.0}
        
        # Berechne Abweichungen
        errors = []
        within_tolerance = 0
        
        for eid in common_ids:
            pred = pred_dict[eid]
            true = gt_dict[eid]
            error = abs(pred - true)
            errors.append(error)
            
            if error <= tolerance:
                within_tolerance += 1
        
        mae = sum(errors) / len(errors)  # Mean Absolute Error
        rmse = (sum(e**2 for e in errors) / len(errors)) ** 0.5  # Root Mean Squared Error
        wt_rate = within_tolerance / len(errors)
        
        return {
            "mae": round(mae, 3),
            "rmse": round(rmse, 3),
            "within_tolerance": round(wt_rate, 3),
            "tolerance_threshold": tolerance
        }
    
    def evaluate_hypothesis_quality(self,
                                    hypotheses: List[str],
                                    ground_truth_hypotheses: List[str]) -> Dict:
        """
        Evaluiert Hypothesen-Qualität (String-Matching).
        
        Args:
            hypotheses: LLM-generierte Hypothesen
            ground_truth_hypotheses: Bekannte korrekte Hypothesen
        
        Returns:
            Dict mit Match-Rate und Overlap
        """
        logger.info(f"Evaluiere {len(hypotheses)} Hypothesen")
        
        # Normalisiere zu Lowercase für Matching
        hyp_lower = [h.lower() for h in hypotheses]
        gt_lower = [g.lower() for g in ground_truth_hypotheses]
        
        # Prüfe Keyword-Overlap
        matches = 0
        for gt in gt_lower:
            # Extrahiere Keywords (simplified)
            keywords = set(gt.split())
            
            for hyp in hyp_lower:
                hyp_keywords = set(hyp.split())
                overlap = len(keywords & hyp_keywords) / len(keywords)
                
                if overlap > 0.5:  # 50% Keyword-Übereinstimmung
                    matches += 1
                    break
        
        match_rate = matches / len(ground_truth_hypotheses) if ground_truth_hypotheses else 0
        
        return {
            "match_rate": round(match_rate, 3),
            "generated_count": len(hypotheses),
            "expected_count": len(ground_truth_hypotheses)
        }
    
    def evaluate_report_completeness(self, report: str) -> Dict:
        """
        Evaluiert Report-Vollständigkeit (Heuristik).
        
        Prüft Vorhandensein von:
        - Executive Summary
        - Timeline/Details
        - Recommendations
        - Evidence/References
        
        Returns:
            Dict mit Completeness-Score (0-1)
        """
        logger.info("Evaluiere Report-Vollständigkeit")
        
        required_sections = {
            "executive_summary": ["executive summary", "summary", "overview"],
            "timeline": ["timeline", "chronological", "sequence of events"],
            "recommendations": ["recommendations", "mitigation", "remediation"],
            "evidence": ["evidence", "ioc", "indicators", "hash", "ip address"]
        }
        
        report_lower = report.lower()
        section_scores = {}
        
        for section, keywords in required_sections.items():
            found = any(kw in report_lower for kw in keywords)
            section_scores[section] = 1.0 if found else 0.0
        
        completeness = sum(section_scores.values()) / len(section_scores)
        
        # Zusätzliche Checks
        word_count = len(report.split())
        has_structure = report.count("#") >= 3  # Markdown-Header
        
        return {
            "completeness_score": round(completeness, 3),
            "sections_present": section_scores,
            "word_count": word_count,
            "has_structure": has_structure,
            "meets_minimum": word_count >= 300 and completeness >= 0.75
        }
    
    def compare_thresholds(self,
                          predictions: List[Dict],
                          ground_truth: List[Dict],
                          thresholds: List[float] = None) -> pd.DataFrame:
        """
        Vergleicht Performance bei verschiedenen Anomalie-Thresholds.
        
        Args:
            predictions: LLM-Predictions mit Scores
            ground_truth: Ground Truth Labels
            thresholds: Liste von Thresholds (default: [0.3, 0.5, 0.7, 0.9])
        
        Returns:
            DataFrame mit Metriken pro Threshold
        """
        if thresholds is None:
            thresholds = [0.3, 0.5, 0.7, 0.9]
        
        logger.info(f"Vergleiche Thresholds: {thresholds}")
        
        results = []
        
        pred_dict = {p["event_id"]: p["anomaly_score"] for p in predictions}
        gt_dict = {g["event_id"]: g["is_anomaly"] for g in ground_truth}
        common_ids = set(pred_dict.keys()) & set(gt_dict.keys())
        
        y_true = [1 if gt_dict[eid] else 0 for eid in common_ids]
        
        for threshold in thresholds:
            y_pred = [1 if pred_dict[eid] >= threshold else 0 for eid in common_ids]
            
            precision = precision_score(y_true, y_pred, zero_division=0)
            recall = recall_score(y_true, y_pred, zero_division=0)
            f1 = f1_score(y_true, y_pred, zero_division=0)
            
            results.append({
                "threshold": threshold,
                "precision": round(precision, 3),
                "recall": round(recall, 3),
                "f1_score": round(f1, 3),
                "predicted_positives": sum(y_pred)
            })
        
        return pd.DataFrame(results)
    
    def plot_confusion_matrix(self,
                             predictions: List[Dict],
                             ground_truth: List[Dict],
                             output_path: Optional[Path] = None):
        """
        Visualisiert Confusion Matrix.
        
        Args:
            predictions: LLM-Predictions
            ground_truth: Ground Truth
            output_path: Pfad zum Speichern (optional)
        """
        pred_dict = {p["event_id"]: p["anomaly_score"] for p in predictions}
        gt_dict = {g["event_id"]: g["is_anomaly"] for g in ground_truth}
        common_ids = set(pred_dict.keys()) & set(gt_dict.keys())
        
        y_true = [1 if gt_dict[eid] else 0 for eid in common_ids]
        y_pred = [1 if pred_dict[eid] >= 0.5 else 0 for eid in common_ids]
        
        cm = confusion_matrix(y_true, y_pred)
        
        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                   xticklabels=['Normal', 'Anomaly'],
                   yticklabels=['Normal', 'Anomaly'])
        plt.xlabel('Predicted')
        plt.ylabel('True')
        plt.title('Confusion Matrix - Anomaly Detection')
        
        if output_path:
            plt.savefig(output_path, dpi=300, bbox_inches='tight')
            logger.info(f"Confusion Matrix gespeichert: {output_path}")
        else:
            plt.show()
        
        plt.close()
    
    def plot_threshold_comparison(self,
                                  df_thresholds: pd.DataFrame,
                                  output_path: Optional[Path] = None):
        """
        Visualisiert Threshold-Comparison.
        
        Args:
            df_thresholds: DataFrame von compare_thresholds()
            output_path: Pfad zum Speichern (optional)
        """
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))
        
        # Plot 1: Precision/Recall/F1 vs Threshold
        ax1.plot(df_thresholds['threshold'], df_thresholds['precision'], 
                marker='o', label='Precision', linewidth=2)
        ax1.plot(df_thresholds['threshold'], df_thresholds['recall'], 
                marker='s', label='Recall', linewidth=2)
        ax1.plot(df_thresholds['threshold'], df_thresholds['f1_score'], 
                marker='^', label='F1-Score', linewidth=2)
        ax1.set_xlabel('Threshold')
        ax1.set_ylabel('Score')
        ax1.set_title('Metrics vs Threshold')
        ax1.legend()
        ax1.grid(True, alpha=0.3)
        
        # Plot 2: Predicted Positives vs Threshold
        ax2.bar(df_thresholds['threshold'], df_thresholds['predicted_positives'], 
               color='steelblue', alpha=0.7)
        ax2.set_xlabel('Threshold')
        ax2.set_ylabel('Predicted Anomalies')
        ax2.set_title('Detection Count vs Threshold')
        ax2.grid(True, alpha=0.3, axis='y')
        
        plt.tight_layout()
        
        if output_path:
            plt.savefig(output_path, dpi=300, bbox_inches='tight')
            logger.info(f"Threshold-Comparison gespeichert: {output_path}")
        else:
            plt.show()
        
        plt.close()
    
    def generate_evaluation_report(self,
                                   metrics: EvaluationMetrics,
                                   risk_eval: Dict,
                                   hyp_eval: Dict,
                                   report_eval: Dict) -> str:
        """
        Generiert zusammenfassenden Evaluations-Report.
        
        Returns:
            Markdown-formatierter Report
        """
        report = f"""# LLM-Agent Evaluation Report

## Anomaly Detection Performance

| Metric | Value |
|--------|-------|
| **Precision** | {metrics.precision:.3f} |
| **Recall** | {metrics.recall:.3f} |
| **F1-Score** | {metrics.f1_score:.3f} |
| **Accuracy** | {metrics.accuracy:.3f} |

### Confusion Matrix
- True Positives: {metrics.true_positives}
- False Positives: {metrics.false_positives}
- True Negatives: {metrics.true_negatives}
- False Negatives: {metrics.false_negatives}

## Risk Scoring Performance

| Metric | Value |
|--------|-------|
| **MAE** | {risk_eval['mae']} |
| **RMSE** | {risk_eval['rmse']} |
| **Within Tolerance ({risk_eval['tolerance_threshold']})** | {risk_eval['within_tolerance']*100:.1f}% |

## Hypothesis Quality

| Metric | Value |
|--------|-------|
| **Match Rate** | {hyp_eval['match_rate']*100:.1f}% |
| **Generated** | {hyp_eval['generated_count']} |
| **Expected** | {hyp_eval['expected_count']} |

## Report Completeness

| Metric | Value |
|--------|-------|
| **Completeness Score** | {report_eval['completeness_score']*100:.1f}% |
| **Word Count** | {report_eval['word_count']} |
| **Structured** | {"✓" if report_eval['has_structure'] else "✗"} |
| **Meets Minimum** | {"✓" if report_eval['meets_minimum'] else "✗"} |

### Sections Present
"""
        for section, present in report_eval['sections_present'].items():
            status = "✓" if present else "✗"
            report += f"- {section.replace('_', ' ').title()}: {status}\n"
        
        report += f"""
---
*Generated: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}*
"""
        
        return report
    
    def export_results(self, output_path: Path):
        """
        Exportiert alle Evaluations-Ergebnisse.
        
        Args:
            output_path: Verzeichnis zum Speichern
        """
        output_path.mkdir(exist_ok=True, parents=True)
        
        # Exportiere History als JSON
        history_file = output_path / "evaluation_history.json"
        with open(history_file, 'w') as f:
            json.dump(self.results_history, f, indent=2)
        
        # Exportiere als CSV
        if self.results_history:
            df = pd.DataFrame([
                {
                    'timestamp': r['timestamp'],
                    **r['metrics']
                }
                for r in self.results_history
            ])
            df.to_csv(output_path / "evaluation_history.csv", index=False)
        
        logger.info(f"Ergebnisse exportiert nach: {output_path}")


# Beispiel-Usage
if __name__ == "__main__":
    # Setup Logging
    logging.basicConfig(level=logging.INFO)
    
    # Beispiel-Daten
    predictions = [
        {"event_id": "evt_001", "anomaly_score": 0.85, "risk": 0.9},
        {"event_id": "evt_002", "anomaly_score": 0.3, "risk": 0.4},
        {"event_id": "evt_003", "anomaly_score": 0.92, "risk": 0.95},
        {"event_id": "evt_004", "anomaly_score": 0.1, "risk": 0.1},
    ]
    
    ground_truth = [
        {"event_id": "evt_001", "is_anomaly": True, "true_risk": 0.9},
        {"event_id": "evt_002", "is_anomaly": False, "true_risk": 0.2},
        {"event_id": "evt_003", "is_anomaly": True, "true_risk": 1.0},
        {"event_id": "evt_004", "is_anomaly": False, "true_risk": 0.1},
    ]
    
    # Evaluiere
    evaluator = LLMEvaluator()
    
    metrics = evaluator.evaluate_anomaly_detection(predictions, ground_truth)
    print(f"\nMetrics: {metrics.to_dict()}")
    
    risk_eval = evaluator.evaluate_risk_scoring(predictions, ground_truth)
    print(f"\nRisk Scoring: {risk_eval}")
    
    # Threshold-Vergleich
    df_thresholds = evaluator.compare_thresholds(predictions, ground_truth)
    print(f"\nThreshold Comparison:\n{df_thresholds}")