"""
LLM Response Data Models.
Pydantic-Models für strukturierte LLM-Outputs.
"""

from pydantic import BaseModel, Field, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class RiskLevel(str, Enum):
    """Risiko-Level."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ConfidenceLevel(str, Enum):
    """Konfidenz-Level."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class AnomalyDetectionResponse(BaseModel):
    """
    Response für Anomalie-Erkennung.
    
    Beispiel:
        {
            "event_id": "evt_001",
            "event": "Root login from 192.168.1.100",
            "timestamp": "2026-02-15T10:30:00",
            "anomaly_score": 0.85,
            "risk_level": "high",
            "explanation": "Root login from unknown IP outside business hours",
            "confidence": "high",
            "indicators": ["unusual_time", "unknown_ip", "root_access"]
        }
    """
    
    event_id: str = Field(..., description="Event-ID aus Timeline")
    event: str = Field(..., description="Event-Beschreibung")
    timestamp: Optional[datetime] = Field(None, description="Event-Zeitstempel")
    
    anomaly_score: float = Field(..., description="Anomalie-Score (0-1)", ge=0, le=1)
    risk_level: RiskLevel = Field(..., description="Risiko-Level")
    
    explanation: str = Field(..., description="Warum ist es anomal?")
    confidence: ConfidenceLevel = Field(default=ConfidenceLevel.MEDIUM, description="Konfidenz")
    
    indicators: List[str] = Field(default_factory=list, description="Anomalie-Indikatoren")
    recommended_actions: List[str] = Field(default_factory=list, description="Empfohlene Aktionen")
    
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Zusätzliche Daten")
    
    class Config:
        use_enum_values = True
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }
    
    @validator('timestamp', pre=True)
    def parse_timestamp(cls, v):
        """Parst Timestamp."""
        if v is None:
            return None
        if isinstance(v, datetime):
            return v
        if isinstance(v, str):
            try:
                return datetime.fromisoformat(v.replace('Z', '+00:00'))
            except:
                return None
        return None


class Hypothesis(BaseModel):
    """
    Einzelne Hypothese.
    
    Beispiel:
        {
            "title": "Persistence via Cron Job",
            "description": "Attacker likely established persistence using scheduled tasks",
            "evidence": ["evt_042", "evt_058"],
            "confidence": "high",
            "mitre_techniques": ["T1053.003"],
            "priority": 1
        }
    """
    
    title: str = Field(..., description="Hypothesen-Titel")
    description: str = Field(..., description="Detaillierte Beschreibung")
    
    evidence: List[str] = Field(default_factory=list, description="Event-IDs als Evidenz")
    confidence: ConfidenceLevel = Field(..., description="Konfidenz-Level")
    
    mitre_techniques: List[str] = Field(default_factory=list, description="MITRE ATT&CK Techniques")
    iocs: List[str] = Field(default_factory=list, description="Indicators of Compromise")
    
    priority: int = Field(..., description="Priorität (1=höchste)", ge=1)
    
    class Config:
        use_enum_values = True


class Finding(BaseModel):
    """
    Einzelner Finding.
    
    Beispiel:
        {
            "finding_id": "find_001",
            "category": "Malware",
            "title": "Unknown Binary in /tmp",
            "description": "Suspicious executable found in temporary directory",
            "severity": "high",
            "evidence": ["evt_001", "evt_002"],
            "recommendation": "Analyze binary with sandbox, check process tree"
        }
    """
    
    finding_id: str = Field(..., description="Finding-ID")
    category: str = Field(..., description="Kategorie (Malware, Persistence, etc.)")
    
    title: str = Field(..., description="Kurztitel")
    description: str = Field(..., description="Detaillierte Beschreibung")
    
    severity: RiskLevel = Field(..., description="Schweregrad")
    
    evidence: List[str] = Field(default_factory=list, description="Event-IDs/Artefakte")
    
    recommendation: str = Field(..., description="Empfohlene Maßnahme")
    
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Zusätzliche Daten")
    
    class Config:
        use_enum_values = True


class TimelineInterpretation(BaseModel):
    """
    Response für Timeline-Interpretation.
    
    Beispiel:
        {
            "summary": "Attack timeline shows initial compromise...",
            "key_events": [
                {"time": "10:00", "description": "Initial SSH login", "relevance": "Entry point"}
            ],
            "hypotheses": [...],
            "top_findings": [...],
            "attack_narrative": "The attacker gained initial access via...",
            "confidence": "high"
        }
    """
    
    summary: str = Field(..., description="Zusammenfassung (3-5 Sätze)")
    
    key_events: List[Dict[str, str]] = Field(
        default_factory=list,
        description="Schlüssel-Events [{time, description, relevance}]"
    )
    
    hypotheses: List[Hypothesis] = Field(default_factory=list, description="Hypothesen")
    top_findings: List[Finding] = Field(default_factory=list, description="Top-Findings")
    
    attack_narrative: Optional[str] = Field(None, description="Angriffs-Narrativ")
    
    confidence: ConfidenceLevel = Field(default=ConfidenceLevel.MEDIUM, description="Gesamt-Konfidenz")
    
    timeline_coverage: Optional[Dict[str, Any]] = Field(
        None,
        description="Zeitabdeckung {start, end, gaps}"
    )
    
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Metadaten")
    
    class Config:
        use_enum_values = True
    
    def get_high_priority_findings(self) -> List[Finding]:
        """Gibt Findings mit HIGH/CRITICAL Severity zurück."""
        return [
            f for f in self.top_findings
            if f.severity in [RiskLevel.HIGH, RiskLevel.CRITICAL]
        ]


class ForensicReport(BaseModel):
    """
    Vollständiger forensischer Report.
    
    Beispiel:
        {
            "report_id": "rep_001",
            "title": "Security Incident Report - 2026-02-15",
            "generated_at": "2026-02-15T12:00:00",
            "executive_summary": "...",
            "timeline_summary": "...",
            "findings": [...],
            "recommendations": [...],
            "iocs": {...},
            "overall_risk": "high",
            "confidence": "high"
        }
    """
    
    report_id: str = Field(..., description="Report-ID")
    title: str = Field(..., description="Report-Titel")
    
    generated_at: datetime = Field(default_factory=datetime.now, description="Generierungszeitpunkt")
    
    executive_summary: str = Field(..., description="Executive Summary (1 Paragraph)")
    timeline_summary: str = Field(..., description="Timeline-Zusammenfassung")
    
    findings: List[Finding] = Field(default_factory=list, description="Alle Findings")
    hypotheses: Optional[List[Hypothesis]] = Field(None, description="Hypothesen")
    
    recommendations: List[str] = Field(default_factory=list, description="Empfehlungen")
    
    iocs: Dict[str, List[str]] = Field(
        default_factory=dict,
        description="IOCs kategorisiert {ips: [...], domains: [...], hashes: [...]}"
    )
    
    overall_risk: RiskLevel = Field(..., description="Gesamt-Risiko")
    confidence: ConfidenceLevel = Field(..., description="Gesamt-Konfidenz")
    
    statistics: Dict[str, Any] = Field(default_factory=dict, description="Statistiken")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Metadaten")
    
    class Config:
        use_enum_values = True
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
    
    def to_markdown(self) -> str:
        """Konvertiert Report zu Markdown."""
        md = f"# {self.title}\n\n"
        md += f"**Generated:** {self.generated_at.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        md += f"**Overall Risk:** {self.overall_risk.upper()}\n\n"
        
        md += "## Executive Summary\n\n"
        md += f"{self.executive_summary}\n\n"
        
        md += "## Timeline Summary\n\n"
        md += f"{self.timeline_summary}\n\n"
        
        if self.findings:
            md += "## Key Findings\n\n"
            for i, finding in enumerate(self.findings, 1):
                md += f"### {i}. [{finding.severity.upper()}] {finding.title}\n\n"
                md += f"{finding.description}\n\n"
                md += f"**Recommendation:** {finding.recommendation}\n\n"
        
        if self.recommendations:
            md += "## Recommendations\n\n"
            for i, rec in enumerate(self.recommendations, 1):
                md += f"{i}. {rec}\n"
            md += "\n"
        
        if self.iocs:
            md += "## Indicators of Compromise (IOCs)\n\n"
            for ioc_type, values in self.iocs.items():
                if values:
                    md += f"**{ioc_type.title()}:**\n"
                    for val in values[:10]:  # Max 10 pro Typ
                        md += f"- `{val}`\n"
                    md += "\n"
        
        md += f"---\n*Confidence Level: {self.confidence}*\n"
        
        return md
    
    def export_markdown(self, filepath: str):
        """Exportiert Report als Markdown-Datei."""
        with open(filepath, 'w') as f:
            f.write(self.to_markdown())


class LLMResponse(BaseModel):
    """
    Generische LLM-Response (Container für verschiedene Response-Typen).
    
    Beispiel:
        {
            "response_id": "resp_001",
            "response_type": "anomaly_detection",
            "model": "llama3.1",
            "generated_at": "2026-02-15T10:00:00",
            "prompt_tokens": 1500,
            "completion_tokens": 500,
            "data": {...}
        }
    """
    
    response_id: str = Field(..., description="Response-ID")
    response_type: str = Field(..., description="Response-Typ (anomaly_detection, interpretation, report)")
    
    model: str = Field(..., description="Verwendetes LLM-Model")
    generated_at: datetime = Field(default_factory=datetime.now, description="Generierungszeitpunkt")
    
    prompt_tokens: Optional[int] = Field(None, description="Anzahl Prompt-Tokens")
    completion_tokens: Optional[int] = Field(None, description="Anzahl Completion-Tokens")
    
    data: Dict[str, Any] = Field(..., description="Eigentliche Response-Daten")
    
    raw_response: Optional[str] = Field(None, description="Raw LLM-Output")
    
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Metadaten")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


# Beispiel-Usage
if __name__ == "__main__":
    # Anomalie-Detektion
    anomaly = AnomalyDetectionResponse(
        event_id="evt_001",
        event="Root SSH login from 192.168.1.100",
        timestamp=datetime.now(),
        anomaly_score=0.85,
        risk_level=RiskLevel.HIGH,
        explanation="Root login from unknown IP at 03:00 AM",
        confidence=ConfidenceLevel.HIGH,
        indicators=["unusual_time", "unknown_ip", "root_access"],
        recommended_actions=["Block IP", "Review SSH logs", "Check for lateral movement"]
    )
    
    print(anomaly.json(indent=2))
    
    # Forensischer Report
    report = ForensicReport(
        report_id="rep_001",
        title="Security Incident - Feb 15 2026",
        executive_summary="Unauthorized access detected via SSH...",
        timeline_summary="Attack timeline spans 6 hours...",
        findings=[
            Finding(
                finding_id="find_001",
                category="Persistence",
                title="Malicious Cron Job",
                description="Suspicious cron job found...",
                severity=RiskLevel.HIGH,
                evidence=["evt_042"],
                recommendation="Remove cron job and investigate origin"
            )
        ],
        recommendations=[
            "Immediately disable compromised accounts",
            "Review all SSH access logs",
            "Implement MFA for SSH"
        ],
        iocs={
            "ips": ["192.168.1.100", "10.0.0.50"],
            "hashes": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
        },
        overall_risk=RiskLevel.HIGH,
        confidence=ConfidenceLevel.HIGH
    )
    
    print("\n" + report.to_markdown())