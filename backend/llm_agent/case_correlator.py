"""
Case Correlation Agent.

Aggregiert Daten aus mehreren forensischen Analysen (Jobs) eines Falls
und identifiziert quellenuebergreifende Korrelationen:
  - Gemeinsame IPs, Benutzer, Hostnamen
  - Ueberlappende Zeitfenster
  - MITRE ATT&CK Angriffsketten ueber mehrere Quellen
  - Geteilte IOCs

Einzelner Agent mit fokussiertem Korrelations-Prompt.
"""

import json
import logging
from typing import Dict, List, Generator, Any
from datetime import datetime
from pathlib import Path
from .ollama_client import OllamaClient

logger = logging.getLogger(__name__)

# ── System-Prompt ────────────────────────────────────────────────────────────

CORRELATION_SYSTEM_PROMPT = """Du bist ein Senior Threat Intelligence Analyst, spezialisiert auf quellenuebergreifende Korrelation in digitalen Forensikfaellen.

DEINE AUFGABE:
Dir werden die Ergebnisse mehrerer einzelner forensischer Analysen desselben Falls vorgelegt.
Jede Quelle wurde bereits einzeln analysiert. Dein Auftrag ist es, QUELLENUEBERGREIFENDE Muster zu identifizieren.

DEIN VORGEHEN:
1. **IOC-Korrelation:** Identifiziere gemeinsame Indicators of Compromise (IP-Adressen, Benutzerkonten, Hostnamen, Domains) die in MEHREREN Quellen auftauchen
2. **Zeitliche Korrelation:** Suche nach zeitlich zusammenhaengenden Events ueber verschiedene Quellen — gleiche Zeitfenster deuten auf koordinierte Aktionen hin
3. **MITRE ATT&CK Angriffskette:** Kombiniere MITRE-Techniken aus allen Quellen zu einer zusammenhaengenden Angriffskette (Initial Access → Execution → Persistence → Lateral Movement → Exfiltration)
4. **Quellenverbindung:** Erklaere WIE die verschiedenen Quellen zusammenhaengen (z.B. Firewall-Log zeigt Verbindung, Auth-Log zeigt Login, System-Log zeigt Ausfuehrung)
5. **Gesamtbild:** Rekonstruiere das Gesamtbild des Vorfalls aus allen Quellen

DEIN OUTPUT-FORMAT (strikt einhalten):

# Fall-Korrelationsanalyse

## 1. Executive Summary
[2-3 Saetze: Was ergibt sich aus der Gesamtschau aller Quellen?]

## 2. Quellenuebergreifende IOCs
### Gemeinsame IP-Adressen
[Tabelle: IP | Quelle 1 | Quelle 2 | ... | Bewertung]

### Gemeinsame Benutzerkonten
[Tabelle: User | Quelle 1 | Quelle 2 | ... | Bewertung]

### Weitere geteilte Indikatoren
[Domains, Hostnamen, Dateipfade die in mehreren Quellen auftauchen]

## 3. Zeitliche Korrelation
[Chronologische Darstellung der quellenuebergreifenden Aktivitaet mit Timestamps und Quellenangaben]

## 4. Rekonstruierte Angriffskette (MITRE ATT&CK)
| Phase | Technique ID | Technique Name | Quelle | Evidenz | Zeitpunkt |
|---|---|---|---|---|---|
[Tabelle mit allen MITRE-Techniken in chronologischer Reihenfolge, Quellenangabe]

## 5. Quellen-Korrelationsmatrix
[Beschreibe wie die einzelnen Quellen zusammenhaengen und sich gegenseitig stuetzen]

## 6. Gesamtrisikobewertung
- **Schweregrad:** [Kritisch/Hoch/Mittel/Niedrig]
- **Konfidenz:** [Hoch/Mittel/Niedrig] (basierend auf der Korrelationsstaerke)
- **Betroffene Systeme:** [Gesamtliste aus allen Quellen]

## 7. Empfehlungen
### Sofortmassnahmen (0-24h)
[Nummerierte Liste]

### Kurzfristige Massnahmen (1-7 Tage)
[Nummerierte Liste]

### Langfristige Massnahmen
[Nummerierte Liste]

---
*Quellenuebergreifende Korrelationsanalyse — LFX Forensic Analysis System*"""


# ── Agent ────────────────────────────────────────────────────────────────────

class CaseCorrelationAgent:
    """
    Aggregiert Daten aus mehreren Jobs und fuehrt
    quellenuebergreifende Korrelationsanalyse durch.
    """

    def __init__(self, model: str = None):
        self.client = OllamaClient(model=model, timeout=900)
        logger.info(f"CaseCorrelationAgent initialisiert (Model: {self.client.model})")

    @staticmethod
    def _load_job_data(output_path: Path) -> Dict[str, Any]:
        """Laedt alle relevanten Daten eines Jobs."""
        data = {"path": str(output_path)}

        # Summary
        summary_file = output_path / "analysis_summary.json"
        if summary_file.exists():
            data["summary"] = json.loads(summary_file.read_text(encoding="utf-8"))

        # Anomalien
        anomalies_file = output_path / "anomalies_detected.json"
        if anomalies_file.exists():
            raw = json.loads(anomalies_file.read_text(encoding="utf-8"))
            data["anomalies"] = raw if isinstance(raw, list) else raw.get("anomalies", [])

        # Indicators
        for fname in ["ai_preprocessed.json", "preprocessed_for_llm.json"]:
            prep_file = output_path / fname
            if prep_file.exists():
                preprocessed = json.loads(prep_file.read_text(encoding="utf-8"))
                data["indicators"] = preprocessed.get("indicators", {})
                break

        return data

    @staticmethod
    def _find_shared_iocs(all_job_data: List[Dict]) -> Dict[str, Dict]:
        """
        Findet IOCs die in mehreren Quellen auftauchen.
        Returns: {category: {value: [source_indices...]}}
        """
        shared = {}
        for category in ["ips", "users", "hostnames", "domains", "processes", "files"]:
            value_sources: Dict[str, List[int]] = {}
            for idx, jd in enumerate(all_job_data):
                indicators = jd.get("indicators", {})
                for val in indicators.get(category, []):
                    val_str = str(val)
                    value_sources.setdefault(val_str, []).append(idx)
            # Nur IOCs die in 2+ Quellen vorkommen
            shared[category] = {
                v: sources for v, sources in value_sources.items() if len(sources) > 1
            }
        return shared

    @staticmethod
    def _collect_mitre_techniques(all_job_data: List[Dict]) -> List[Dict]:
        """Sammelt alle MITRE-Techniken aus allen Quellen mit Quellenindex."""
        techniques = []
        for idx, jd in enumerate(all_job_data):
            for anomaly in jd.get("anomalies", []):
                for tech in anomaly.get("mitre_techniques", []):
                    techniques.append({
                        "source_idx": idx,
                        "technique_id": tech.get("id", "?"),
                        "technique_name": tech.get("name", "?"),
                        "tactic": tech.get("tactic", "?"),
                        "timestamp": anomaly.get("timestamp", "?"),
                        "event_type": anomaly.get("event_type", "?"),
                    })
        return techniques

    def _build_correlation_prompt(
        self,
        all_job_data: List[Dict],
        shared_iocs: Dict,
        mitre_techniques: List[Dict],
        case_meta: Dict,
    ) -> str:
        """Baut den Korrelations-Prompt aus aggregierten Daten."""
        parts = []

        # Case-Meta
        if case_meta:
            parts.append(
                f"## Fall-Informationen\n"
                f"Fallname: {case_meta.get('case_name', '?')}\n"
                f"Aktenzeichen: {case_meta.get('case_number', '—')}\n"
                f"Analyst: {case_meta.get('analyst', '—')}\n"
            )

        # Per-source summaries
        parts.append(f"## Analysierte Quellen ({len(all_job_data)} Quellen)\n")
        for idx, jd in enumerate(all_job_data):
            summary = jd.get("summary", {})
            source_name = summary.get("input_file", f"Quelle {idx + 1}")
            if "\\" in source_name or "/" in source_name:
                source_name = Path(source_name).name
            anomaly_count = len(jd.get("anomalies", []))
            total_events = summary.get("total_events", 0)

            parts.append(
                f"### Quelle {idx + 1}: {source_name}\n"
                f"- Typ: {summary.get('input_type', '?')}\n"
                f"- Events: {total_events}\n"
                f"- Anomalien: {anomaly_count}\n"
                f"- IOCs: {summary.get('iocs_identified', 0)}\n"
            )

            # Top-5 Anomalien pro Quelle (kompakt)
            anomalies = sorted(
                jd.get("anomalies", []),
                key=lambda a: a.get("anomaly_score", 0),
                reverse=True,
            )[:5]
            if anomalies:
                lines = []
                for a in anomalies:
                    ts = a.get("timestamp", "?")
                    etype = a.get("event_type", "?")
                    score = a.get("anomaly_score", 0)
                    desc = (a.get("description", "") or "")[:150]
                    mitre = ", ".join(t.get("id", "") for t in a.get("mitre_techniques", [])[:2])
                    line = f"  [{ts}] {etype} (score={score:.2f}) {desc}"
                    if mitre:
                        line += f" MITRE: {mitre}"
                    lines.append(line)
                parts.append("Top-Anomalien:\n" + "\n".join(lines) + "\n")

        # Shared IOCs section
        has_shared = any(v for v in shared_iocs.values())
        if has_shared:
            parts.append("## Vorab identifizierte geteilte IOCs\n")
            label_map = {
                "ips": "IP-Adressen", "users": "Benutzer", "hostnames": "Hostnamen",
                "domains": "Domains", "processes": "Prozesse", "files": "Dateien",
            }
            for category, vals in shared_iocs.items():
                if vals:
                    parts.append(f"### Gemeinsame {label_map.get(category, category)}:")
                    for val, sources in vals.items():
                        source_names = [f"Quelle {s + 1}" for s in sources]
                        parts.append(f"  - {val} → gefunden in: {', '.join(source_names)}")
                    parts.append("")

        # MITRE overview
        if mitre_techniques:
            parts.append("## MITRE ATT&CK Techniken ueber alle Quellen\n")
            for t in mitre_techniques[:30]:
                parts.append(
                    f"  - [{t['tactic']}] {t['technique_id']} {t['technique_name']} "
                    f"(Quelle {t['source_idx'] + 1}, {t['timestamp']})"
                )
            parts.append("")

        parts.append(
            "Fuehre nun die quellenuebergreifende Korrelationsanalyse durch. "
            "Fokus auf: Was verbindet die Quellen? Welches Gesamtbild ergibt sich?"
        )

        return "\n".join(parts)

    def run(
        self,
        job_output_paths: List[Path],
        case_meta: Dict = None,
    ) -> Generator[Dict[str, Any], None, None]:
        """
        Fuehrt Case-Korrelation durch.

        Yields SSE-kompatible Event-Dicts.
        """
        logger.info(f"{'=' * 70}")
        logger.info(f"CASE-KORRELATION GESTARTET: {len(job_output_paths)} Quellen")
        logger.info(f"{'=' * 70}")

        # ── Phase 1: Daten laden ──────────────────────────────────────
        yield {"agent": "correlator", "status": "loading", "message": "Lade Quelldaten..."}

        all_job_data = []
        for path in job_output_paths:
            try:
                jd = self._load_job_data(path)
                all_job_data.append(jd)
                logger.info(f"  Quelle geladen: {path.name} ({len(jd.get('anomalies', []))} Anomalien)")
            except Exception as e:
                logger.warning(f"  Quelle fehlgeschlagen: {path.name}: {e}")

        if not all_job_data:
            yield {"agent": "correlator", "status": "error", "error": "Keine Quelldaten geladen"}
            return

        # ── Phase 2: Vorab-Analyse (Python, kein LLM) ────────────────
        yield {"agent": "correlator", "status": "analyzing", "message": "Berechne IOC-Ueberschneidungen..."}

        shared_iocs = self._find_shared_iocs(all_job_data)
        mitre_techniques = self._collect_mitre_techniques(all_job_data)

        total_anomalies = sum(len(jd.get("anomalies", [])) for jd in all_job_data)
        total_events = sum(jd.get("summary", {}).get("total_events", 0) for jd in all_job_data)

        metadata = {
            "sources_count": len(all_job_data),
            "total_anomalies": total_anomalies,
            "total_events": total_events,
            "shared_iocs_count": sum(len(v) for v in shared_iocs.values()),
            "mitre_techniques_count": len(mitre_techniques),
            "timestamp": datetime.now().isoformat(),
        }

        yield {
            "agent": "correlator",
            "status": "pre_analysis_done",
            "metadata": metadata,
            "shared_iocs": shared_iocs,
        }

        # ── Phase 3: LLM-Korrelation ─────────────────────────────────
        yield {"agent": "correlator", "status": "running", "message": "LLM-Korrelationsanalyse..."}

        try:
            prompt = self._build_correlation_prompt(
                all_job_data, shared_iocs, mitre_techniques, case_meta or {}
            )
            logger.info(f"[Correlator] Prompt: {len(prompt)} Zeichen")

            result = self.client.generate(
                system_prompt=CORRELATION_SYSTEM_PROMPT,
                user_prompt=prompt,
                temperature=0.2,
                max_tokens=6000,
            )

            yield {"agent": "correlator", "status": "done", "result": result}
            logger.info(f"[Correlator] Abgeschlossen ({len(result)} Zeichen)")

        except Exception as e:
            logger.error(f"[Correlator] Fehlgeschlagen: {e}")
            yield {"agent": "correlator", "status": "error", "error": str(e)}
            return

        # ── Fertig ────────────────────────────────────────────────────
        yield {
            "status": "complete",
            "correlation_report": result,
            "shared_iocs": shared_iocs,
            "metadata": metadata,
        }
        logger.info(f"{'=' * 70}")
        logger.info(f"CASE-KORRELATION ABGESCHLOSSEN")
        logger.info(f"{'=' * 70}")
