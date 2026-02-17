import subprocess
import json
import pandas as pd
from dissect.target import Target  # Dissect API
import pytsk3  # Sleuth Kit
from pathlib import Path
import click
import magic  # Für MIME-Typ-Prüfung (pip install python-magic)
import logging
from datetime import datetime

# ============================================================================
# REPARATUR #1: Besseres Logging mit Zeitstempeln & Phasen-Tracking
# ============================================================================
# Logging-Setup für bessere Fehleranalyse mit detailliertem Format
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s.%(msecs)03d | %(levelname)-8s | %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

# Phase-Tracking für Timing
class PhaseTracker:
    """NEUE KLASSE: Verfolgt Phasen der Analyse mit Zeitstempeln."""
    def __init__(self):
        self.phases = {}
        self.start_time = datetime.now()
    
    def start_phase(self, phase_name: str):
        """Markiert Start einer Phase."""
        self.phases[phase_name] = {'start': datetime.now(), 'end': None}
        elapsed = (datetime.now() - self.start_time).total_seconds()
        logger.info(f"[PHASE START] {phase_name} (T+{elapsed:.1f}s)")
    
    def end_phase(self, phase_name: str):
        """Markiert Ende einer Phase."""
        if phase_name in self.phases:
            self.phases[phase_name]['end'] = datetime.now()
            duration = (self.phases[phase_name]['end'] - self.phases[phase_name]['start']).total_seconds()
            elapsed = (datetime.now() - self.start_time).total_seconds()
            logger.info(f"[PHASE END  ] {phase_name} - Dauer: {duration:.1f}s (T+{elapsed:.1f}s)")

@click.command()
@click.argument('input_path', type=click.Path(exists=True, path_type=Path))  # KORRIGIERT: click.Path
@click.option('--output_dir', default='output', type=click.Path(path_type=Path))  # KORRIGIERT: type hinzugefügt
def run_pipeline(input_path: Path, output_dir: Path):
    """
    REPARATUR #2: Überarbeitete Pipeline mit allen Modulen in korrekter Reihenfolge!
    
    Ablauf:
    1. File Detection → Input-Typ erkennen
    2. Dissect Parser → Artefakte extrahieren
    3. Sleuth Kit → Timeline erstellen
    4. Normalizer → Daten vereinheitlichen
    5. Anomaly Detector → ML-basierte Anomalieerkennung
    6. AI Preprocessor → Top-1000 Events filtern
    7. LLM Agent → KI-Analyse & Report-Erstellung
    8. Report speichern → report.md, timeline.csv
    """
    # Initialisierung
    output_dir.mkdir(exist_ok=True, parents=True)  # VERBESSERT: parents=True hinzugefügt
    tracker = PhaseTracker()
    
    # REPARATUR #3: Input-Typ-Erkennung mit detailliertem Logging
    tracker.start_phase("FILE_DETECTION")
    input_type = detect_input_type(input_path)
    logger.info(f"✓ Input-Typ erkannt: {input_type} (Datei: {input_path.name})")
    tracker.end_phase("FILE_DETECTION")
    
    artifacts = []
    timeline = []
    
    # 1. UAC Runner: Nur bei Dumps/Logs/RAM (nicht bei reinen Images)
    # REPARATUR #4: Besseres Logging für UAC-Phase
    if input_type in ['uac_dump', 'logs', 'ram_dump']:
        tracker.start_phase("UAC_PROCESSING")
        try:
            uac_cmd = ['./uac', '-p', 'ir_triage', str(input_path), str(output_dir / 'uac_dump')]
            subprocess.run(uac_cmd, check=True, capture_output=True)
            logger.info("✓ UAC-Dump verarbeitet.")
            # Lade UAC-Output ein (z. B. Bodyfile parsen)
            artifacts.extend(load_uac_artifacts(output_dir / 'uac_dump'))
        except FileNotFoundError:
            logger.warning("⚠ UAC-Tool nicht gefunden. Übersprungen.")
        except Exception as e:
            logger.error(f"✗ UAC-Fehler: {e}")
        tracker.end_phase("UAC_PROCESSING")
    else:
        logger.info("⊘ UAC übersprungen (nicht für Disk-Images geeignet).")
    
    # 2. Dissect Parser: Für Images/Logs (breiteste Abdeckung)
    # REPARATUR #5: Besseres Logging für Dissect-Phase
    if input_type in ['disk_image', 'logs', 'unknown']:
        tracker.start_phase("DISSECT_PARSING")
        try:
            target = Target(str(input_path))
            # REPARATUR #6: Mehr Datenquellen von Dissect nutzen
            for record in target.query('mft'):  # Erweitere: 'eventlogs', 'users' etc.
                artifacts.append({
                    'path': str(record.path),  # VERBESSERT: str() für JSON-Serialisierung
                    'mtime': str(record.mtime) if record.mtime else None,  # VERBESSERT: Timestamp-Konvertierung
                    'hash': getattr(record, 'sha256', None),
                    'source': 'dissect'  # NEU: Datenquelle kennzeichnen
                })
            
            # REPARATUR #7: Speichern mit Logging
            dissect_file = output_dir / 'dissect_artifacts.json'
            with open(dissect_file, 'w') as f:
                json.dump(artifacts, f, indent=2)
            logger.info(f"✓ Dissect: {len(artifacts)} Artefakte extrahiert → {dissect_file.name}")
        except Exception as e:
            logger.error(f"✗ Dissect-Fehler: {e} – Fallback zu Sleuth Kit.")
        tracker.end_phase("DISSECT_PARSING")
    
    # 3. Sleuth Kit Analyzer: Für Images (Timelines)
    # REPARATUR #8: Besseres Logging für Sleuth Kit-Phase
    if input_type == 'disk_image':
        tracker.start_phase("SLEUTH_KIT_ANALYSIS")
        try:
            img_info = pytsk3.Img_Info(str(input_path))
            fs = pytsk3.FS_Info(img_info)
            
            # VERBESSERT: Rekursive Funktion für alle Verzeichnisse
            def walk_directory(directory, path="/"):
                for file_entry in directory:
                    # Überspringe . und ..
                    if file_entry.info.name.name in [b'.', b'..']:
                        continue
                    
                    try:
                        stat = file_entry.info
                        timeline.append({
                            'inode': stat.meta.addr,  # KORRIGIERT
                            'name': (path + file_entry.info.name.name.decode('utf-8', errors='ignore')),  # KORRIGIERT: decode()
                            'mtime': stat.meta.mtime,  # KORRIGIERT
                            'atime': stat.meta.atime,  # VERBESSERT: Access-Zeit hinzugefügt
                            'ctime': stat.meta.ctime,  # VERBESSERT: Change-Zeit hinzugefügt
                            'size': stat.meta.size,  # VERBESSERT: Dateigröße
                            'type': 'file' if stat.meta.type == pytsk3.TSK_FS_META_TYPE_REG else 'dir',  # KORRIGIERT
                            'source': 'sleuthkit'  # REPARATUR #9: Datenquelle kennzeichnen
                        })
                        
                        # Rekursiv in Unterverzeichnisse
                        if stat.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                            try:
                                sub_directory = fs.open_dir(path + file_entry.info.name.name.decode('utf-8', errors='ignore'))
                                walk_directory(sub_directory, path + file_entry.info.name.name.decode('utf-8', errors='ignore') + "/")
                            except:
                                pass
                    except Exception as e:
                        logger.debug(f"Fehler bei Datei: {e}")
                        pass
            
            walk_directory(fs.open_dir('/'))
            df_timeline = pd.DataFrame(timeline)
            sleuth_file = output_dir / 'sleuth_timeline.csv'
            df_timeline.to_csv(sleuth_file, index=False)
            logger.info(f"✓ Sleuth Kit: {len(timeline)} Einträge in Timeline → {sleuth_file.name}")
        except Exception as e:
            logger.error(f"✗ Sleuth Kit-Fehler: {e}")
        tracker.end_phase("SLEUTH_KIT_ANALYSIS")
    
    # 4. Data Normalization: Vereinheitliche Daten zu Standard-Schema
    # REPARATUR #10: Echte Normalisierung mit DataNormalizer Klasse
    tracker.start_phase("DATA_NORMALIZATION")
    from modules.normalizer import DataNormalizer
    
    try:
        normalizer = DataNormalizer()
        
        # Normalisiere Timeline-Events
        normalized_timeline = []
        for event in timeline:
            source = event.get('source', 'unknown')
            normalized_event = normalizer.normalize_timeline_event(event, source)
            normalized_timeline.append(normalized_event)
        
        # Normalisiere Artifacts
        normalized_artifacts = normalizer.normalize_artifacts({
            'dissect': [a for a in artifacts if a.get('source') == 'dissect'],
            'sleuthkit': [a for a in artifacts if a.get('source') == 'sleuthkit'],
            'uac': [a for a in artifacts if a.get('source') == 'uac']
        })
        
        # Speichere normalisierte Daten
        combined = {
            'artifacts': normalized_artifacts,
            'timeline': normalized_timeline,
            'metadata': {
                'input_type': input_type,
                'input': str(input_path),
                'timestamp': pd.Timestamp.now().isoformat(),
                'artifact_count': len(normalized_artifacts),
                'timeline_count': len(normalized_timeline)
            }
        }
        
        normalized_file = output_dir / 'normalized_output.json'
        with open(normalized_file, 'w') as f:
            json.dump(combined, f, indent=2, default=str)
        
        logger.info(f"✓ Normalisierung: {len(normalized_timeline)} Events standardisiert → {normalized_file.name}")
    except Exception as e:
        logger.error(f"✗ Normalisierungs-Fehler: {e}")
        # Fallback: Nutze nicht-normalisierte Daten
        combined = {
            'artifacts': artifacts,
            'timeline': timeline,
            'metadata': {
                'input_type': input_type,
                'input': str(input_path),
                'timestamp': pd.Timestamp.now().isoformat(),
                'artifact_count': len(artifacts),
                'timeline_count': len(timeline)
            }
        }
        normalized_timeline = timeline
    tracker.end_phase("DATA_NORMALIZATION")
    
    # 5. Anomaly Detection: ML-basierte Anomalieerkennung
    # REPARATUR #11: ANOMALY DETECTOR JETZT INTEGRIERT!
    tracker.start_phase("ANOMALY_DETECTION")
    from modules.anomaly_detector import AnomalyDetector
    
    try:
        anomaly_detector = AnomalyDetector(contamination=0.1)
        timeline_with_scores = anomaly_detector.fit_detect(normalized_timeline)
        
        anomaly_count = sum(1 for e in timeline_with_scores if e.get('is_anomaly', False))
        logger.info(f"✓ Anomalieerkennung: {anomaly_count} Anomalien in {len(timeline_with_scores)} Events gefunden")
        
        # Speichere anomale Events
        anomaly_file = output_dir / 'anomalies_detected.json'
        anomalies = [e for e in timeline_with_scores if e.get('is_anomaly', False)]
        with open(anomaly_file, 'w') as f:
            json.dump(anomalies, f, indent=2, default=str)
        logger.info(f"  → {len(anomalies)} anomale Events gespeichert → {anomaly_file.name}")
        
        # Update timeline with anomaly scores
        normalized_timeline = timeline_with_scores
    except Exception as e:
        logger.error(f"✗ Anomalieerkennung-Fehler: {e}")
    tracker.end_phase("ANOMALY_DETECTION")
    
    # 6. AI Preprocessing: Top-1000 Events filtern & extrahieren
    # REPARATUR #12: AI PREPROCESSOR JETZT INTEGRIERT!
    tracker.start_phase("AI_PREPROCESSING")
    from modules.ai_preprocessor import AIPreprocessor
    
    try:
        preprocessor = AIPreprocessor()
        
        # REPARATUR #13: Bereite gefilterte Timeline vor
        filtered_timeline = preprocessor.prepare_timeline_for_llm(
            normalized_timeline,
            max_events=1000,
            focus='suspicious'
        )
        
        # REPARATUR #14: Extrahiere Key-Indikatoren (IPs, Domains, etc.)
        key_indicators = preprocessor.extract_key_indicators(filtered_timeline)
        logger.info(f"✓ AI Preprocessing:")
        logger.info(f"  → {len(filtered_timeline)} verdächtige Events gefiltert")
        logger.info(f"  → IPs: {len(key_indicators['ips'])}, Domains: {len(key_indicators['domains'])}")
        
        # Speichere gefilterte Daten
        preprocessed_file = output_dir / 'preprocessed_for_llm.json'
        with open(preprocessed_file, 'w') as f:
            json.dump({
                'timeline': filtered_timeline,
                'indicators': key_indicators
            }, f, indent=2, default=str)
        logger.info(f"  → Preprocessing-Daten gespeichert → {preprocessed_file.name}")
        
    except Exception as e:
        logger.error(f"✗ AI Preprocessing-Fehler: {e}")
        filtered_timeline = normalized_timeline
        key_indicators = {'ips': [], 'domains': [], 'users': [], 'processes': [], 'files': []}
    tracker.end_phase("AI_PREPROCESSING")
    
    # 7. LLM-Agent: KI-basierte Analyse & Report-Generierung
    # REPARATUR #15: LLM AGENT MIT REPORT-SPEICHERUNG!
    tracker.start_phase("LLM_AGENT_ANALYSIS")
    try:
        from llm_agent.agent import ForensicLLMAgent
        
        agent = ForensicLLMAgent(model="llama3.1", use_rag=True)
        
        # Anomalie-Erkennung durch LLM
        logger.info("  → Starte KI-basierte Anomalieerkennung...")
        llm_anomalies = agent.detect_anomalies(filtered_timeline[:100])  # Top 100 für LLM
        logger.info(f"  → LLM: {len(llm_anomalies)} Anomalien identifiziert")
        
        # Timeline-Interpretation
        logger.info("  → Interpretiere Timeline mit KI...")
        interpretation = agent.interpret_timeline(filtered_timeline, key_indicators.get('ips', []))
        logger.info(f"  → LLM: Timeline interpretiert")
        
        # Report-Generierung
        logger.info("  → Generiere Executive Report...")
        risk_scores = [e.get('anomaly_score', 0) for e in filtered_timeline]
        report = agent.generate_report(llm_anomalies, risk_scores)
        logger.info(f"  → Report generiert ({len(report)} Zeichen)")
        
        # REPARATUR #16: REPORT SPEICHERN!
        report_file = output_dir / 'report.md'
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report)
        logger.info(f"✓ Report gespeichert → {report_file.name}")
        
        # REPARATUR #17: Speichere auch strukturierte Interpretationen
        interpretation_file = output_dir / 'interpretation.json'
        with open(interpretation_file, 'w', encoding='utf-8') as f:
            json.dump(interpretation, f, indent=2, ensure_ascii=False)
        logger.info(f"✓ KI-Interpretation gespeichert → {interpretation_file.name}")
        
    except ImportError as e:
        logger.warning(f"⚠ LLM-Agent nicht verfügbar ({e}). Übersprungen.")
    except Exception as e:
        logger.error(f"✗ LLM-Agent-Fehler: {e}")
    tracker.end_phase("LLM_AGENT_ANALYSIS")
    
    # 8. Export: Erstelle Zusammenfassung & finale Outputs
    # REPARATUR #18: Schließe alle Outputs ab
    tracker.start_phase("EXPORT_FINALIZATION")
    
    try:
        # REPARATUR #19: Erstelle Timeline-CSV mit allen Daten
        if normalized_timeline:
            timeline_csv_file = output_dir / 'timeline.csv'
            df = pd.DataFrame(normalized_timeline)
            df.to_csv(timeline_csv_file, index=False)
            logger.info(f"✓ Timeline-CSV exportiert → {timeline_csv_file.name} ({len(df)} Zeichen)")
        
        # REPARATUR #20: Erstelle Analysis Summary
        summary = {
            'analysis_timestamp': datetime.now().isoformat(),
            'input_file': str(input_path),
            'input_type': input_type,
            'total_events': len(normalized_timeline),
            'anomalies_found': sum(1 for e in normalized_timeline if e.get('is_anomaly', False)),
            'iocs_identified': len(key_indicators.get('ips', [])) + len(key_indicators.get('domains', [])),
            'output_files': [
                'report.md',
                'timeline.csv',
                'anomalies_detected.json',
                'preprocessed_for_llm.json',
                'normalized_output.json',
                'interpretation.json'
            ]
        }
        
        summary_file = output_dir / 'analysis_summary.json'
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        logger.info(f"✓ Analysis-Summary erstellt → {summary_file.name}")
        
    except Exception as e:
        logger.error(f"✗ Export-Fehler: {e}")
    tracker.end_phase("EXPORT_FINALIZATION")
    
    # REPARATUR #21: Finale Zusammenfassung
    total_duration = (datetime.now() - tracker.start_time).total_seconds()
    logger.info("=" * 80)
    logger.info(f"✓✓✓ ANALYSE ABGESCHLOSSEN ✓✓✓")
    logger.info(f"    Gesamtdauer: {total_duration:.1f}s")
    logger.info(f"    Output-Verzeichnis: {output_dir}")
    logger.info(f"    Alle Dateien sind bereit zum Download")
    logger.info("=" * 80)
    
    return combined  # VERBESSERT: Return für API-Integration

def detect_input_type(path: Path) -> str:
    """
    REPARATUR #22: Verbesserte Input-Typ-Erkennung mit detailliertem Logging.
    
    Prüft:
    - Extension
    - MIME-Type (libmagic)
    - Directory-Struktur
    """
    suffix = path.suffix.lower()
    
    # REPARATUR #23: Try-catch für MIME-Erkennung mit besserers Logging
    mime = ""
    try:
        mime = magic.from_file(str(path), mime=True)
        logger.debug(f"MIME-Type: {mime}")
    except Exception as e:
        logger.debug(f"MIME-Erkennung fehlgeschlagen: {e}")
    
    # REPARATUR #24: Strukturierte Extension-Checks mit Logging
    if suffix in ['.dd', '.raw', '.img', '.e01', '.ewf', '.vdi', '.vmdk']:
        logger.debug(f"Erkannt als Disk-Image (Extension: {suffix})")
        return 'disk_image'
    elif suffix in ['.log', '.syslog', '.auth', '.txt']:
        logger.debug(f"Erkannt als Log-Datei (Extension: {suffix})")
        return 'logs'
    elif path.is_dir() and any(f.suffix in ['.yaml', '.json', '.csv'] for f in path.iterdir()):
        logger.debug(f"Erkannt als UAC-Dump (Directory-Struktur)")
        return 'uac_dump'
    elif suffix in ['.mem', '.dump', '.dmp'] or 'memory' in mime:
        logger.debug(f"Erkannt als Memory-Dump (Extension: {suffix} oder MIME: {mime})")
        return 'ram_dump'
    else:
        logger.warning(f"Unbekannter Typ für {path}. Versuche Dissect als Fallback. (Suffix: {suffix})")
        return 'unknown'

def load_uac_artifacts(dump_dir: Path) -> list:
    """
    REPARATUR #25: Loading UAC artifacts mit besserem Logging und Fehlerbehandlung.
    """
    artifacts = []
    try:
        # Beispiel: Bodyfile-Format (TSK)
        bodyfile_path = dump_dir / 'bodyfile.txt'
        if bodyfile_path.exists():
            df = pd.read_csv(bodyfile_path, sep='|', names=['md5', 'name', 'inode', 'mode', 'uid', 'gid', 'size', 'atime', 'mtime', 'ctime', 'crtime'])
            artifacts = df.to_dict('records')
            # REPARATUR #26: Markiere alle UAC-Artifacts mit Source
            for art in artifacts:
                art['source'] = 'uac'
            logger.info(f"✓ UAC: {len(artifacts)} Artefakte aus Bodyfile geladen.")
    except Exception as e:
        logger.error(f"✗ Fehler beim Laden von UAC-Artefakten: {e}")
    return artifacts

# REPARATUR #27: DIESE FUNKTION WURDE ENTFERNT (nicht mehr nötig, da in AI_PREPROCESSOR)
# Die alte prepare_ai_input() function ist nicht mehr nötig, da AIPreprocessor
# diese Funktionalität besser implementiert

if __name__ == '__main__':
    run_pipeline()