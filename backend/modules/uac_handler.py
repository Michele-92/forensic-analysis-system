"""
UAC (Unix-like Artifacts Collector) Handler.
Wrapper für UAC-Tool zur Artefakt-Sammlung.
"""

import subprocess
import logging
from pathlib import Path
from typing import List, Dict, Optional
import json
import pandas as pd

logger = logging.getLogger(__name__)


class UACHandler:
    """Verwaltet UAC-Integration für Artefakt-Sammlung."""
    
    def __init__(self, uac_path: Path = None):
        """
        Args:
            uac_path: Pfad zum UAC-Binary (default: ./tools/uac/uac)
        """
        if uac_path is None:
            uac_path = Path(__file__).parent.parent.parent / "tools" / "uac" / "uac"
        
        self.uac_path = uac_path
        
        if not self.uac_path.exists():
            logger.warning(f"UAC-Binary nicht gefunden: {self.uac_path}")
    
    def run_collection(self, 
                      input_path: Path, 
                      output_dir: Path,
                      profile: str = "ir_triage") -> bool:
        """
        Führt UAC-Collection aus.
        
        Args:
            input_path: Pfad zum Ziel (Dump/Live-System)
            output_dir: Output-Verzeichnis
            profile: UAC-Profil (ir_triage, full, etc.)
        
        Returns:
            True bei Erfolg, False bei Fehler
        """
        if not self.uac_path.exists():
            logger.error("UAC nicht verfügbar")
            return False
        
        output_dir.mkdir(exist_ok=True, parents=True)
        
        cmd = [
            str(self.uac_path),
            '-p', profile,
            str(input_path),
            str(output_dir)
        ]
        
        try:
            logger.info(f"Starte UAC-Collection: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
                timeout=600  # 10 Minuten Timeout
            )
            
            logger.info(f"UAC erfolgreich: {output_dir}")
            logger.debug(f"UAC Output: {result.stdout}")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"UAC-Fehler: {e.stderr}")
            return False
        except subprocess.TimeoutExpired:
            logger.error("UAC-Timeout nach 10 Minuten")
            return False
        except Exception as e:
            logger.error(f"Unerwarteter UAC-Fehler: {e}")
            return False
    
    def parse_bodyfile(self, bodyfile_path: Path) -> List[Dict]:
        """
        Parst UAC-Bodyfile (TSK-Format).
        
        Bodyfile-Format:
        MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime
        
        Args:
            bodyfile_path: Pfad zur Bodyfile
        
        Returns:
            Liste von Artefakt-Dicts
        """
        if not bodyfile_path.exists():
            logger.warning(f"Bodyfile nicht gefunden: {bodyfile_path}")
            return []
        
        try:
            df = pd.read_csv(
                bodyfile_path,
                sep='|',
                names=['md5', 'name', 'inode', 'mode', 'uid', 'gid', 
                       'size', 'atime', 'mtime', 'ctime', 'crtime'],
                on_bad_lines='skip'
            )
            
            artifacts = df.to_dict('records')
            logger.info(f"Bodyfile geparst: {len(artifacts)} Einträge")
            return artifacts
            
        except Exception as e:
            logger.error(f"Fehler beim Parsen des Bodyfile: {e}")
            return []
    
    def parse_artifacts(self, output_dir: Path) -> Dict[str, List[Dict]]:
        """
        Parst alle UAC-Outputs.
        
        Args:
            output_dir: UAC-Output-Verzeichnis
        
        Returns:
            Dict mit kategorisierten Artefakten
        """
        artifacts = {
            'bodyfile': [],
            'logs': [],
            'configs': [],
            'other': []
        }
        
        # Parse Bodyfile
        bodyfile = output_dir / 'bodyfile.txt'
        if bodyfile.exists():
            artifacts['bodyfile'] = self.parse_bodyfile(bodyfile)
        
        # Parse Logs (vereinfacht)
        logs_dir = output_dir / 'logs'
        if logs_dir.exists():
            for log_file in logs_dir.glob('*.log'):
                try:
                    with open(log_file) as f:
                        artifacts['logs'].append({
                            'filename': log_file.name,
                            'content': f.read()
                        })
                except:
                    pass
        
        # Parse Configs
        config_dir = output_dir / 'configs'
        if config_dir.exists():
            for config_file in config_dir.glob('*'):
                try:
                    with open(config_file) as f:
                        artifacts['configs'].append({
                            'filename': config_file.name,
                            'content': f.read()
                        })
                except:
                    pass
        
        logger.info(f"UAC-Artefakte geparst: {sum(len(v) for v in artifacts.values())} gesamt")
        return artifacts
    
    def extract_iocs(self, artifacts: Dict[str, List[Dict]]) -> List[Dict]:
        """
        Extrahiert IOCs aus UAC-Artefakten.
        
        Args:
            artifacts: Geparste UAC-Artefakte
        
        Returns:
            Liste von IOCs (IPs, Domains, Hashes, etc.)
        """
        import re
        
        iocs = []
        
        # Regex-Patterns
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
        hash_pattern = r'\b[a-fA-F0-9]{32,64}\b'
        
        # Durchsuche Logs
        for log in artifacts.get('logs', []):
            content = log.get('content', '')
            
            # IPs
            for ip in re.findall(ip_pattern, content):
                if not ip.startswith(('127.', '192.168.', '10.', '172.')):  # Privat-IPs ausschließen
                    iocs.append({'type': 'ip', 'value': ip, 'source': log['filename']})
            
            # Domains
            for domain in re.findall(domain_pattern, content):
                if '.' in domain and not domain.startswith('localhost'):
                    iocs.append({'type': 'domain', 'value': domain, 'source': log['filename']})
            
            # Hashes
            for hash_val in re.findall(hash_pattern, content):
                iocs.append({'type': 'hash', 'value': hash_val, 'source': log['filename']})
        
        # Dedupliziere
        seen = set()
        unique_iocs = []
        for ioc in iocs:
            key = (ioc['type'], ioc['value'])
            if key not in seen:
                seen.add(key)
                unique_iocs.append(ioc)
        
        logger.info(f"IOCs extrahiert: {len(unique_iocs)}")
        return unique_iocs