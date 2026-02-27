# Test-Samples fuer das Forensic Analysis System

## Szenario

Alle Sample-Dateien simulieren einen koordinierten Cyberangriff auf eine kleine Infrastruktur mit drei Systemen:

- **webserver01** (10.0.1.10) - Linux Webserver
- **dbserver02** (10.0.2.20) - Linux Datenbankserver
- **WORKSTATION01** (10.0.1.15) - Windows Arbeitsstation

### Angriffsverlauf (Kill Chain)

1. **Reconnaissance**: Port-Scanning und Web-Enumeration von 185.220.101.34 und 203.0.113.45
2. **Initial Access**: Brute-Force SSH auf webserver01, Web-Admin Login, SQL Injection
3. **Execution**: Encoded PowerShell, wget Malware-Download
4. **Persistence**: Cron-Job, Registry Run Key, Scheduled Task, Backdoor-User
5. **Credential Access**: LSASS Dump, /etc/shadow auslesen
6. **Lateral Movement**: SSH von webserver01 zu dbserver02 mit gestohlenen Credentials
7. **Exfiltration**: Datenkompression und SCP/HTTPS-Transfer zu C2-Server
8. **Defense Evasion**: Log-Clearing, History-Loeschung, Shadow Copy Deletion

### Bekannte IOCs (Indicators of Compromise)

| Typ | Wert | Beschreibung |
|-----|------|-------------|
| IP | 185.220.101.34 | Tor Exit Node / Scanner |
| IP | 203.0.113.45 | Web-Scanner / SQLi |
| IP | 194.26.29.110 | C2-Server (Command & Control) |
| IP | 45.155.205.233 | SSH Brute-Force Quelle |
| IP | 45.33.32.156 | DDoS-Quelle |
| File | /tmp/.cache_update | Malware-Binary |
| File | C:\Users\Public\svchost.exe | Getarnte Malware |
| User | backdoor | Erstellter Backdoor-Account |
| User | hacker | Erstellter Admin-Account |
| Port | 4444 | Reverse Shell Port |

## Dateien

### sample_syslog.log
**Format:** Syslog (Linux)
**Groesse:** ~4 KB
**Inhalt:** Kompromittierung von webserver01 - SSH Brute-Force, Malware-Download, Datenexfiltration, Log-Clearing

**Zum Testen:** Direkt in der Web-Oberflaeche hochladen.

---

### sample_auth.log
**Format:** Auth.log (Linux PAM)
**Groesse:** ~4 KB
**Inhalt:** Kompromittierung von dbserver02 - SSH Brute-Force mit Username-Enumeration, erfolgreicher Root-Login, Backdoor-User-Erstellung, Lateral Movement

**Zum Testen:** Direkt in der Web-Oberflaeche hochladen.

---

### sample_webserver_access.log
**Format:** Apache/Nginx Combined Log
**Groesse:** ~4 KB
**Inhalt:** Web-Angriffe - Admin-Panel Brute-Force, Directory Traversal, SQL Injection, XSS, Remote Code Execution, DDoS

**Zum Testen:** Direkt in der Web-Oberflaeche hochladen.

---

### sample_windows_events.txt
**Format:** Windows Event Log (Text-Export)
**Groesse:** ~5 KB
**Inhalt:** Windows-Kompromittierung - Fehlgeschlagene Logins (4625), PowerShell Execution, User-Erstellung (4720), Privilege Escalation (4732), Registry Persistence, LSASS Dump, Log Clearing (1102)

**Zum Testen:** Direkt in der Web-Oberflaeche hochladen.

---

### sample_firewall.log
**Format:** Firewall-Log (Custom)
**Groesse:** ~2 KB
**Inhalt:** Netzwerk-Sicht des Angriffs - Blockierte Scans, erlaubte C2-Verbindungen, SYN Floods, Datenexfiltration

**Zum Testen:** Direkt in der Web-Oberflaeche hochladen.

---

### sample_combined_timeline.txt
**Format:** Pipe-delimited Timeline (Timestamp|Category|Source|Event|Host|User)
**Groesse:** ~5 KB
**Inhalt:** Korrelierte Timeline aller drei Systeme - zeigt den kompletten Angriffsverlauf chronologisch

**Zum Testen:** Direkt in der Web-Oberflaeche hochladen. Am besten geeignet fuer eine umfassende Analyse.

---

### sample_memory_dump.dmp
**Format:** Simulierter Memory Dump
**Groesse:** ~1 KB
**Inhalt:** Simulierte Prozessliste, Netzwerkverbindungen und verdaechtige Strings aus dem Arbeitsspeicher

**Zum Testen:** Direkt in der Web-Oberflaeche hochladen. Wird als Text-Log verarbeitet.

## Empfohlene Test-Reihenfolge

1. **sample_syslog.log** - Einfachster Test, gut strukturiertes Syslog-Format
2. **sample_auth.log** - Test mit PAM/SSH-spezifischen Logs
3. **sample_webserver_access.log** - Test mit Apache Combined Log Format
4. **sample_windows_events.txt** - Test mit Windows Event Log Format
5. **sample_combined_timeline.txt** - Komplexester Test mit korrelierter Multi-Host-Timeline
6. **sample_firewall.log** - Netzwerk-Perspektive
7. **sample_memory_dump.dmp** - Memory-Analysis-Test

## Echte Forensik-Samples

Fuer realistische Tests mit echten Disk-Images, EVTX-Dateien und PCAP-Captures:

- **Digital Corpora**: https://digitalcorpora.org/
- **DFTT (Digital Forensics Tool Testing)**: http://dftt.sourceforge.net/
- **NIST CFReDS**: https://cfreds.nist.gov/
- **Malware Traffic Analysis**: https://www.malware-traffic-analysis.net/
- **EVTX-ATTACK-SAMPLES**: https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
