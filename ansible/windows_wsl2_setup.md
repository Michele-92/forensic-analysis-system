# Windows — Setup via WSL2

Ansible läuft nicht nativ auf Windows. Diese Anleitung erklärt zwei Wege,
das Forensic Analysis System unter Windows zu installieren.

---

## Option A — WSL2 + Ansible (empfohlen)

WSL2 (Windows Subsystem for Linux) führt ein vollständiges Ubuntu direkt in
Windows aus. Das Ansible-Playbook läuft dann wie auf einem echten Linux-System.

### Schritt 1 — WSL2 installieren

PowerShell als Administrator öffnen und ausführen:

```powershell
wsl --install
```

Danach Windows neu starten. Ubuntu wird automatisch als Standard-Distribution
installiert.

> Falls WSL2 bereits installiert ist, Ubuntu nachinstallieren:
> ```powershell
> wsl --install -d Ubuntu
> ```

### Schritt 2 — Ubuntu in WSL2 öffnen

Im Startmenü **"Ubuntu"** suchen und öffnen. Beim ersten Start Benutzername
und Passwort festlegen.

### Schritt 3 — Ansible installieren

Im Ubuntu-Terminal:

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y ansible python3-pip
```

Version prüfen:
```bash
ansible --version
# → ansible [core 2.x.x]
```

### Schritt 4 — Projektordner öffnen

Windows-Laufwerke sind in WSL2 unter `/mnt/` erreichbar:

```bash
# Beispiel: Projekt liegt unter C:\Users\Name\forensic-analysis-system
cd /mnt/c/Users/Name/forensic-analysis-system

# Aktuellen Pfad anzeigen
pwd
```

> **Tipp:** Im Windows Explorer den Projektordner öffnen, in der Adressleiste
> `wsl` eintippen → WSL2-Terminal öffnet sich direkt im richtigen Verzeichnis.

### Schritt 5 — Playbook ausführen

```bash
ansible-playbook ansible/setup.yml -K
```

`-K` fragt nach dem sudo-Passwort (das in Schritt 2 festgelegte WSL-Passwort).

### Schritt 6 — Anwendung starten

Nach erfolgreichem Playbook drei WSL2-Terminals öffnen:

```bash
# Terminal 1 — Ollama
ollama serve

# Terminal 2 — Backend
source venv/bin/activate
cd backend && uvicorn api:app --reload --host 0.0.0.0 --port 8000

# Terminal 3 — Frontend
cd frontend && bun dev
```

Browser öffnen: **http://localhost:5173**

> WSL2 und Windows teilen sich den Netzwerk-Stack — `localhost` funktioniert
> direkt im Windows-Browser ohne weitere Konfiguration.

---

## Option B — Docker Desktop (einfacher, kein WSL2 nötig)

Falls WSL2 nicht erwünscht ist, funktioniert Docker Desktop als vollständige
Alternative ohne Ansible.

### Schritt 1 — Docker Desktop installieren

[https://www.docker.com/products/docker-desktop/](https://www.docker.com/products/docker-desktop/)

Nach der Installation Windows neu starten.

### Schritt 2 — Anwendung starten

PowerShell oder CMD im Projektordner öffnen:

```powershell
docker compose -f docker/docker-compose.yml up --build -d
```

### Schritt 3 — LLM-Modell laden (einmalig, ~4.7 GB)

```powershell
docker exec -it forensic-ollama ollama pull llama3.1
```

### Schritt 4 — Browser öffnen

**http://localhost:3000**

---

## Vergleich beider Optionen

| Kriterium             | WSL2 + Ansible        | Docker Desktop        |
|-----------------------|-----------------------|-----------------------|
| Installationsaufwand  | Mittel                | Gering                |
| Flexibilität          | Hoch (voller Zugriff) | Mittel (Container)    |
| Performance LLM       | Besser (direkt)       | Etwas langsamer       |
| Entwicklung möglich   | Ja                    | Eingeschränkt         |
| Empfohlen für         | Entwickler            | Schnelle Demo         |

---

## Häufige Probleme unter Windows / WSL2

**`wsl --install` schlägt fehl:**
- Virtualisierung im BIOS aktivieren (Intel VT-x / AMD-V)
- Windows 10 Version 2004+ oder Windows 11 erforderlich

**Playbook findet den Projektordner nicht:**
```bash
# Windows-Pfad C:\Users\Name\... wird zu:
cd /mnt/c/Users/Name/...
```

**Port bereits belegt (Backend startet nicht):**
```bash
# Prozess auf Port 8000 finden und beenden
sudo lsof -i :8000
sudo kill -9 <PID>
```

**Ollama läuft nicht nach WSL2-Neustart:**
```bash
# Ollama manuell starten
ollama serve &
```
