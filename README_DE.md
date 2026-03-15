<h1 align="center">🦞 LobsterGuard</h1>

<p align="center">
  <b>Dediziertes Sicherheitsbewertungswerkzeug für OpenClaw</b><br>
  <sub>31 Angriffsketten | 23 Nuclei-Vorlagen | Interaktive Shell | Shodan/FOFA Asset-Erkennung | Vollständige Pipeline-Automatisierung</sub>
</p>

<p align="center">
  <a href="README.md">简体中文</a> ·
  <a href="README_EN.md">English</a> ·
  <a href="README_JA.md">日本語</a> ·
  <a href="README_RU.md">Русский</a> ·
  <a href="README_DE.md"><b>Deutsch</b></a> ·
  <a href="README_FR.md">Français</a>
</p>

<p align="center">
  <a href="https://github.com/Coff0xc/lobster-guard/stargazers"><img src="https://img.shields.io/github/stars/Coff0xc/lobster-guard?style=flat-square&logo=github&color=gold" alt="Stars"></a>
  <a href="https://github.com/Coff0xc/lobster-guard/network/members"><img src="https://img.shields.io/github/forks/Coff0xc/lobster-guard?style=flat-square&logo=github&color=silver" alt="Forks"></a>
  <a href="https://github.com/Coff0xc/lobster-guard/issues"><img src="https://img.shields.io/github/issues/Coff0xc/lobster-guard?style=flat-square&logo=github&color=red" alt="Issues"></a>
  <a href="https://github.com/Coff0xc/lobster-guard/commits/master"><img src="https://img.shields.io/github/last-commit/Coff0xc/lobster-guard?style=flat-square&logo=github" alt="Last Commit"></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-1.0.0-blue?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go">
  <img src="https://img.shields.io/badge/Chains-31-FF6B6B?style=flat-square" alt="Chains">
  <img src="https://img.shields.io/badge/Nuclei-23_Templates-4CAF50?style=flat-square" alt="Nuclei">
  <img src="https://img.shields.io/badge/Exploits-30_Modules-orange?style=flat-square" alt="Exploits">
  <img src="https://img.shields.io/badge/License-GPL--3.0-green?style=flat-square" alt="License">
</p>

---

## Highlights

```
┌──────────────────────────────────────────────────────────────────────────┐
│                        LobsterGuard v1.0.0                              │
├──────────────────────────────────────────────────────────────────────────┤
│  ● 31 Angriffsketten   ● 30 Exploit-Module     ● 23 Nuclei-Vorlagen     │
│  ● Interaktive Shell   ● Shodan/FOFA-Erkennung ● JSON + HTML-Berichte   │
│  ● Volle WebSocket-Ab. ● Null-Auth-Fingerprint ● Multi-Ziel-Nebenläuf.  │
├──────────────────────────────────────────────────────────────────────────┤
│  Angriffsfläche: Gateway WS API | HTTP REST | OAuth | Webhook | Node-Kopplung   │
│  Abdeckung: SSRF | RCE | Schlüsseldiebstahl | Session-Hijack | Privesc | Persist | Datenleck   │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Inhaltsverzeichnis

- [Überblick](#überblick)
- [Kernfunktionen](#kernfunktionen)
- [Schnellstart](#schnellstart)
- [Verwendung](#verwendung)
- [Interaktive Shell](#interaktive-shell)
- [31 Angriffsketten](#31-angriffsketten)
- [Nuclei-Vorlagen](#nuclei-vorlagen)
- [Asset-Erkennung](#asset-erkennung)
- [Projektstruktur](#projektstruktur)
- [Haftungsausschluss](#haftungsausschluss)
- [Autor](#autor)
- [Lizenz](#lizenz)

---

## Überblick

**LobsterGuard** ist ein automatisiertes Penetrationstestwerkzeug, das speziell auf [OpenClaw](https://github.com/anthropics/open-claw) abzielt, die Open-Source-KI-Coding-Agent-Plattform. Es deckt den vollständigen Angriffslebenszyklus von der Asset-Erkennung bis zur RCE-Validierung ab und verwendet 31 verkettete Exploit-Module, um die Sicherheit der OpenClaw Gateway WebSocket API, HTTP-Endpunkte und Integrationsschnittstellen umfassend zu testen.

### Warum LobsterGuard?

| Szenario | Manuelles Testen | LobsterGuard |
|----------|-----------------|-------------|
| **Zielerkennung** | Manuelle Shodan/FOFA-Suche | `discover` Ein-Klick-Aggregation |
| **Instanzidentifikation** | HTTP einzeln sondieren | Null-Auth automatisches Fingerprinting |
| **Auth-Tests** | Eigene Brute-Force-Skripte schreiben | Eingebaute Wortliste + intelligente Verzögerung |
| **Schwachstellenvalidierung** | PoC manuell einzeln erstellen | 31-Ketten automatisierte Validierung |
| **Angriffsflächen-Abdeckung** | Erfahrungsabhängig | WS + HTTP + OAuth + Webhook + Node Vollabdeckung |
| **Berichtsausgabe** | Manuelle Zusammenstellung | JSON + HTML Ein-Klick-Generierung |
| **CI/CD-Integration** | Keine | 23 Nuclei-Vorlagen plug-and-play |

---

## Kernfunktionen

<table>
<tr>
<td width="50%">

### Aufklärung & Erkennung

- **Shodan / FOFA Asset-Erkennung** — Internetweite OpenClaw-Instanzsuche
- **Null-Auth-Fingerprinting** — OpenClaw automatisch erkennen und Versionsinformationen extrahieren
- **HTTP-Endpunkt-Enumeration** — Umfassendes REST-API-Routen-Scanning
- **WebSocket-Methoden-Erkennung** — Verfügbare Gateway-WS-Methoden aufzählen
- **Auth-Modus-Erkennung** — Kein-Auth / Token / OAuth-Modi identifizieren

</td>
<td width="50%">

### Angriff & Exploitation

- **31 Angriffsketten** — Von SSRF bis zu vollständigen RCE-Ketten
- **Automatisierte Exploit-Orchestrierung** — Chain Orchestrator führt sequenziell aus
- **Self-Approve RCE** — exec.approval.request → selbst genehmigen → node.invoke
- **Schlüsseldiebstahl** — secrets.resolve / talk.config / API-Schlüssel-Extraktion
- **Persistente Backdoors** — Agent-Injektion + Datei-Schreiben + Cron-Bypass

</td>
</tr>
<tr>
<td width="50%">

### Sicherheitsaudit

- **15+ Konfigurations-Audit-Punkte** — Auth, Berechtigungen, Verschlüsselung, Protokollierung usw.
- **Token-Brute-Force** — Eingebaute hochfrequente Schwachpasswort-Wortliste + benutzerdefinierte Wortliste
- **CORS-Erkennung** — Origin-Reflexion + Anmeldedaten-Leck-Validierung
- **OAuth-Sicherheit** — Redirect-Hijacking + State-Fixation-Angriffe

</td>
<td width="50%">

### Werkzeuge & Berichte

- **Interaktive Shell** — msfconsole-artiges REPL, kettenweise Ausführung
- **23 Nuclei-Vorlagen** — Direkte CI/CD-Pipeline-Integration
- **JSON + HTML-Berichte** — Schweregrad-Klassifizierung + Behebungsempfehlungen
- **Multi-Ziel-Nebenläufigkeit** — `-c`-Flag steuert die Nebenläufigkeitsanzahl

</td>
</tr>
</table>

---

## Schnellstart

### Voraussetzungen

- Go 1.22+
- Netzwerkerreichbare OpenClaw-Instanz

### Erstellen & Installieren

```bash
git clone https://github.com/Coff0xc/lobster-guard.git
cd lobster-guard
go build -o lobster-guard ./cmd/lobster-guard/
```

### Grundlegende Verwendung

```bash
# Vollständiger Scan
./lobster-guard scan -t 10.0.0.1:18789

# Scan mit Token
./lobster-guard scan -t 10.0.0.1:18789 --token "your-gateway-token"

# Nur Exploit
./lobster-guard exploit -t 10.0.0.1:18789 --token "tok"

# Interaktive Shell
./lobster-guard shell
```

---

## Verwendung

```
Verwendung:
  lobster-guard [Befehl]

Befehle:
  scan          Vollständige Pipeline: Fingerprint + Auth + Brute-Force + Recon + Audit + Exploit
  fingerprint   OpenClaw-Instanz erkennen
  auth          Auth-Tests: Kein-Auth-Erkennung + Token-Brute-Force
  recon         Endpunkt-Enumeration + WS-Methoden-Erkennung + Versionserkennung
  audit         Konfigurationsaudit (Token erforderlich)
  exploit       Alle 31 Angriffsketten ausführen
  discover      Shodan/FOFA Asset-Erkennung
  shell         Interaktive Shell (msfconsole-Stil)

Flags:
  -t, --target string     Ziel-Host:Port
  -T, --targets string    Ziel-Listendatei (eine pro Zeile)
  -c, --concurrency int   Gleichzeitige Scan-Anzahl (Standard 1)
  -o, --output string     JSON-Berichts-Ausgabepfad
      --token string      Gateway-Token
      --tls               HTTPS/WSS verwenden
      --timeout int       HTTP-Timeout in Sekunden (Standard 10)
```

---

## Interaktive Shell

```
$ ./lobster-guard shell

LobsterGuard interactive shell. Type 'help' for commands.
lobster🦞> target 10.0.0.1:18789
[*] Target set: 10.0.0.1:18789
lobster🦞> token my-gateway-token
[*] Token set: my-...ken
lobster🦞> chain 30
[*] Running chain 30: Full RCE chain (self-approve + node.invoke)
lobster🦞> exploit
[*] ═══ OpenClaw Attack Chain Orchestration ═══
lobster🦞> chains
Chain  0: Platform fingerprint (zero-auth)
Chain  1: SSRF + cloud metadata
...
Chain 30: Full RCE chain (self-approve + node.invoke)
lobster🦞> results
lobster🦞> export report.json
```

---

## 31 Angriffsketten

| # | Angriffskette | Schweregrad | Beschreibung |
|---|---------------|-------------|--------------|
| 0 | Plattform-Fingerprint | Info | Null-Auth OpenClaw-Erkennung |
| 1 | SSRF | Critical | browser.request/navigate → Cloud-Metadaten (AWS/GCP/Azure/DO) |
| 2 | eval()-Injektion | Critical | eval/exec-Codeausführung über Werkzeugparameter |
| 3 | API-Schlüssel-Diebstahl | Critical | Provider-API-Schlüssel über config/env-Endpunkte extrahieren |
| 4 | Pairing-Code-Brute-Force | High | DM-Pairing-Code 6-stelliger Brute-Force |
| 5 | Cron-Bypass | High | Cron-Blacklist-Bypass + Persistenz |
| 6 | Prompt-Injektion | High | System-Prompt-Extraktion + Anweisungsüberschreibung |
| 7 | RCE-Erreichbarkeit | Critical | system.run-Befehlsausführungs-Sondierung |
| 8 | Hook-Injektion | Critical | Webhook-Endpunkt-Injektion zur Befehlsausführung |
| 9 | Schlüsselextraktion | Critical | secrets.list + secrets.get Klartext-Diebstahl |
| 10 | Konfigurations-Tampering | High | config.set schreibt Sicherheitskonfigurationen |
| 11 | Direkter Werkzeugaufruf | Critical | tools.invoke umgeht Chat-Layer-Sicherheit |
| 12 | Session-Hijacking | High | sessions.preview IDOR + Cross-Session-Injektion |
| 13 | CORS-Bypass | Medium | Origin-Reflexion → Cross-Origin WS/API-Zugriff |
| 14 | Kanal-Injektion | High | Mattermost/Slack/Discord unsignierte Befehlsinjektion |
| 15 | Log-Leak | Medium | logs.query Anmeldedaten/Sensitivdaten-Exposition |
| 16 | Patch-Escape | Critical | apply_patch Pfad-Traversal → beliebiges Datei-Schreiben |
| 17 | WS-Hijacking | High | Cross-Origin WebSocket-Upgrade + Token-Replay |
| 18 | Agent-Injektion | Critical | agents.create/update Backdoor + System-Prompt-Leak |
| 19 | OAuth-Missbrauch | High | Slack OAuth Redirect-Hijacking + State-Fixation |
| 20 | Responses API | Critical | /v1/responses Auth-Bypass + Werkzeug-Injektion |
| 21 | WS-Fuzz | Medium | Missgeformtes JSON-RPC + Methoden-Injektion |
| 22 | Agent-Datei-Injektion | Critical | agents.files.set persistente Prompt-Backdoor |
| 23 | Session-Datei-Schreiben | Critical | sessions.patch + compact beliebiges Datei-Schreiben |
| 24 | Approval-Hijacking | Critical | Präfix-ID-Matching + Ausführungsrichtlinien-Tampering |
| 25 | Talk-Schlüssel | Critical | talk.config(includeSecrets) API-Schlüssel-Exfiltration |
| 26 | Browser-SSRF | High | browser.request internes Routing |
| 27 | Secrets Resolve | Critical | secrets.resolve Klartext-Extraktion (interne Injektions-API) |
| 28 | Session-Aufzeichnungsdiebstahl | High | Nicht-anonymisierte Session-Historie + Werkzeugausgabe-Diebstahl |
| 29 | Rogue Node | Critical | Self-Approve Node-Kopplung → Befehlsabfang |
| 30 | Vollständige RCE | Critical | nodes.list → selbst genehmigen → node.invoke system.run |

---

## Nuclei-Vorlagen

23 sofort einsatzbereite Vorlagen, direkt in CI/CD integrierbar:

```bash
# Einzelnes Ziel scannen
nuclei -t nuclei-templates/ -u http://10.0.0.1:18789

# Zielliste scannen
nuclei -t nuclei-templates/ -l targets.txt

# Nur Critical
nuclei -t nuclei-templates/ -u http://target:18789 -severity critical
```

Abdeckung: Instanzerkennung, Kein-Auth, Standard-Token, schwache Token, CORS, Session-Exposition, Ausführungsgenehmigung, Webhook, OAuth-Redirect, WebSocket, Slack/Mattermost/Discord-Injektion, Responses API, Agent-Dateien, Rogue Node, Secrets-Auflösung, Session-Diebstahl, vollständige RCE und mehr.

---

## Asset-Erkennung

```bash
# Shodan
./lobster-guard discover --shodan-key "YOUR_KEY" -o targets.txt

# FOFA
./lobster-guard discover --fofa-email "you@x.com" --fofa-key "KEY" -o targets.txt

# Alle gefundenen Ziele scannen
./lobster-guard scan -T targets.txt -c 10
```

---

## Projektstruktur

```
lobster-guard/
├── cmd/lobster-guard/     # CLI-Einstiegspunkt
├── pkg/
│   ├── audit/             # Konfigurationsaudit
│   ├── auth/              # Kein-Auth-Erkennung + Token-Brute-Force
│   ├── chain/             # Angriffsketten-Orchestrator
│   ├── discovery/         # Shodan/FOFA Asset-Erkennung
│   ├── exploit/           # 30 Exploit-Module (4500+ Zeilen)
│   ├── interactive/       # msfconsole-artige interaktive Shell
│   ├── recon/             # Endpunkt + WS-Methoden-Enumeration
│   ├── report/            # JSON + HTML Berichtsgenerierung
│   ├── scanner/           # Fingerprinting-Engine
│   └── utils/             # HTTP-Client, WS-Client, Typdefinitionen
├── nuclei-templates/      # 23 Nuclei-YAML-Vorlagen
└── rules/                 # Standard-Anmeldedaten-Wortlisten
```

---

## Haftungsausschluss

Dieses Werkzeug ist ausschließlich für **autorisierte Sicherheitstests** bestimmt. Führen Sie Tests nur an Systemen durch, die Sie besitzen oder für die Sie eine ausdrückliche schriftliche Genehmigung haben. Unbefugter Zugriff auf Computersysteme ist illegal. Der Autor übernimmt keine Verantwortung für Missbrauch.

## Autor

**coff0xc**

## Lizenz

[GPL-3.0](LICENSE)
