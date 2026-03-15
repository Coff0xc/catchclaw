<h1 align="center">🦞 LobsterGuard</h1>

<p align="center">
  <b>Outil d'évaluation de sécurité dédié à OpenClaw</b><br>
  <sub>31 chaînes d'attaque | 23 templates Nuclei | Shell interactif | Découverte d'actifs Shodan/FOFA | Automatisation bout en bout</sub>
</p>

<p align="center">
  <a href="README.md">简体中文</a> ·
  <a href="README_EN.md">English</a> ·
  <a href="README_JA.md">日本語</a> ·
  <a href="README_RU.md">Русский</a> ·
  <a href="README_DE.md">Deutsch</a> ·
  <b>Français</b>
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

## Points forts

```
┌──────────────────────────────────────────────────────────────────────────┐
│                        LobsterGuard v1.0.0                              │
├──────────────────────────────────────────────────────────────────────────┤
│  ● 31 chaînes d'attaque   ● 30 modules Exploit    ● 23 templates Nuclei │
│  ● Shell interactif       ● Découverte Shodan/FOFA ● Rapports JSON+HTML  │
│  ● Couverture WebSocket   ● Fingerprint sans auth  ● Scan multi-cibles   │
├──────────────────────────────────────────────────────────────────────────┤
│  Surface d'attaque: Gateway WS API | HTTP REST | OAuth | Webhook | Node Pairing   │
│  Couverture: SSRF | RCE | Vol de clés | Détournement de session | Élévation de privilèges | Persistance | Fuite de données   │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Table des matières

- [Présentation](#présentation)
- [Fonctionnalités principales](#fonctionnalités-principales)
- [Démarrage rapide](#démarrage-rapide)
- [Utilisation](#utilisation)
- [Shell interactif](#shell-interactif)
- [31 chaînes d'attaque](#31-chaînes-dattaque)
- [Modèles Nuclei](#modèles-nuclei)
- [Découverte d'actifs](#découverte-dactifs)
- [Structure du projet](#structure-du-projet)
- [Avertissement](#avertissement)
- [Auteur](#auteur)
- [Licence](#licence)

---

## Présentation

**LobsterGuard** est un outil de test de pénétration automatisé spécialement conçu pour [OpenClaw](https://github.com/anthropics/open-claw) (plateforme open source d'agent de programmation IA). Il couvre le cycle de vie complet d'une attaque, de la découverte d'actifs à la validation RCE, et teste exhaustivement la sécurité de l'API WebSocket Gateway, des endpoints HTTP et des interfaces d'intégration d'OpenClaw via 31 modules Exploit enchaînés.

### Pourquoi LobsterGuard ?

| Scénario | Test manuel | LobsterGuard |
|----------|-------------|--------------|
| **Découverte de cibles** | Recherche manuelle Shodan/FOFA | `discover` agrégation en un clic |
| **Identification d'instances** | Sondage HTTP un par un | Fingerprint automatique sans authentification |
| **Test d'authentification** | Scripts de brute-force maison | Dictionnaire intégré + délai intelligent |
| **Validation de vulnérabilités** | Construction manuelle de PoC | 31 chaînes de validation automatisée |
| **Couverture de surface d'attaque** | Dépend de l'expérience | WS + HTTP + OAuth + Webhook + Node couverture complète |
| **Génération de rapport** | Compilation manuelle | JSON + HTML en un clic |
| **Intégration CI/CD** | Aucune | 23 templates Nuclei plug-and-play |

---

## Fonctionnalités principales

<table>
<tr>
<td width="50%">

### Reconnaissance et découverte

- **Découverte d'actifs Shodan / FOFA** — Recherche d'instances OpenClaw à l'échelle d'Internet
- **Fingerprint sans authentification** — Détection automatique d'OpenClaw et extraction des informations de version
- **Énumération des endpoints HTTP** — Scan complet des routes REST API
- **Découverte des méthodes WebSocket** — Énumération des méthodes disponibles sur le Gateway WS
- **Détection du mode d'authentification** — Identification des modes no-auth / token / OAuth

</td>
<td width="50%">

### Attaque et exploitation

- **31 chaînes d'attaque** — De SSRF à la chaîne RCE complète
- **Orchestration d'exploitation automatisée** — Chain Orchestrator exécute en séquence
- **RCE auto-approuvé** — exec.approval.request → auto-approbation → node.invoke
- **Vol de clés** — secrets.resolve / talk.config / extraction de clés API
- **Backdoor persistant** — Injection d'agent + écriture de fichiers + contournement Cron

</td>
</tr>
<tr>
<td width="50%">

### Audit de sécurité

- **15+ points d'audit de configuration** — Authentification, permissions, chiffrement, journaux, etc.
- **Brute-force de tokens** — Dictionnaire de mots de passe faibles haute fréquence + dictionnaire personnalisé
- **Détection CORS** — Réflexion d'Origin + validation de fuite de credentials
- **Sécurité OAuth** — Détournement de redirection + attaque de fixation de State

</td>
<td width="50%">

### Outils et rapports

- **Shell interactif** — REPL style msfconsole, exécution chaîne par chaîne
- **23 templates Nuclei** — Intégration directe dans les pipelines CI/CD
- **Rapports JSON + HTML** — Classification par niveau de criticité + recommandations de remédiation
- **Multi-cibles concurrent** — Paramètre `-c` pour contrôler la concurrence

</td>
</tr>
</table>

---

## Démarrage rapide

### Prérequis

- Go 1.22+
- Instance OpenClaw accessible sur le réseau

### Compilation et installation

```bash
git clone https://github.com/Coff0xc/lobster-guard.git
cd lobster-guard
go build -o lobster-guard ./cmd/lobster-guard/
```

### Utilisation de base

```bash
# Scan complet
./lobster-guard scan -t 10.0.0.1:18789

# Scan avec Token
./lobster-guard scan -t 10.0.0.1:18789 --token "your-gateway-token"

# Exploit uniquement
./lobster-guard exploit -t 10.0.0.1:18789 --token "tok"

# Shell interactif
./lobster-guard shell
```

---

## Utilisation

```
Usage:
  lobster-guard [command]

Commands:
  scan          Pipeline complet: fingerprint + auth + brute-force + recon + audit + exploit
  fingerprint   Détection d'instance OpenClaw
  auth          Test d'authentification: détection sans auth + brute-force de token
  recon         Énumération des endpoints + découverte des méthodes WS + détection de version
  audit         Audit de configuration (nécessite un Token)
  exploit       Exécution complète des 31 chaînes d'attaque
  discover      Découverte d'actifs Shodan/FOFA
  shell         Shell interactif (style msfconsole)

Flags:
  -t, --target string     Cible host:port
  -T, --targets string    Fichier de liste de cibles (une par ligne)
  -c, --concurrency int   Nombre de scans concurrents (défaut 1)
  -o, --output string     Chemin de sortie du rapport JSON
      --token string      Gateway Token
      --tls               Utiliser HTTPS/WSS
      --timeout int       Délai d'expiration HTTP en secondes (défaut 10)
```

---

## Shell interactif

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

## 31 chaînes d'attaque

| # | Chaîne d'attaque | Criticité | Description |
|---|------------------|-----------|-------------|
| 0 | Fingerprint de plateforme | Info | Détection OpenClaw sans authentification |
| 1 | SSRF | Critical | browser.request/navigate → métadonnées cloud (AWS/GCP/Azure/DO) |
| 2 | Injection eval() | Critical | Exécution de code eval/exec dans les paramètres d'outils |
| 3 | Vol de clé API | Critical | Extraction de clés API Provider via les endpoints config/env |
| 4 | Brute-force du code de jumelage | High | Brute-force du code de jumelage DM à 6 chiffres |
| 5 | Contournement Cron | High | Contournement de la liste noire Cron + persistance |
| 6 | Injection de prompt | High | Extraction du prompt système + remplacement d'instructions |
| 7 | Accessibilité RCE | Critical | Sondage d'exécution de commandes system.run |
| 8 | Injection de Hook | Critical | Injection de commandes via endpoint Webhook |
| 9 | Extraction de secrets | Critical | secrets.list + secrets.get vol en clair |
| 10 | Falsification de configuration | High | config.set écriture de configuration de sécurité |
| 11 | Invocation directe d'outils | Critical | tools.invoke contournement de la sécurité de la couche Chat |
| 12 | Détournement de session | High | sessions.preview IDOR + injection inter-sessions |
| 13 | Contournement CORS | Medium | Réflexion d'Origin → accès WS/API cross-origin |
| 14 | Injection de canal | High | Injection de commandes non signées Mattermost/Slack/Discord |
| 15 | Fuite de journaux | Medium | logs.query fuite de credentials/données sensibles |
| 16 | Évasion de Patch | Critical | apply_patch traversée de chemin → écriture de fichier arbitraire |
| 17 | Détournement WS | High | Upgrade WebSocket cross-origin + rejeu de Token |
| 18 | Injection d'agent | Critical | agents.create/update backdoor + fuite du prompt système |
| 19 | Abus OAuth | High | Détournement de redirection Slack OAuth + fixation de State |
| 20 | Responses API | Critical | /v1/responses contournement d'auth + injection d'outils |
| 21 | WS Fuzz | Medium | JSON-RPC malformé + injection de méthodes |
| 22 | Injection de fichiers d'agent | Critical | agents.files.set backdoor de prompt persistant |
| 23 | Écriture de fichiers de session | Critical | sessions.patch + compact écriture de fichier arbitraire |
| 24 | Détournement d'approbation | Critical | Correspondance de préfixe d'ID + falsification de politique d'exécution |
| 25 | Clés Talk | Critical | talk.config(includeSecrets) fuite de clés API |
| 26 | SSRF navigateur | High | browser.request dispatch interne |
| 27 | Secrets Resolve | Critical | secrets.resolve extraction en clair (API d'injection interne) |
| 28 | Vol d'historique de session | High | Historique de session non anonymisé + vol de sortie d'outils |
| 29 | Nœud malveillant | Critical | Jumelage de nœud auto-approuvé → interception de commandes |
| 30 | RCE complet | Critical | nodes.list → auto-approbation → node.invoke system.run |

---

## Modèles Nuclei

23 modèles prêts à l'emploi, intégrables directement dans CI/CD :

```bash
# Scanner une cible unique
nuclei -t nuclei-templates/ -u http://10.0.0.1:18789

# Scanner une liste de cibles
nuclei -t nuclei-templates/ -l targets.txt

# Critical uniquement
nuclei -t nuclei-templates/ -u http://target:18789 -severity critical
```

Couverture : détection d'instance, sans authentification, token par défaut, token faible, CORS, exposition de session, approbation d'exécution, Webhook, redirection OAuth, WebSocket, injection Slack/Mattermost/Discord, Responses API, fichiers d'agent, nœud malveillant, résolution de secrets, vol de session, RCE complet, etc.

---

## Découverte d'actifs

```bash
# Shodan
./lobster-guard discover --shodan-key "YOUR_KEY" -o targets.txt

# FOFA
./lobster-guard discover --fofa-email "you@x.com" --fofa-key "KEY" -o targets.txt

# Scanner toutes les cibles découvertes
./lobster-guard scan -T targets.txt -c 10
```

---

## Structure du projet

```
lobster-guard/
├── cmd/lobster-guard/     # Point d'entrée CLI
├── pkg/
│   ├── audit/             # Audit de configuration
│   ├── auth/              # Détection sans auth + brute-force de token
│   ├── chain/             # Orchestrateur de chaînes d'attaque
│   ├── discovery/         # Découverte d'actifs Shodan/FOFA
│   ├── exploit/           # 30 modules Exploit (4500+ lignes)
│   ├── interactive/       # Shell interactif style msfconsole
│   ├── recon/             # Énumération des endpoints + méthodes WS
│   ├── report/            # Génération de rapports JSON + HTML
│   ├── scanner/           # Moteur de fingerprint
│   └── utils/             # Client HTTP, client WS, définitions de types
├── nuclei-templates/      # 23 templates Nuclei YAML
└── rules/                 # Dictionnaires de credentials par défaut
```

---

## Avertissement

Cet outil est destiné uniquement aux **tests de sécurité autorisés**. Ne testez que les systèmes que vous possédez ou pour lesquels vous avez obtenu une autorisation écrite explicite. L'accès non autorisé à des systèmes informatiques est illégal. L'auteur décline toute responsabilité en cas d'utilisation abusive.

## Auteur

**coff0xc**

## Licence

[GPL-3.0](LICENSE)
