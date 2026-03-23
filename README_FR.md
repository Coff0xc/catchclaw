<h1 align="center">🦞 CatchClaw v5.1.0</h1>

<p align="center">
  <b>Outil d'évaluation de sécurité automatisé pour les plateformes OpenClaw / Open-WebUI AI</b><br>
  <sub>59 chaînes d'attaque DAG | 72 modules d'exploit | Mapping de phases ATT&CK | Moteur Async Tokio | Visualisation du graphe d'attaque</sub>
</p>

<p align="center">
  <a href="README.md">简体中文</a> ·
  <a href="README_EN.md">English</a> ·
  <a href="README_JA.md">日本語</a> ·
  <a href="README_RU.md">Русский</a> ·
  <a href="README_DE.md">Deutsch</a> ·
  <a href="README_FR.md"><b>Français</b></a>
</p>

<p align="center">
  <a href="https://github.com/Coff0xc/catchclaw/stargazers"><img src="https://img.shields.io/github/stars/Coff0xc/catchclaw?style=flat-square&logo=github&color=gold" alt="Stars"></a>
  <a href="https://github.com/Coff0xc/catchclaw/network/members"><img src="https://img.shields.io/github/forks/Coff0xc/catchclaw?style=flat-square&logo=github&color=silver" alt="Forks"></a>
  <a href="https://github.com/Coff0xc/catchclaw/issues"><img src="https://img.shields.io/github/issues/Coff0xc/catchclaw?style=flat-square&logo=github&color=red" alt="Issues"></a>
  <a href="https://github.com/Coff0xc/catchclaw/commits/master"><img src="https://img.shields.io/github/last-commit/Coff0xc/catchclaw?style=flat-square&logo=github" alt="Last Commit"></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-5.1.0-blue?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/Rust-Edition_2024-DEA584?style=flat-square&logo=rust&logoColor=white" alt="Rust">
  <img src="https://img.shields.io/badge/DAG_Chains-72-FF6B6B?style=flat-square" alt="Chains">
  <img src="https://img.shields.io/badge/Async-Tokio-4CAF50?style=flat-square" alt="Tokio">
  <img src="https://img.shields.io/badge/Exploits-72_Modules-orange?style=flat-square" alt="Exploits">
  <img src="https://img.shields.io/badge/License-Non--Commercial--v2.0-green?style=flat-square" alt="License">
</p>

---

> **⚠️ UTILISATION COMMERCIALE STRICTEMENT INTERDITE**
>
> Sous licence **CatchClaw Strict Non-Commercial License v2.0**.
>
> **TOUTE utilisation commerciale est STRICTEMENT INTERDITE sans autorisation écrite préalable du détenteur des droits d'auteur (Coff0xc).** Les contrevenants seront poursuivis.
>
> Les activités interdites incluent, sans s'y limiter :
> - Vente, sous-licence ou location du Logiciel ou de ses œuvres dérivées
> - Utilisation du Logiciel pour SaaS, services de pentest, conseil ou tout service payant
> - Intégration dans des produits, plateformes ou outils commerciaux
> - Entraînement de modèles AI/ML commerciaux
> - Rebranding, reconditionnement ou distribution en marque blanche
> - Toute activité générant directement ou indirectement des revenus
>
> **Le détenteur des droits d'auteur se réserve le droit d'application rétroactive SANS limitation de temps, y compris le recouvrement de tous les bénéfices, frais juridiques et dommages punitifs.**
>
> Voir [LICENSE](LICENSE).

---

## Points forts

```
┌────────────────────────────────────────────────────────────────────────────┐
│                          CatchClaw v5.1.0                                │
├────────────────────────────────────────────────────────────────────────────┤
│  ● 72 chaînes DAG       ● 72 modules d'exploit  ● Moteur Async Tokio    │
│  ● ATT&CK 9 phases      ● Graphe Mermaid        ● Rapports JSON/HTML/MD │
│  ● Tri topologique Kahn  ● Semaphore concurrence ● Condition/Fallback    │
│  ● Multi-cibles (CIDR)  ● Scan ports / Découverte● 200+ payloads ext.   │
├────────────────────────────────────────────────────────────────────────────┤
│  Surface d'attaque: Gateway WS API | HTTP REST | OAuth | Webhook | Node  │
│  Couverture: SSRF | RCE | Vol de clés | Détournement de session | Priv.  │
│  Nouveau: Exfiltration C2 | Empoisonnement Skill | Injection Agent | MCP │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## Table des matières

- [Aperçu](#aperçu)
- [Fonctionnalités clés](#fonctionnalités-clés)
- [Installation](#installation)
- [Démarrage rapide](#démarrage-rapide)
- [Utilisation CLI](#utilisation-cli)
- [72 modules d'exploit](#59-modules-dexploit)
- [Architecture des chaînes d'attaque DAG](#architecture-des-chaînes-dattaque-dag)
- [Modèles Nuclei](#modèles-nuclei)
- [Structure du projet](#structure-du-projet)
- [Avertissement](#avertissement)

---

## Aperçu

**CatchClaw** est un outil d'évaluation de sécurité automatisé en Rust, conçu pour les plateformes [OpenClaw](https://github.com/anthropics/open-claw) / Open-WebUI. Il orchestre 72 modules d'exploit via un DAG (Graphe Acyclique Dirigé) de chaînes d'attaque, couvrant le cycle de vie complet ATT&CK de la reconnaissance à l'exfiltration de données.

Construit sur le runtime asynchrone Tokio, le moteur DAG utilise le tri topologique de Kahn pour une exécution parallèle par niveaux avec une concurrence limitée par Semaphore, une exécution conditionnelle et des nœuds de repli. Les résultats d'attaque sont visualisés sous forme de diagrammes Mermaid.

---

## Fonctionnalités clés

<table>
<tr>
<td width="50%">

### Moteur d'attaque

- **72 modules d'exploit** — 10 catégories, auto-enregistrement par macro `inventory`
- **72 chaînes DAG** — 9 phases ATT&CK, orchestration automatisée
- **Tri topologique de Kahn** — Exécution parallèle par niveaux avec résolution des dépendances
- **Nœuds conditionnels/repli** — Décisions de chemin dynamiques basées sur les résultats précédents
- **Visualisation du graphe** — Export Mermaid avec statuts touché/ignoré/repli

</td>
<td width="50%">

### Support des protocoles

- **WebSocket Gateway** — Détection du handshake challenge, appels JSON-RPC
- **HTTP REST** — Redirections désactivées pour éviter les faux positifs OAuth 302
- **Élimination des faux positifs** — Pages challenge / fallback SPA / refus LLM
- **Support TLS** — Backend rustls, `--tls` active HTTPS/WSS
- **Rapports multi-formats** — JSON + HTML (thème sombre) + Markdown

</td>
</tr>
<tr>
<td width="50%">

### Améliorations du scan

- **Scan multi-cibles** — CIDR (/24), plage IP, séparé par virgules, fichier cibles
- **Scan de ports** — TCP connect scan + plages personnalisées
- **Découverte de services** — Empreinte OpenClaw (API/WebSocket/santé)
- **200+ Payloads** — SSRF/Injection/Prompt/Auth/XSS bibliothèque YAML externe
- **Configuration** — Fichier TOML + profils de scan + support proxy

</td>
<td width="50%">

### Expérience CLI

- **`--profile`** — Profils de scan prédéfinis (quick/stealth/full)
- **`--severity-filter`** — Filtrer par niveau de sévérité
- **`--format`** — Format de sortie : json/html/markdown
- **`--dry-run`** — Aperçu du plan DAG sans scanner
- **`--targets-file`** — Fichier de cibles en batch

</td>
</tr>
</table>

---

## Installation

```bash
git clone https://github.com/Coff0xc/catchclaw.git
cd catchclaw/rust

# Build Release (optimisé + symboles supprimés)
cargo build --release

# Binaire: target/release/catchclaw
```

**Prérequis :** Rust Edition 2024 (rustc 1.85+) | Windows / Linux / macOS

---

## Démarrage rapide

```bash
# Lister les modules enregistrés
catchclaw list

# Scan complet
catchclaw scan -t CIBLE_IP:PORT

# Scan avec rapport JSON
catchclaw scan -t CIBLE_IP:PORT -o report.json

# Scan avec jeton d'authentification
catchclaw scan -t CIBLE_IP:PORT --token "your-gateway-token"

# Rapport HTML
catchclaw scan -t CIBLE_IP:PORT -o report.html --format html

# Scan multi-cibles (CIDR)
catchclaw scan --targets "192.168.1.0/24:8080"

# Scan batch depuis fichier
catchclaw scan -f targets.txt -o results.json

# Utiliser un profil
catchclaw scan -t CIBLE_IP:PORT --profile stealth

# Résultats critiques/élevés uniquement
catchclaw scan -t CIBLE_IP:PORT --severity-filter critical,high

# Aperçu du plan d'exécution
catchclaw scan -t CIBLE_IP:PORT --dry-run

# Exécuter la chaîne d'attaque complète
catchclaw exploit -t CIBLE_IP:PORT --token xxx

# Exécuter un seul nœud de chaîne
catchclaw exploit -t CIBLE_IP:PORT --chain-id 30
```

---

## Utilisation CLI

```
CatchClaw v5.1.0 — Outil d'évaluation de sécurité OpenClaw

Usage: catchclaw <COMMAND>

Commands:
  scan      Scan de sécurité complet (construction DAG → exécution → résumé)
  exploit   Exécuter les chaînes d'attaque (DAG complet ou nœud unique)
  list      Lister tous les modules d'exploit enregistrés
  config    Générer ou valider le fichier de configuration

Scan Flags:
  -t, --target <HOST:PORT>     Adresse cible
      --targets <TARGETS>      Multi-cibles (CIDR, plage, séparé par virgules)
  -f, --targets-file <FILE>    Fichier de cibles (une par ligne)
      --token <TOKEN>          Jeton Gateway (ou variable CATCHCLAW_TOKEN)
      --timeout <SECS>         Délai de requête en secondes (défaut 10)
  -o, --output <FILE>          Chemin de sortie du rapport
      --format <FORMAT>        Format de sortie : json/html/markdown (défaut json)
      --profile <PROFILE>      Profil de scan : quick/stealth/full
      --severity-filter <LVL>  Filtrer par sévérité (ex. critical,high)
      --dry-run                Aperçu du plan DAG sans exécution
      --concurrency <N>        Workers parallèles max (défaut 10)
      --tls                    Utiliser HTTPS/WSS
      --callback <URL>         URL de callback SSRF
      --config <FILE>          Fichier de configuration TOML

Exploit Flags:
  -t, --target <HOST:PORT>     Adresse cible
      --token <TOKEN>          Jeton Gateway
      --chain-id <ID>          Exécuter un nœud de chaîne unique par ID
      --concurrency <N>        Workers parallèles max (défaut 10)
      --tls                    Utiliser HTTPS/WSS
```

---

## 72 modules d'exploit

Par phase ATT&CK et catégorie d'attaque :

| Phase | Nombre | Modules clés |
|-------|--------|-------------|
| **Recon** | 6 | cors_bypass, ws_hijack, auth_mode_abuse, log_disclosure, hidden_content, origin_wildcard |
| **Initial Access** | 13 | ssrf, eval_inject, prompt_inject, mcp_inject, pairing_brute, oauth_abuse, responses_exploit, ws_fuzz, acp_bypass, ssrf_rebind, ssrf_proxy_bypass, browser_request, csrf_no_origin |
| **Credential Access** | 5 | apikey_steal, oauth_token_theft, secret_extract, secrets_resolve, talk_secrets |
| **Execution** | 7 | rce, hook_inject, tools_invoke, keychain_cmd_inject, qmd_cmd_inject, exec_race_toctou, exec_socket_leak |
| **Persistence** | 8 | agent_inject, agent_file_inject, channel_inject, skill_poison, cron_bypass, session_file_write, patch_escape, link_template_inject |
| **Privilege Escalation** | 5 | approval_hijack, config_tamper, rogue_node, silent_pair_abuse, auth_disable_leak |
| **Lateral/Exfil** | 15 | session_hijack, transcript_theft, memory_data_leak, c2_exfil, browser_upload_traversal, secret_exec_abuse, bypass_soul, marker_spoof, redact_bypass, obfuscation_bypass, unicode_bypass, ratelimit_scope_bypass, flood_guard_reset, webhook_verify, skill_scanner_bypass |

---

## Architecture des chaînes d'attaque DAG

```
                        ┌─────────────────────┐
                        │  Level 0 (Recon)     │
                        │  CORS / WS / Auth    │
                        └─────────┬───────────┘
                                  │
              ┌───────────────────┼───────────────────┐
              ▼                   ▼                   ▼
    ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
    │ Level 1 (Accès) │ │ Level 1 (Cred.) │ │ Level 1 (Accès) │
    │ SSRF / Eval /   │ │ APIKey / OAuth  │ │ Prompt / MCP /  │
    │ Pairing         │ │ Token Theft     │ │ Responses       │
    └────────┬────────┘ └────────┬────────┘ └────────┬────────┘
             │                   │                   │
             └───────────────────┼───────────────────┘
                                 ▼
                   ┌─────────────────────────┐
                   │  Level 2 (Exécution)    │
                   │  RCE / Hook / Tools     │
                   └────────────┬────────────┘
                                │
                   ┌────────────┼────────────┐
                   ▼                         ▼
         ┌─────────────────┐       ┌─────────────────┐
         │ Level 3 (Persis)│       │ Level 3 (Escal.)│
         │ Agent / Cron    │       │ Approval / Node │
         └────────┬────────┘       └────────┬────────┘
                  └────────────┬────────────┘
                               ▼
                  ┌─────────────────────────┐
                  │  Level 4 (Exfiltr.)     │
                  │  C2 / Transcript / Leak │
                  └─────────────────────────┘
```

**Caractéristiques d'exécution :** Tri topologique de Kahn → parallélisme par niveaux | Concurrence Semaphore | `depends_on` dépendances | `fallback_for` repli | `condition` exécution conditionnelle | `AttackGraph` export Mermaid

---

## Modèles Nuclei

`nuclei-templates/` contient 24 modèles YAML compatibles Nuclei :

```bash
nuclei -t nuclei-templates/ -u http://CIBLE:PORT
nuclei -t nuclei-templates/ -l targets.txt
nuclei -t nuclei-templates/ -u http://CIBLE:PORT -severity critical
```

---

## Structure du projet

```
catchclaw/
├── rust/
│   ├── Cargo.toml                 # Configuration du projet
│   └── src/
│       ├── main.rs                # Point d'entrée CLI (clap derive)
│       ├── config/mod.rs          # AppConfig + profils + constantes
│       ├── chain/
│       │   ├── dag.rs             # Moteur DAG (tri topo + concurrence + AttackGraph)
│       │   └── chains.rs          # 59 définitions de nœuds de chaînes d'attaque
│       ├── exploit/
│       │   ├── registry.rs        # ExploitMeta + système d'enregistrement inventory
│       │   ├── base.rs            # ExploitCtx contexte partagé
│       │   └── *.rs               # 59 implémentations de modules d'exploit
│       ├── scan/mod.rs            # Scan complet + multi-cibles
│       ├── report/mod.rs          # Rapports JSON/HTML/Markdown
│       └── utils/
│           ├── types.rs           # Target / Finding / Severity / ScanResult
│           ├── http.rs            # Client HTTP + filtres de faux positifs
│           ├── ws.rs              # GatewayWsClient (WS + détection challenge)
│           ├── target_parser.rs   # Analyse multi-cibles
│           ├── port_scan.rs       # Scan de ports + découverte OpenClaw
│           ├── payload_registry.rs # PayloadRegistry (chargement YAML + fusion répertoire)
│           └── payload_mutator.rs # Moteur de mutation de payloads
├── payloads/                      # 200+ payloads externes (YAML)
│   ├── ssrf/                      # SSRF: AWS/GCP/Azure/contournement IP
│   ├── command_injection/         # Injection commande/métacaractères shell
│   ├── prompt_injection/          # Injection Prompt/jailbreak
│   ├── auth/                      # Token/header/traversée chemin
│   └── xss/                       # XSS: reflété/événement/contournement filtre
├── nuclei-templates/              # 24 modèles YAML Nuclei
├── scripts/gen_dag_chains.py      # Aide à la génération de chaînes DAG
└── LICENSE                        # CatchClaw Strict Non-Commercial License v2.0
```

---

## Avertissement

Cet outil est destiné **exclusivement aux tests de sécurité autorisés**. Ne testez que les systèmes que vous possédez ou pour lesquels vous disposez d'une autorisation écrite explicite. L'accès non autorisé aux systèmes informatiques est illégal. L'auteur décline toute responsabilité en cas d'utilisation abusive.

## Auteur

**Coff0xc** — [https://github.com/Coff0xc](https://github.com/Coff0xc)

## Licence

[CatchClaw Strict Non-Commercial License v2.0](LICENSE) — Utilisation commerciale strictement interdite.
