<h1 align="center">🦞 CatchClaw v5.0.0</h1>

<p align="center">
  <b>Инструмент автоматизированной оценки безопасности для OpenClaw / Open-WebUI AI-платформ</b><br>
  <sub>59 DAG-цепочек атак | 59 Exploit-модулей | ATT&CK-маппинг фаз | Async Tokio-движок | Визуализация графа атак</sub>
</p>

<p align="center">
  <a href="README.md">简体中文</a> ·
  <a href="README_EN.md">English</a> ·
  <a href="README_JA.md">日本語</a> ·
  <a href="README_RU.md"><b>Русский</b></a> ·
  <a href="README_DE.md">Deutsch</a> ·
  <a href="README_FR.md">Français</a>
</p>

<p align="center">
  <a href="https://github.com/Coff0xc/catchclaw/stargazers"><img src="https://img.shields.io/github/stars/Coff0xc/catchclaw?style=flat-square&logo=github&color=gold" alt="Stars"></a>
  <a href="https://github.com/Coff0xc/catchclaw/network/members"><img src="https://img.shields.io/github/forks/Coff0xc/catchclaw?style=flat-square&logo=github&color=silver" alt="Forks"></a>
  <a href="https://github.com/Coff0xc/catchclaw/issues"><img src="https://img.shields.io/github/issues/Coff0xc/catchclaw?style=flat-square&logo=github&color=red" alt="Issues"></a>
  <a href="https://github.com/Coff0xc/catchclaw/commits/master"><img src="https://img.shields.io/github/last-commit/Coff0xc/catchclaw?style=flat-square&logo=github" alt="Last Commit"></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-5.0.0-blue?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/Rust-Edition_2024-DEA584?style=flat-square&logo=rust&logoColor=white" alt="Rust">
  <img src="https://img.shields.io/badge/DAG_Chains-59-FF6B6B?style=flat-square" alt="Chains">
  <img src="https://img.shields.io/badge/Async-Tokio-4CAF50?style=flat-square" alt="Tokio">
  <img src="https://img.shields.io/badge/Exploits-59_Modules-orange?style=flat-square" alt="Exploits">
  <img src="https://img.shields.io/badge/License-Non--Commercial--v2.0-green?style=flat-square" alt="License">
</p>

---

> **⚠️ КОММЕРЧЕСКОЕ ИСПОЛЬЗОВАНИЕ СТРОГО ЗАПРЕЩЕНО**
>
> Лицензировано под **CatchClaw Strict Non-Commercial License v2.0**.
>
> **ЛЮБОЕ коммерческое использование СТРОГО ЗАПРЕЩЕНО без предварительного письменного разрешения правообладателя (Coff0xc).** Нарушители будут привлечены к ответственности.
>
> Запрещённые действия включают, но не ограничиваются:
> - Продажа, сублицензирование или аренда ПО или производных работ
> - Использование ПО для SaaS, услуг пентеста, консалтинга или любых платных услуг
> - Интеграция в коммерческие продукты, платформы или инструменты
> - Обучение коммерческих AI/ML моделей
> - Ребрендинг, перепаковка или white-label дистрибуция
> - Любая деятельность, прямо или косвенно генерирующая доход
>
> **Правообладатель сохраняет право ретроактивного преследования без ограничения срока давности, включая возмещение всей прибыли, судебных расходов и штрафных убытков.**
>
> См. [LICENSE](LICENSE).

---

## Основные возможности

```
┌────────────────────────────────────────────────────────────────────────────┐
│                          CatchClaw v5.0.0                                │
├────────────────────────────────────────────────────────────────────────────┤
│  ● 59 DAG-цепочек атак  ● 59 Exploit-модулей    ● Async Tokio-движок    │
│  ● ATT&CK 9 фаз        ● Mermaid граф атак     ● JSON-отчёты           │
│  ● Топосортировка Кана  ● Semaphore конкуренция ● Условия/Откат         │
├────────────────────────────────────────────────────────────────────────────┤
│  Поверхность атаки: Gateway WS API | HTTP REST | OAuth | Webhook | Node │
│  Покрытие: SSRF | RCE | Кража ключей | Перехват сессий | Эскалация      │
│  Новое: C2 эксфильтрация | Skill отравление | Agent инъекция | MCP      │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## Содержание

- [Обзор](#обзор)
- [Ключевые функции](#ключевые-функции)
- [Установка](#установка)
- [Быстрый старт](#быстрый-старт)
- [Использование CLI](#использование-cli)
- [59 Exploit-модулей](#59-exploit-модулей)
- [Архитектура DAG-цепочек](#архитектура-dag-цепочек)
- [Шаблоны Nuclei](#шаблоны-nuclei)
- [Структура проекта](#структура-проекта)
- [Отказ от ответственности](#отказ-от-ответственности)

---

## Обзор

**CatchClaw** — инструмент автоматизированной оценки безопасности на Rust, разработанный для платформ [OpenClaw](https://github.com/anthropics/open-claw) / Open-WebUI. 59 Exploit-модулей оркестрируются через DAG (направленный ациклический граф) цепочек атак, покрывая полный жизненный цикл ATT&CK от разведки до эксфильтрации данных.

Построен на асинхронном рантайме Tokio. DAG-движок использует топологическую сортировку Кана для поуровневого параллельного выполнения с ограничением конкуренции через Semaphore, условным выполнением и узлами отката. Результаты атак визуализируются как Mermaid-диаграммы.

---

## Ключевые функции

<table>
<tr>
<td width="50%">

### Движок атак

- **59 Exploit-модулей** — 10 категорий, автоматическая регистрация через `inventory`
- **59 DAG-цепочек** — 9 фаз ATT&CK, автоматическая оркестрация
- **Топосортировка Кана** — поуровневое параллельное выполнение с разрешением зависимостей
- **Условия/Откат** — динамический выбор пути на основе предыдущих результатов
- **Визуализация графа** — Mermaid-экспорт со статусами попадания/пропуска/отката

</td>
<td width="50%">

### Поддержка протоколов

- **WebSocket Gateway** — обнаружение challenge-рукопожатия, JSON-RPC вызовы
- **HTTP REST** — отключение редиректов для предотвращения OAuth 302 ложных срабатываний
- **Устранение ложных срабатываний** — challenge-страницы / SPA-фоллбэк / LLM-отказ
- **TLS** — бэкенд rustls, `--tls` для HTTPS/WSS
- **JSON-отчёты** — структурированный вывод с классификацией по серьёзности

</td>
</tr>
</table>

---

## Установка

```bash
git clone https://github.com/Coff0xc/catchclaw.git
cd catchclaw/rust

# Release-сборка (оптимизация + удаление символов)
cargo build --release

# Бинарник: target/release/catchclaw
```

**Требования:** Rust Edition 2024 (rustc 1.85+) | Windows / Linux / macOS

---

## Быстрый старт

```bash
# Список зарегистрированных модулей
catchclaw list

# Полное сканирование
catchclaw scan -t ЦЕЛЬ_IP:ПОРТ

# Сканирование с JSON-отчётом
catchclaw scan -t ЦЕЛЬ_IP:ПОРТ -o report.json

# Сканирование с токеном
catchclaw scan -t ЦЕЛЬ_IP:ПОРТ --token "your-gateway-token"

# Полная цепочка атак
catchclaw exploit -t ЦЕЛЬ_IP:ПОРТ --token xxx

# Одиночный узел цепочки
catchclaw exploit -t ЦЕЛЬ_IP:ПОРТ --chain-id 30
```

---

## Использование CLI

```
CatchClaw v5.0.0 — Инструмент оценки безопасности OpenClaw

Usage: catchclaw <COMMAND>

Commands:
  scan      Полное сканирование (построение DAG → выполнение → сводка)
  exploit   Выполнение цепочек атак (полный DAG или одиночный узел)
  list      Список всех зарегистрированных Exploit-модулей

Scan Flags:
  -t, --target <HOST:PORT>     Адрес цели
      --token <TOKEN>          Токен Gateway (или перем. CATCHCLAWGUARD_TOKEN)
      --timeout <SECS>         Таймаут запроса в секундах (по умолч. 10)
  -o, --output <FILE>          Путь вывода JSON-отчёта
      --concurrency <N>        Макс. параллельных воркеров (по умолч. 10)
      --tls                    Использовать HTTPS/WSS
      --callback <URL>         URL обратного вызова SSRF

Exploit Flags:
  -t, --target <HOST:PORT>     Адрес цели
      --token <TOKEN>          Токен Gateway
      --chain-id <ID>          Запуск одиночного узла цепочки по ID
      --concurrency <N>        Макс. параллельных воркеров (по умолч. 10)
      --tls                    Использовать HTTPS/WSS
```

---

## 59 Exploit-модулей

По фазам ATT&CK и категориям атак:

| Фаза | Кол-во | Ключевые модули |
|------|--------|----------------|
| **Recon** | 6 | cors_bypass, ws_hijack, auth_mode_abuse, log_disclosure, hidden_content, origin_wildcard |
| **Initial Access** | 13 | ssrf, eval_inject, prompt_inject, mcp_inject, pairing_brute, oauth_abuse, responses_exploit, ws_fuzz, acp_bypass, ssrf_rebind, ssrf_proxy_bypass, browser_request, csrf_no_origin |
| **Credential Access** | 5 | apikey_steal, oauth_token_theft, secret_extract, secrets_resolve, talk_secrets |
| **Execution** | 7 | rce, hook_inject, tools_invoke, keychain_cmd_inject, qmd_cmd_inject, exec_race_toctou, exec_socket_leak |
| **Persistence** | 8 | agent_inject, agent_file_inject, channel_inject, skill_poison, cron_bypass, session_file_write, patch_escape, link_template_inject |
| **Privilege Escalation** | 5 | approval_hijack, config_tamper, rogue_node, silent_pair_abuse, auth_disable_leak |
| **Lateral/Exfil** | 15 | session_hijack, transcript_theft, memory_data_leak, c2_exfil, browser_upload_traversal, secret_exec_abuse, bypass_soul, marker_spoof, redact_bypass, obfuscation_bypass, unicode_bypass, ratelimit_scope_bypass, flood_guard_reset, webhook_verify, skill_scanner_bypass |

---

## Архитектура DAG-цепочек

```
                        ┌─────────────────────┐
                        │   Level 0 (Разведка) │
                        │  CORS / WS / Auth    │
                        └─────────┬───────────┘
                                  │
              ┌───────────────────┼───────────────────┐
              ▼                   ▼                   ▼
    ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
    │ Level 1 (Доступ)│ │ Level 1 (Учётн.)│ │ Level 1 (Доступ)│
    │ SSRF / Eval /   │ │ APIKey / OAuth  │ │ Prompt / MCP /  │
    │ Pairing         │ │ Token Theft     │ │ Responses       │
    └────────┬────────┘ └────────┬────────┘ └────────┬────────┘
             │                   │                   │
             └───────────────────┼───────────────────┘
                                 ▼
                   ┌─────────────────────────┐
                   │  Level 2 (Выполнение)   │
                   │  RCE / Hook / Tools     │
                   └────────────┬────────────┘
                                │
                   ┌────────────┼────────────┐
                   ▼                         ▼
         ┌─────────────────┐       ┌─────────────────┐
         │ Level 3 (Перс.) │       │ Level 3 (Эскал.)│
         │ Agent / Cron    │       │ Approval / Node │
         └────────┬────────┘       └────────┬────────┘
                  └────────────┬────────────┘
                               ▼
                  ┌─────────────────────────┐
                  │  Level 4 (Эксфильтр.)   │
                  │  C2 / Transcript / Leak │
                  └─────────────────────────┘
```

**Особенности выполнения:** Топосортировка Кана → поуровневый параллелизм | Semaphore конкуренция | `depends_on` зависимости | `fallback_for` откат | `condition` условия | `AttackGraph` Mermaid-экспорт

---

## Шаблоны Nuclei

`nuclei-templates/` содержит 24 автономных Nuclei-совместимых YAML-шаблонов:

```bash
nuclei -t nuclei-templates/ -u http://ЦЕЛЬ:ПОРТ
nuclei -t nuclei-templates/ -l targets.txt
nuclei -t nuclei-templates/ -u http://ЦЕЛЬ:ПОРТ -severity critical
```

---

## Структура проекта

```
catchclaw/
├── rust/
│   ├── Cargo.toml                 # Конфигурация проекта
│   └── src/
│       ├── main.rs                # Точка входа CLI (clap derive)
│       ├── config/mod.rs          # AppConfig + константы протокола
│       ├── chain/
│       │   ├── dag.rs             # DAG-движок (топосорт + конкуренция + AttackGraph)
│       │   └── chains.rs          # 59 определений узлов цепочек атак
│       ├── exploit/
│       │   ├── registry.rs        # ExploitMeta + система регистрации inventory
│       │   ├── base.rs            # ExploitCtx общий контекст
│       │   └── *.rs               # 59 реализаций Exploit-модулей
│       ├── scan/mod.rs            # Оркестрация полного сканирования
│       ├── report/mod.rs          # Вывод JSON-отчётов
│       └── utils/
│           ├── types.rs           # Target / Finding / Severity / ScanResult
│           ├── http.rs            # HTTP-клиент + фильтры ложных срабатываний
│           └── ws.rs              # GatewayWsClient (WS + обнаружение challenge)
├── nuclei-templates/              # 24 Nuclei YAML-шаблонов
├── scripts/gen_dag_chains.py      # Помощник генерации DAG-цепочек
└── LICENSE                        # CatchClaw Strict Non-Commercial License v2.0
```

---

## Отказ от ответственности

Данный инструмент предназначен **исключительно для авторизованного тестирования безопасности**. Тестируйте только системы, которыми вы владеете или на тестирование которых получили явное письменное разрешение. Несанкционированный доступ к компьютерным системам незаконен. Автор не несёт ответственности за любое злоупотребление.

## Автор

**Coff0xc** — [https://github.com/Coff0xc](https://github.com/Coff0xc)

## Лицензия

[CatchClaw Strict Non-Commercial License v2.0](LICENSE) — Коммерческое использование строго запрещено.
