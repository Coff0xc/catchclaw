<h1 align="center">🦞 LobsterGuard</h1>

<p align="center">
  <b>Специализированный инструмент оценки безопасности для OpenClaw</b><br>
  <sub>31 цепочка атак | 23 шаблона Nuclei | Интерактивная оболочка | Обнаружение активов Shodan/FOFA | Полная автоматизация пайплайна</sub>
</p>

<p align="center">
  <a href="README.md">简体中文</a> ·
  <a href="README_EN.md">English</a> ·
  <a href="README_JA.md">日本語</a> ·
  <b>Русский</b> ·
  <a href="README_DE.md">Deutsch</a> ·
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

## Основные возможности

```
┌──────────────────────────────────────────────────────────────────────────┐
│                        LobsterGuard v1.0.0                              │
├──────────────────────────────────────────────────────────────────────────┤
│  ● 31 цепочка атак     ● 30 модулей эксплойтов  ● 23 шаблона Nuclei    │
│  ● Интерактивная оболочка  ● Поиск Shodan/FOFA  ● Отчёты JSON + HTML   │
│  ● Полное покрытие WS  ● Фингерпринт без авторизации  ● Многопоточность │
├──────────────────────────────────────────────────────────────────────────┤
│  Поверхность атаки: Gateway WS API | HTTP REST | OAuth | Webhook | Сопряжение узлов   │
│  Покрытие: SSRF | RCE | Кража ключей | Перехват сессий | Повышение привилегий | Персистентность | Утечка данных   │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Содержание

- [Обзор](#обзор)
- [Ключевые функции](#ключевые-функции)
- [Быстрый старт](#быстрый-старт)
- [Использование](#использование)
- [Интерактивная оболочка](#интерактивная-оболочка)
- [31 цепочка атак](#31-цепочка-атак)
- [Шаблоны Nuclei](#шаблоны-nuclei)
- [Обнаружение активов](#обнаружение-активов)
- [Структура проекта](#структура-проекта)
- [Отказ от ответственности](#отказ-от-ответственности)
- [Автор](#автор)
- [Лицензия](#лицензия)

---

## Обзор

**LobsterGuard** — автоматизированный инструмент пентестинга, специально разработанный для [OpenClaw](https://github.com/anthropics/open-claw) — платформы AI-агента для написания кода с открытым исходным кодом. Охватывает полный жизненный цикл атаки: от обнаружения активов до валидации RCE. Использует 31 связанный модуль эксплойтов для комплексного тестирования безопасности Gateway WebSocket API, HTTP-эндпоинтов и интеграционных интерфейсов OpenClaw.

### Почему LobsterGuard?

| Сценарий | Ручное тестирование | LobsterGuard |
|----------|---------------------|--------------|
| **Обнаружение целей** | Ручной поиск Shodan/FOFA | Агрегация одним кликом `discover` |
| **Идентификация экземпляра** | Поочерёдный опрос HTTP | Автоматический фингерпринт без авторизации |
| **Тестирование аутентификации** | Написание собственных скриптов брутфорса | Встроенный словарь + умная задержка |
| **Валидация уязвимостей** | Ручное создание PoC по одному | Автоматическая валидация 31 цепочкой |
| **Покрытие поверхности атаки** | Зависит от опыта | Полное покрытие WS + HTTP + OAuth + Webhook + Node |
| **Вывод отчётов** | Ручная компиляция | Генерация JSON + HTML одним кликом |
| **Интеграция CI/CD** | Отсутствует | 23 шаблона Nuclei, готовые к использованию |

---

## Ключевые функции

<table>
<tr>
<td width="50%">

### Разведка и обнаружение

- **Обнаружение активов Shodan / FOFA** — Поиск экземпляров OpenClaw в интернете
- **Фингерпринт без авторизации** — Автоопределение OpenClaw и извлечение информации о версии
- **Перечисление HTTP-эндпоинтов** — Комплексное сканирование маршрутов REST API
- **Обнаружение методов WebSocket** — Перечисление доступных методов Gateway WS
- **Определение режима аутентификации** — Выявление режимов без авторизации / токен / OAuth

</td>
<td width="50%">

### Атака и эксплуатация

- **31 цепочка атак** — От SSRF до полных цепочек RCE
- **Автоматическая оркестрация эксплойтов** — Chain Orchestrator выполняет последовательно
- **Self-Approve RCE** — exec.approval.request → самоодобрение → node.invoke
- **Кража ключей** — secrets.resolve / talk.config / извлечение API-ключей
- **Персистентные бэкдоры** — Инъекция агента + запись файлов + обход Cron

</td>
</tr>
<tr>
<td width="50%">

### Аудит безопасности

- **15+ пунктов аудита конфигурации** — Аутентификация, права доступа, шифрование, логирование и др.
- **Брутфорс токенов** — Встроенный словарь слабых паролей высокой частоты + пользовательский словарь
- **Обнаружение CORS** — Отражение Origin + валидация утечки учётных данных
- **Безопасность OAuth** — Перехват редиректа + атаки фиксации State

</td>
<td width="50%">

### Инструменты и отчётность

- **Интерактивная оболочка** — REPL в стиле msfconsole, пошаговое выполнение цепочек
- **23 шаблона Nuclei** — Прямая интеграция в CI/CD пайплайн
- **Отчёты JSON + HTML** — Классификация по критичности + рекомендации по устранению
- **Многопоточность** — Флаг `-c` управляет количеством потоков

</td>
</tr>
</table>

---

## Быстрый старт

### Требования

- Go 1.22+
- Доступный по сети экземпляр OpenClaw

### Сборка и установка

```bash
git clone https://github.com/Coff0xc/lobster-guard.git
cd lobster-guard
go build -o lobster-guard ./cmd/lobster-guard/
```

### Базовое использование

```bash
# Полное сканирование
./lobster-guard scan -t 10.0.0.1:18789

# Сканирование с токеном
./lobster-guard scan -t 10.0.0.1:18789 --token "your-gateway-token"

# Только эксплуатация
./lobster-guard exploit -t 10.0.0.1:18789 --token "tok"

# Интерактивная оболочка
./lobster-guard shell
```

---

## Использование

```
Использование:
  lobster-guard [команда]

Команды:
  scan          Полный пайплайн: фингерпринт + аутентификация + брутфорс + разведка + аудит + эксплуатация
  fingerprint   Определение экземпляра OpenClaw
  auth          Тестирование аутентификации: обнаружение без авторизации + брутфорс токенов
  recon         Перечисление эндпоинтов + обнаружение методов WS + определение версии
  audit         Аудит конфигурации (требуется токен)
  exploit       Выполнение всех 31 цепочки атак
  discover      Обнаружение активов Shodan/FOFA
  shell         Интерактивная оболочка (в стиле msfconsole)

Флаги:
  -t, --target string     Целевой хост:порт
  -T, --targets string    Файл со списком целей (по одной на строку)
  -c, --concurrency int   Количество параллельных сканирований (по умолчанию 1)
  -o, --output string     Путь для сохранения JSON-отчёта
      --token string      Gateway Token
      --tls               Использовать HTTPS/WSS
      --timeout int       Таймаут HTTP в секундах (по умолчанию 10)
```

---

## Интерактивная оболочка

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

## 31 цепочка атак

| # | Цепочка | Критичность | Описание |
|---|---------|-------------|----------|
| 0 | Фингерпринт платформы | Info | Обнаружение OpenClaw без авторизации |
| 1 | SSRF | Critical | browser.request/navigate → облачные метаданные (AWS/GCP/Azure/DO) |
| 2 | Инъекция eval() | Critical | Выполнение кода через eval/exec в параметрах инструментов |
| 3 | Кража API-ключей | Critical | Извлечение API-ключей провайдеров через эндпоинты config/env |
| 4 | Брутфорс кода сопряжения | High | Брутфорс 6-значного кода сопряжения DM |
| 5 | Обход Cron | High | Обход чёрного списка Cron + персистентность |
| 6 | Инъекция в промпт | High | Извлечение системного промпта + подмена инструкций |
| 7 | Достижимость RCE | Critical | Проверка выполнения команд system.run |
| 8 | Инъекция хука | Critical | Инъекция в Webhook-эндпоинт для выполнения команд |
| 9 | Извлечение секретов | Critical | secrets.list + secrets.get кража в открытом виде |
| 10 | Подмена конфигурации | High | config.set запись в конфигурацию безопасности |
| 11 | Прямой вызов инструментов | Critical | tools.invoke обходит защиту слоя Chat |
| 12 | Перехват сессии | High | sessions.preview IDOR + межсессионная инъекция |
| 13 | Обход CORS | Medium | Отражение Origin → межсайтовый доступ к WS/API |
| 14 | Инъекция в канал | High | Неподписанная инъекция команд Mattermost/Slack/Discord |
| 15 | Утечка логов | Medium | logs.query раскрытие учётных данных и чувствительных данных |
| 16 | Побег через патч | Critical | apply_patch обход пути → произвольная запись файлов |
| 17 | Перехват WS | High | Межсайтовое обновление WebSocket + воспроизведение токена |
| 18 | Инъекция агента | Critical | agents.create/update бэкдор + утечка системного промпта |
| 19 | Злоупотребление OAuth | High | Перехват редиректа Slack OAuth + фиксация State |
| 20 | Responses API | Critical | /v1/responses обход аутентификации + инъекция инструментов |
| 21 | Фаззинг WS | Medium | Некорректный JSON-RPC + инъекция методов |
| 22 | Инъекция файлов агента | Critical | agents.files.set персистентный бэкдор в промпте |
| 23 | Запись файлов сессии | Critical | sessions.patch + compact произвольная запись файлов |
| 24 | Перехват одобрения | Critical | Сопоставление префикса ID + подмена политики выполнения |
| 25 | Talk Secret | Critical | talk.config(includeSecrets) эксфильтрация API-ключей |
| 26 | Browser SSRF | High | browser.request внутренняя диспетчеризация |
| 27 | Secrets Resolve | Critical | secrets.resolve извлечение в открытом виде (внутренний API инъекции) |
| 28 | Кража записей сессии | High | Несанированная история сессий + кража вывода инструментов |
| 29 | Мошеннический узел | Critical | Самоодобрение сопряжения узла → перехват команд |
| 30 | Полный RCE | Critical | nodes.list → самоодобрение → node.invoke system.run |

---

## Шаблоны Nuclei

23 готовых к использованию шаблона, напрямую интегрируемых в CI/CD:

```bash
# Сканирование одной цели
nuclei -t nuclei-templates/ -u http://10.0.0.1:18789

# Сканирование списка целей
nuclei -t nuclei-templates/ -l targets.txt

# Только критические
nuclei -t nuclei-templates/ -u http://target:18789 -severity critical
```

Покрытие: обнаружение экземпляра, отсутствие авторизации, токен по умолчанию, слабый токен, CORS, раскрытие сессий, одобрение выполнения, webhook, перенаправление OAuth, WebSocket, инъекция Slack/Mattermost/Discord, Responses API, файлы агентов, мошеннический узел, разрешение секретов, кража сессий, полный RCE и другое.

---

## Обнаружение активов

```bash
# Shodan
./lobster-guard discover --shodan-key "YOUR_KEY" -o targets.txt

# FOFA
./lobster-guard discover --fofa-email "you@x.com" --fofa-key "KEY" -o targets.txt

# Сканирование всех обнаруженных целей
./lobster-guard scan -T targets.txt -c 10
```

---

## Структура проекта

```
lobster-guard/
├── cmd/lobster-guard/     # Точка входа CLI
├── pkg/
│   ├── audit/             # Аудит конфигурации
│   ├── auth/              # Обнаружение без авторизации + брутфорс токенов
│   ├── chain/             # Оркестратор цепочек атак
│   ├── discovery/         # Обнаружение активов Shodan/FOFA
│   ├── exploit/           # 30 модулей эксплойтов (4500+ строк)
│   ├── interactive/       # Интерактивная оболочка в стиле msfconsole
│   ├── recon/             # Перечисление эндпоинтов + методов WS
│   ├── report/            # Генерация отчётов JSON + HTML
│   ├── scanner/           # Движок фингерпринтинга
│   └── utils/             # HTTP-клиент, WS-клиент, определения типов
├── nuclei-templates/      # 23 шаблона Nuclei YAML
└── rules/                 # Словари учётных данных по умолчанию
```

---

## Отказ от ответственности

Данный инструмент предназначен **исключительно для авторизованного тестирования безопасности**. Тестируйте только те системы, которыми вы владеете или на тестирование которых у вас есть явное письменное разрешение. Несанкционированный доступ к компьютерным системам является незаконным. Автор не несёт ответственности за любое неправомерное использование.

## Автор

**coff0xc**

## Лицензия

[GPL-3.0](LICENSE)
