<h1 align="center">🦞 LobsterGuard</h1>

<p align="center">
  <b>OpenClaw 专用安全评估工具</b><br>
  <sub>31 条攻击链 | 23 Nuclei 模板 | 交互式 Shell | Shodan/FOFA 资产发现 | 全链路自动化</sub>
</p>

<p align="center">
  <a href="README.md"><b>简体中文</b></a> ·
  <a href="README_EN.md">English</a> ·
  <a href="README_JA.md">日本語</a> ·
  <a href="README_RU.md">Русский</a> ·
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

## 项目亮点

```
┌──────────────────────────────────────────────────────────────────────────┐
│                        LobsterGuard v1.0.0                              │
├──────────────────────────────────────────────────────────────────────────┤
│  ● 31 条攻击链         ● 30 个 Exploit 模块   ● 23 Nuclei 模板         │
│  ● 交互式 Shell        ● Shodan/FOFA 发现     ● JSON + HTML 报告       │
│  ● WebSocket 全覆盖    ● 零认证指纹识别       ● 多目标并发扫描         │
├──────────────────────────────────────────────────────────────────────────┤
│  攻击面: Gateway WS API | HTTP REST | OAuth | Webhook | Node Pairing   │
│  覆盖: SSRF | RCE | 密钥窃取 | 会话劫持 | 提权 | 持久化 | 数据泄露   │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 目录

- [项目简介](#项目简介)
- [核心特性](#核心特性)
- [快速开始](#快速开始)
- [使用方式](#使用方式)
- [交互式 Shell](#交互式-shell)
- [31 条攻击链](#31-条攻击链)
- [Nuclei 模板](#nuclei-模板)
- [资产发现](#资产发现)
- [项目结构](#项目结构)
- [免责声明](#免责声明)
- [作者](#作者)
- [许可证](#许可证)

---

## 项目简介

**LobsterGuard** 是一款专门针对 [OpenClaw](https://github.com/anthropics/open-claw)（开源 AI 编程代理平台）的自动化渗透测试工具。它覆盖从资产发现到 RCE 验证的完整攻击生命周期，通过 31 条链式 Exploit 模块全面测试 OpenClaw Gateway WebSocket API、HTTP 端点和集成接口的安全性。

### 为什么需要 LobsterGuard？

| 场景 | 手动测试 | LobsterGuard |
|------|----------|-------------|
| **发现目标** | 手动搜索 Shodan/FOFA | `discover` 一键聚合 |
| **识别实例** | 逐个 HTTP 探测 | 零认证自动指纹识别 |
| **认证测试** | 手写脚本爆破 | 内置字典 + 智能延迟 |
| **漏洞验证** | 逐个手工构造 PoC | 31 条链自动化验证 |
| **攻击面覆盖** | 依赖经验 | WS + HTTP + OAuth + Webhook + Node 全覆盖 |
| **报告输出** | 手动整理 | JSON + HTML 一键生成 |
| **CI/CD 集成** | 无 | 23 Nuclei 模板即插即用 |

---

## 核心特性

<table>
<tr>
<td width="50%">

### 侦察与发现

- **Shodan / FOFA 资产发现** — 互联网范围 OpenClaw 实例搜索
- **零认证指纹识别** — 自动检测 OpenClaw 并提取版本信息
- **HTTP 端点枚举** — 全面扫描 REST API 路由
- **WebSocket 方法发现** — 枚举 Gateway WS 可用方法
- **认证模式检测** — 识别 no-auth / token / OAuth 模式

</td>
<td width="50%">

### 攻击与利用

- **31 条攻击链** — 从 SSRF 到完整 RCE 链
- **自动化利用编排** — Chain Orchestrator 按序执行
- **自审批 RCE** — exec.approval.request → 自审批 → node.invoke
- **密钥窃取** — secrets.resolve / talk.config / API key 提取
- **持久化后门** — Agent 注入 + 文件写入 + Cron 绕过

</td>
</tr>
<tr>
<td width="50%">

### 安全审计

- **15+ 配置审计项** — 认证、权限、加密、日志等
- **Token 爆破** — 内置高频弱口令字典 + 自定义字典
- **CORS 检测** — Origin 反射 + 凭据泄露验证
- **OAuth 安全** — 重定向劫持 + State 固定攻击

</td>
<td width="50%">

### 工具与报告

- **交互式 Shell** — msfconsole 风格 REPL，逐链执行
- **23 Nuclei 模板** — 直接集成 CI/CD 流水线
- **JSON + HTML 报告** — 严重等级分类 + 修复建议
- **多目标并发** — `-c` 参数控制并发数

</td>
</tr>
</table>

---

## 快速开始

### 系统要求

- Go 1.22+
- 网络可达 OpenClaw 实例

### 编译安装

```bash
git clone https://github.com/Coff0xc/lobster-guard.git
cd lobster-guard
go build -o lobster-guard ./cmd/lobster-guard/
```

### 基本使用

```bash
# 全量扫描
./lobster-guard scan -t 10.0.0.1:18789

# 带 Token 扫描
./lobster-guard scan -t 10.0.0.1:18789 --token "your-gateway-token"

# 仅 Exploit
./lobster-guard exploit -t 10.0.0.1:18789 --token "tok"

# 交互式 Shell
./lobster-guard shell
```

---

## 使用方式

```
Usage:
  lobster-guard [command]

Commands:
  scan          全量流水线: 指纹 + 认证 + 爆破 + 侦察 + 审计 + 利用
  fingerprint   检测 OpenClaw 实例
  auth          认证测试: 无认证检测 + Token 爆破
  recon         端点枚举 + WS 方法发现 + 版本检测
  audit         配置审计 (需要 Token)
  exploit       31 条攻击链全量执行
  discover      Shodan/FOFA 资产发现
  shell         交互式 Shell (msfconsole 风格)

Flags:
  -t, --target string     目标 host:port
  -T, --targets string    目标列表文件 (每行一个)
  -c, --concurrency int   并发扫描数 (默认 1)
  -o, --output string     JSON 报告输出路径
      --token string      Gateway Token
      --tls               使用 HTTPS/WSS
      --timeout int       HTTP 超时秒数 (默认 10)
```

---

## 交互式 Shell

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

## 31 条攻击链

| # | 攻击链 | 严重等级 | 描述 |
|---|--------|----------|------|
| 0 | 平台指纹 | Info | 零认证 OpenClaw 检测 |
| 1 | SSRF | Critical | browser.request/navigate → 云元数据 (AWS/GCP/Azure/DO) |
| 2 | eval() 注入 | Critical | 工具参数中的 eval/exec 代码执行 |
| 3 | API Key 窃取 | Critical | 通过 config/env 端点提取 Provider API 密钥 |
| 4 | 配对码爆破 | High | DM 配对码 6 位爆破 |
| 5 | Cron 绕过 | High | Cron 黑名单绕过 + 持久化 |
| 6 | Prompt 注入 | High | 系统提示词提取 + 指令覆盖 |
| 7 | RCE 可达性 | Critical | system.run 命令执行探测 |
| 8 | Hook 注入 | Critical | Webhook 端点注入执行命令 |
| 9 | 密钥提取 | Critical | secrets.list + secrets.get 明文窃取 |
| 10 | 配置篡改 | High | config.set 写入安全配置 |
| 11 | 工具直调 | Critical | tools.invoke 绕过 Chat 层安全 |
| 12 | 会话劫持 | High | sessions.preview IDOR + 跨会话注入 |
| 13 | CORS 绕过 | Medium | Origin 反射 → 跨域 WS/API 访问 |
| 14 | 频道注入 | High | Mattermost/Slack/Discord 未签名命令注入 |
| 15 | 日志泄露 | Medium | logs.query 凭据/敏感数据泄露 |
| 16 | Patch 逃逸 | Critical | apply_patch 路径穿越 → 任意文件写入 |
| 17 | WS 劫持 | High | 跨域 WebSocket 升级 + Token 重放 |
| 18 | Agent 注入 | Critical | agents.create/update 后门 + 系统提示词泄露 |
| 19 | OAuth 滥用 | High | Slack OAuth 重定向劫持 + State 固定 |
| 20 | Responses API | Critical | /v1/responses 认证绕过 + 工具注入 |
| 21 | WS Fuzz | Medium | 畸形 JSON-RPC + 方法注入 |
| 22 | Agent 文件注入 | Critical | agents.files.set 持久化 Prompt 后门 |
| 23 | 会话文件写入 | Critical | sessions.patch + compact 任意文件写入 |
| 24 | 审批劫持 | Critical | 前缀 ID 匹配 + 执行策略篡改 |
| 25 | Talk 密钥 | Critical | talk.config(includeSecrets) API 密钥外泄 |
| 26 | 浏览器 SSRF | High | browser.request 内部调度 |
| 27 | Secrets Resolve | Critical | secrets.resolve 明文提取 (内部注入 API) |
| 28 | 会话记录窃取 | High | 未脱敏会话历史 + 工具输出窃取 |
| 29 | 流氓节点 | Critical | 自审批节点配对 → 命令拦截 |
| 30 | 完整 RCE | Critical | nodes.list → 自审批 → node.invoke system.run |

---

## Nuclei 模板

23 个即用模板，可直接集成 CI/CD:

```bash
# 扫描单个目标
nuclei -t nuclei-templates/ -u http://10.0.0.1:18789

# 扫描目标列表
nuclei -t nuclei-templates/ -l targets.txt

# 仅 Critical
nuclei -t nuclei-templates/ -u http://target:18789 -severity critical
```

覆盖: 实例检测、无认证、默认 Token、弱 Token、CORS、会话暴露、执行审批、Webhook、OAuth 重定向、WebSocket、Slack/Mattermost/Discord 注入、Responses API、Agent 文件、流氓节点、密钥解析、会话窃取、完整 RCE 等。

---

## 资产发现

```bash
# Shodan
./lobster-guard discover --shodan-key "YOUR_KEY" -o targets.txt

# FOFA
./lobster-guard discover --fofa-email "you@x.com" --fofa-key "KEY" -o targets.txt

# 扫描所有发现的目标
./lobster-guard scan -T targets.txt -c 10
```

---

## 项目结构

```
lobster-guard/
├── cmd/lobster-guard/     # CLI 入口
├── pkg/
│   ├── audit/             # 配置审计
│   ├── auth/              # 无认证检测 + Token 爆破
│   ├── chain/             # 攻击链编排器
│   ├── discovery/         # Shodan/FOFA 资产发现
│   ├── exploit/           # 30 个 Exploit 模块 (4500+ 行)
│   ├── interactive/       # msfconsole 风格交互式 Shell
│   ├── recon/             # 端点 + WS 方法枚举
│   ├── report/            # JSON + HTML 报告生成
│   ├── scanner/           # 指纹识别引擎
│   └── utils/             # HTTP 客户端, WS 客户端, 类型定义
├── nuclei-templates/      # 23 个 Nuclei YAML 模板
└── rules/                 # 默认凭据字典
```

---

## 免责声明

本工具仅用于**授权安全测试**。请仅对您拥有或获得明确书面授权的系统进行测试。未经授权访问计算机系统属于违法行为。作者不对任何滥用行为承担责任。

## 作者

**coff0xc**

## 许可证

[GPL-3.0](LICENSE)
