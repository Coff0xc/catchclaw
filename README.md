<h1 align="center">🦞 CatchClaw v5.2.0</h1>

<p align="center">
  <b>OpenClaw / Open-WebUI AI 编程平台 — 自动化安全评估工具</b><br>
  <sub>72 条 DAG 攻击链 | 72 个 Exploit 模块 | ATT&CK 阶段映射 | Async Tokio 引擎 | 攻击图可视化</sub>
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
  <a href="https://github.com/Coff0xc/catchclaw/stargazers"><img src="https://img.shields.io/github/stars/Coff0xc/catchclaw?style=flat-square&logo=github&color=gold" alt="Stars"></a>
  <a href="https://github.com/Coff0xc/catchclaw/network/members"><img src="https://img.shields.io/github/forks/Coff0xc/catchclaw?style=flat-square&logo=github&color=silver" alt="Forks"></a>
  <a href="https://github.com/Coff0xc/catchclaw/issues"><img src="https://img.shields.io/github/issues/Coff0xc/catchclaw?style=flat-square&logo=github&color=red" alt="Issues"></a>
  <a href="https://github.com/Coff0xc/catchclaw/commits/master"><img src="https://img.shields.io/github/last-commit/Coff0xc/catchclaw?style=flat-square&logo=github" alt="Last Commit"></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-5.2.0-blue?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/Rust-Edition_2024-DEA584?style=flat-square&logo=rust&logoColor=white" alt="Rust">
  <img src="https://img.shields.io/badge/DAG_Chains-72-FF6B6B?style=flat-square" alt="Chains">
  <img src="https://img.shields.io/badge/Async-Tokio-4CAF50?style=flat-square" alt="Tokio">
  <img src="https://img.shields.io/badge/Exploits-72_Modules-orange?style=flat-square" alt="Exploits">
  <img src="https://img.shields.io/badge/License-Non--Commercial--v2.0-green?style=flat-square" alt="License">
</p>

---

> **⚠️ 商业使用严格禁止 | COMMERCIAL USE STRICTLY PROHIBITED**
>
> 本项目采用 **CatchClaw Strict Non-Commercial License v2.0**。
>
> **未经版权持有人 (Coff0xc) 书面授权，严禁任何形式的商业使用。** 违反者将被追究法律责任。
>
> 禁止行为包括但不限于：
> - 出售、转授权、租赁本软件或其衍生作品
> - 将本软件用于 SaaS、渗透测试服务、咨询或任何付费服务
> - 集成至商业产品、平台或工具
> - 用于训练商业 AI/ML 模型
> - 改名、换皮、重新包装后分发
> - 任何直接或间接产生收入的行为
>
> **版权持有人保留无限期追溯追诉权，包括追偿全部利润、法律费用及惩罚性赔偿。**
>
> 详见 [LICENSE](LICENSE)。

---

## 项目亮点

```
┌────────────────────────────────────────────────────────────────────────────┐
│                          CatchClaw v5.2.0                                │
├────────────────────────────────────────────────────────────────────────────┤
│  ● 72 条 DAG 攻击链     ● 72 个 Exploit 模块    ● Async Tokio 引擎       │
│  ● ATT&CK 9阶段映射    ● Mermaid 攻击图导出    ● JSON/HTML/MD 报告       │
│  ● Kahn 拓扑排序引擎    ● Semaphore 并发控制    ● 条件/回退执行           │
│  ● 多目标扫描 (CIDR)   ● 端口扫描/服务发现     ● 200+ 外部 Payload       │
├────────────────────────────────────────────────────────────────────────────┤
│  攻击面: Gateway WS API | HTTP REST | OAuth | Webhook | Node Pairing     │
│  覆盖: SSRF | RCE | 密钥窃取 | 会话劫持 | 提权 | 持久化 | 数据泄露      │
│  新增: C2外泄 | Skill投毒 | Agent注入 | MCP注入 | OAuth窃取 | DNS Rebind  │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## 目录

- [项目简介](#项目简介)
- [核心特性](#核心特性)
- [安装方式](#安装方式)
- [快速开始](#快速开始)
- [CLI 用法](#cli-用法)
- [72 个 Exploit 模块](#59-个-exploit-模块)
- [DAG 攻击链架构](#dag-攻击链架构)
- [Nuclei 模板](#nuclei-模板)
- [项目结构](#项目结构)
- [免责声明](#免责声明)

---

## 项目简介

**CatchClaw** 是一款基于 Rust 的 [OpenClaw](https://github.com/anthropics/open-claw) / Open-WebUI AI 编程平台安全评估工具。通过 72 条 DAG 攻击链和 72 个 Exploit 模块，覆盖从初始侦察到数据泄露的完整 ATT&CK 攻击链路。

基于 Tokio 异步运行时，DAG 引擎使用 Kahn 拓扑排序按层级并发执行，Semaphore 控制并发度，支持条件执行与回退节点。攻击图可导出 Mermaid 流程图。

### 为什么选择 CatchClaw？

| 场景 | 手工测试 | CatchClaw |
|------|---------|-----------|
| **漏洞验证** | 逐个手写 PoC | 59 条链自动编排验证 |
| **攻击面覆盖** | 靠经验判断 | WS + HTTP + OAuth + Webhook + Node 全覆盖 |
| **依赖链发现** | 难以追踪 | DAG 自动发现漏洞依赖路径 |
| **结果可视化** | 手工整理 | Mermaid 攻击图 + JSON/HTML/Markdown 报告 |
| **CI/CD 集成** | 无 | 24 Nuclei 模板即插即用 |
| **多目标扫描** | 逐个手动测试 | CIDR、IP 范围、目标文件批量扫描 |
| **服务发现** | 需配合 nmap | 内置端口扫描 + OpenClaw 指纹识别 |

---

## 核心特性

<table>
<tr>
<td width="50%">

### 攻击引擎

- **72 个 Exploit 模块** — 覆盖 10 大类别，`inventory` 宏自动注册
- **72 条 DAG 攻击链** — 9 个 ATT&CK 阶段自动编排
- **Kahn 拓扑排序** — 层级并发执行，自动解析依赖
- **条件/回退节点** — 按前序结果动态决策执行路径
- **攻击图可视化** — Mermaid 导出，标记命中/跳过/回退状态

</td>
<td width="50%">

### 协议支持

- **WebSocket Gateway** — challenge 握手检测，JSON-RPC 调用
- **HTTP REST** — 禁用重定向防止 OAuth 302 误报
- **误报消除** — challenge 页面 / SPA 回退 / LLM 拒绝检测
- **TLS 支持** — rustls 后端，`--tls` 启用 HTTPS/WSS
- **多格式报告** — JSON + HTML（暗色主题）+ Markdown

</td>
</tr>
<tr>
<td width="50%">

### 扫描增强

- **多目标扫描** — CIDR (/24)、IP 范围、逗号分隔、目标文件
- **端口扫描** — TCP connect 扫描 + 自定义端口范围
- **服务发现** — OpenClaw 指纹识别（API/WebSocket/健康检查）
- **200+ Payload** — SSRF/注入/Prompt/Auth/XSS 外部 YAML 库
- **扫描配置** — TOML 配置文件 + Profile 预设 + 代理支持

</td>
<td width="50%">

### CLI 体验

- **`--profile`** — 使用预设扫描配置（quick/stealth/full）
- **`--severity-filter`** — 按严重级别过滤结果
- **`--format`** — 选择输出格式：json/html/markdown
- **`--dry-run`** — 预览 DAG 执行计划，不实际扫描
- **`--targets-file`** — 批量目标文件输入

</td>
</tr>
</table>

---

## 安装方式

### 从源码构建

```bash
git clone https://github.com/Coff0xc/catchclaw.git
cd catchclaw/rust

# Debug 构建
cargo build

# Release 构建（优化 + 剥离符号表）
cargo build --release

# 二进制位于 target/release/catchclaw
```

### 系统要求

- Rust Edition 2024 (rustc 1.85+)
- 支持 Windows / Linux / macOS

---

## 快速开始

```bash
# 查看所有注册模块
catchclaw list

# 全量扫描
catchclaw scan -t 目标IP:端口

# 扫描并输出 JSON 报告
catchclaw scan -t 目标IP:端口 -o report.json

# 输出 HTML 报告
catchclaw scan -t 目标IP:端口 -o report.html --format html

# 多目标扫描 (CIDR)
catchclaw scan --targets "192.168.1.0/24:8080"

# 从文件批量扫描
catchclaw scan -f targets.txt -o results.json

# 使用 Profile 预设
catchclaw scan -t 目标IP:端口 --profile stealth

# 仅显示高危结果
catchclaw scan -t 目标IP:端口 --severity-filter critical,high

# 预览执行计划
catchclaw scan -t 目标IP:端口 --dry-run

# 带 Token 扫描
catchclaw scan -t 目标IP:端口 --token "your-gateway-token"

# 执行完整攻击链
catchclaw exploit -t 目标IP:端口 --token xxx

# 执行单条攻击链
catchclaw exploit -t 目标IP:端口 --chain-id 30
```

---

## CLI 用法

```
CatchClaw v5.2.0 — OpenClaw 安全评估工具

Usage: catchclaw <COMMAND>

Commands:
  scan      全量安全扫描（构建 DAG → 执行 → 汇总）
  exploit   执行攻击链（完整 DAG 或单节点）
  list      列出所有注册的 Exploit 模块
  config    显示当前配置

Scan Flags:
  -t, --target <HOST:PORT>     目标地址（单目标）
      --targets <SPEC>         多目标：逗号分隔、CIDR 或 IP 范围
  -f, --targets-file <FILE>    目标文件（每行一个 host:port）
      --token <TOKEN>          Gateway Token (或 CATCHCLAW_TOKEN 环境变量)
      --timeout <SECS>         请求超时秒数 (默认 10)
  -o, --output <FILE>          报告输出路径
      --format <FMT>           输出格式：json | html | markdown (默认 json)
      --concurrency <N>        最大并发数 (默认 10)
      --tls                    使用 HTTPS/WSS
      --callback <URL>         SSRF 回调地址
      --profile <NAME>         使用配置文件中的 Profile 预设
      --severity-filter <SEV>  按严重级别过滤：critical,high,medium,low,info
      --dry-run                预览 DAG 执行计划
      --config <FILE>          配置文件路径 (TOML/YAML/JSON)

Exploit Flags:
  -t, --target <HOST:PORT>     目标地址
      --token <TOKEN>          Gateway Token
      --chain-id <ID>          指定运行单条链节点 ID
      --concurrency <N>        最大并发数 (默认 10)
      --tls                    使用 HTTPS/WSS
```

---

## 72 个 Exploit 模块

按 ATT&CK 阶段和攻击类别分组：

### Recon（侦察）

| 模块 | 类别 | 说明 |
|------|------|------|
| cors_bypass | Config | Origin 反射 → 跨域 WS/API 访问 |
| ws_hijack | Transport | 跨域 WebSocket 升级 + Token 重放 |
| auth_mode_abuse | Auth | 认证模式检测与滥用 |
| log_disclosure | DataLeak | logs.query 凭证/敏感数据泄露 |
| hidden_content | DataLeak | 隐藏内容发现 |
| origin_wildcard | Config | Origin 通配符配置检测 |

### Initial Access（初始访问）

| 模块 | 类别 | 说明 |
|------|------|------|
| ssrf | SSRF | browser.request/navigate → 云元数据 (AWS/GCP/Azure) |
| eval_inject | Injection | eval/exec 代码执行 |
| prompt_inject | Injection | 系统提示词提取 + 指令覆盖 |
| mcp_inject | Injection | MCP 插件注入 |
| pairing_brute | Auth | DM 配对码 6 位爆破 |
| oauth_abuse | Auth | Slack OAuth 重定向劫持 |
| responses_exploit | API | /v1/responses 认证绕过 + 工具注入 |
| ws_fuzz | Fuzz | 畸形 JSON-RPC + 方法注入 |
| acp_bypass | Auth | ACP 访问控制绕过 |
| ssrf_rebind | SSRF | DNS Rebind SSRF |
| ssrf_proxy_bypass | SSRF | 代理绕过 SSRF |
| browser_request | SSRF | 浏览器请求内部分发 |
| csrf_no_origin | Config | 无 Origin 验证 CSRF |

### Credential Access（凭证获取）

| 模块 | 类别 | 说明 |
|------|------|------|
| apikey_steal | Credential | Provider API Key 提取 |
| oauth_token_theft | Credential | OAuth Token 窃取 |
| secret_extract | Credential | secrets.list + secrets.get 明文窃取 |
| secrets_resolve | Credential | secrets.resolve 内部注入 API |
| talk_secrets | Credential | talk.config(includeSecrets) 密钥泄露 |

### Execution（执行）

| 模块 | 类别 | 说明 |
|------|------|------|
| rce | RCE | system.run 命令执行探测 |
| hook_inject | RCE | Webhook 端点注入执行命令 |
| tools_invoke | RCE | tools.invoke 绕过 Chat 层安全 |
| keychain_cmd_inject | RCE | Keychain 命令注入 |
| qmd_cmd_inject | RCE | QMD 命令注入 |
| exec_race_toctou | RCE | 执行竞态条件 (TOCTOU) |
| exec_socket_leak | RCE | 执行 Socket 泄露 |

### Persistence（持久化）

| 模块 | 类别 | 说明 |
|------|------|------|
| agent_inject | Injection | agents.create/update 后门 + 系统提示词泄露 |
| agent_file_inject | Injection | agents.files.set 持久化提示词后门 |
| channel_inject | Injection | Mattermost/Slack/Discord 无签名命令注入 |
| skill_poison | Injection | Skill 投毒 |
| cron_bypass | Persistence | Cron 黑名单绕过 + 持久化 |
| session_file_write | RCE | sessions.patch 任意文件写入 |
| patch_escape | RCE | apply_patch 路径穿越 → 任意文件写入 |
| link_template_inject | Injection | 链接模板注入 |

### Privilege Escalation（提权）

| 模块 | 类别 | 说明 |
|------|------|------|
| approval_hijack | Auth | 前缀 ID 匹配 + 执行策略篡改 |
| config_tamper | Config | config.set 安全配置写入 |
| rogue_node | RCE | 自批准节点配对 → 命令拦截 |
| silent_pair_abuse | Auth | 静默配对滥用 |
| auth_disable_leak | Auth | 认证禁用泄露 |

### Lateral Movement / Exfiltration（横移 / 泄露）

| 模块 | 类别 | 说明 |
|------|------|------|
| session_hijack | DataLeak | sessions.preview IDOR + 跨会话注入 |
| transcript_theft | DataLeak | 会话记录窃取 |
| memory_data_leak | DataLeak | 内存数据泄露 |
| c2_exfil | DataLeak | C2 数据外泄 |
| browser_upload_traversal | RCE | 浏览器上传路径穿越 |
| secret_exec_abuse | RCE | 密钥执行滥用 |
| bypass_soul | Injection | Soul 绕过 |
| marker_spoof | Injection | 标记欺骗 |
| redact_bypass | DataLeak | 脱敏绕过 |
| obfuscation_bypass | Injection | 混淆绕过 |
| unicode_bypass | Injection | Unicode 绕过 |
| ratelimit_scope_bypass | Config | 速率限制范围绕过 |
| flood_guard_reset | Config | 洪水防护重置 |
| webhook_verify | Config | Webhook 验证绕过 |
| skill_scanner_bypass | Config | Skill 扫描器绕过 |

### CVE 针对性模块（2026 威胁情报）

| 模块 | CVE / 来源 | 说明 |
|------|-----------|------|
| gateway_hijack | CVE-2026-25253 | gatewayURL WebSocket 劫持 → Token 窃取 |
| safebins_bypass | CVE-2026-28363 | GNU 长选项缩写绕过 safeBins 白名单 → RCE |
| ws_auth_brute | CVE-2026-32025 | WebSocket 认证爆破 + localhost 速率限制豁免 |
| localhost_trust | ClawJacked | localhost 隐式信任绕过认证 |
| guest_mode_abuse | Conscia 审计 | Guest Mode 暴露危险 API 端点 |
| mdns_leak | Conscia 审计 | mDNS/HTTP 配置参数泄露 |
| skill_supply_chain | ClawHavoc | 恶意 Skill 供应链攻击检测 (AMOS 窃密) |

---

## DAG 攻击链架构

```
                        ┌─────────────────────┐
                        │   Level 0 (Recon)    │
                        │  CORS / WS / Auth    │
                        └─────────┬───────────┘
                                  │
              ┌───────────────────┼───────────────────┐
              ▼                   ▼                   ▼
    ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
    │  Level 1 (Init) │ │ Level 1 (Cred)  │ │  Level 1 (Init) │
    │ SSRF / Eval /   │ │ APIKey / OAuth  │ │ Prompt / MCP /  │
    │ Pairing         │ │ Token Theft     │ │ Responses       │
    └────────┬────────┘ └────────┬────────┘ └────────┬────────┘
             │                   │                   │
             └───────────────────┼───────────────────┘
                                 ▼
                   ┌─────────────────────────┐
                   │   Level 2 (Execution)   │
                   │  RCE / Hook / Tools /   │
                   │  Session Write          │
                   └────────────┬────────────┘
                                │
                   ┌────────────┼────────────┐
                   ▼                         ▼
         ┌─────────────────┐       ┌─────────────────┐
         │ Level 3 (Persis)│       │ Level 3 (Priv)  │
         │ Agent / Cron /  │       │ Approval / Node │
         │ Skill Poison    │       │ Config Tamper    │
         └────────┬────────┘       └────────┬────────┘
                  │                         │
                  └────────────┬────────────┘
                               ▼
                  ┌─────────────────────────┐
                  │   Level 4 (Exfil)       │
                  │  C2 / Transcript /      │
                  │  Memory Leak            │
                  └─────────────────────────┘
```

**执行特性：**
- Kahn 拓扑排序 → 按层级并发执行
- `Semaphore` 控制最大并发数
- `depends_on` — 前驱节点必须完成
- `fallback_for` — 父节点有发现则跳过回退节点
- `condition` — 按前序结果条件执行
- `AttackGraph` — 记录每个节点执行/跳过/回退状态，导出 Mermaid 图

---

## Nuclei 模板

`nuclei-templates/` 包含 24 个独立 Nuclei 兼容 YAML 模板：

```bash
# 扫描单目标
nuclei -t nuclei-templates/ -u http://目标IP:端口

# 扫描目标列表
nuclei -t nuclei-templates/ -l targets.txt

# 仅 Critical
nuclei -t nuclei-templates/ -u http://目标IP:端口 -severity critical
```

---

## 项目结构

```
catchclaw/
├── rust/
│   ├── Cargo.toml                 # 项目配置
│   └── src/
│       ├── main.rs                # CLI 入口 (clap derive)
│       ├── config/mod.rs          # AppConfig + Profile + 协议常量
│       ├── chain/
│       │   ├── dag.rs             # DAG 引擎 (拓扑排序 + 并发 + AttackGraph)
│       │   └── chains.rs          # 59 条攻击链节点定义
│       ├── exploit/
│       │   ├── registry.rs        # ExploitMeta + inventory 注册系统
│       │   ├── base.rs            # ExploitCtx 公共上下文 + PayloadRegistry 集成
│       │   └── *.rs               # 59 个 exploit 模块实现
│       ├── scan/mod.rs            # 全量扫描 + 多目标扫描编排
│       ├── report/mod.rs          # JSON / HTML / Markdown 报告输出
│       └── utils/
│           ├── types.rs           # Target / Finding / Severity / 多目标解析
│           ├── http.rs            # HTTP 客户端 + 误报过滤器
│           ├── ws.rs              # GatewayWsClient (WS + challenge)
│           ├── discovery.rs       # 端口扫描 + OpenClaw 服务发现
│           ├── payload.rs         # PayloadRegistry (YAML 加载 + 目录合并)
│           └── mutate.rs          # Payload 变异引擎
├── payloads/                      # 200+ 外部 Payload (YAML)
│   ├── ssrf.yaml                  # SSRF: AWS/GCP/Azure/IP绕过/协议走私
│   ├── injection.yaml             # 命令注入/Shell元字符/编码绕过
│   ├── prompt_inject.yaml         # Prompt注入/越狱/角色覆盖
│   ├── auth_bypass.yaml           # Token/Header/路径穿越/默认凭证
│   └── xss.yaml                   # XSS: 反射/事件/过滤绕过/Polyglot
├── nuclei-templates/              # 24 Nuclei YAML 模板
├── LICENSE                        # CatchClaw Strict Non-Commercial License v2.0
└── README.md
```

---

## 免责声明

本工具仅用于**授权安全测试**。请仅对您拥有或获得明确书面授权的系统进行测试。未经授权访问计算机系统属于违法行为。作者不对任何滥用行为承担责任。

## 作者

**Coff0xc** — [https://github.com/Coff0xc](https://github.com/Coff0xc)

## 许可证

[CatchClaw Strict Non-Commercial License v2.0](LICENSE) — 严禁商业使用，违者必究。
