<h1 align="center">🦞 LobsterGuard v4.1.0</h1>

<p align="center">
  <b>OpenClaw / Open-WebUI AI 编程平台 — 自动化安全评估工具</b><br>
  <sub>60 条 DAG 攻击链 | 63 个 Exploit 模块 | 45 Nuclei 模板（内嵌二进制） | AI 模糊测试 | CVE 漏洞库 | TUI 仪表盘 | MCP 集成</sub>
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
  <img src="https://img.shields.io/badge/Version-4.1.0-blue?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go">
  <img src="https://img.shields.io/badge/DAG_Chains-60-FF6B6B?style=flat-square" alt="Chains">
  <img src="https://img.shields.io/badge/Nuclei-45_Templates-4CAF50?style=flat-square" alt="Nuclei">
  <img src="https://img.shields.io/badge/Exploits-63_Modules-orange?style=flat-square" alt="Exploits">
  <img src="https://img.shields.io/badge/License-GPL--3.0-green?style=flat-square" alt="License">
</p>

---

## 项目亮点

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                         LobsterGuard v4.1.0                                  │
├──────────────────────────────────────────────────────────────────────────────┤
│  ● 60 条 DAG 攻击链     ● 63 个 Exploit 模块    ● 45 Nuclei 模板           │
│  ● AI 智能模糊测试      ● CVE 漏洞库            ● TUI 实时仪表盘           │
│  ● 交互式 Shell         ● MCP Server 集成       ● JSON + HTML 报告         │
│  ● Shodan/FOFA 发现     ● 高并发 DAG 引擎       ● 多目标并发扫描           │
│  ● 模板/字典内嵌二进制  ● PwnKit 攻击链         ● 嵌入式 Wordlist          │
├──────────────────────────────────────────────────────────────────────────────┤
│  攻击面: Gateway WS API | HTTP REST | OAuth | Webhook | Node Pairing       │
│  覆盖: SSRF | RCE | 密钥窃取 | 会话劫持 | 提权 | 持久化 | 数据泄露       │
│  新增: PwnKit LLM Agent 攻击 | C2 外泄检测 | 蜜罐检测 | Skill 投毒        │
└──────────────────────────────────────────────────────────────────────────────┘
```


---

## 目录

- [项目简介](#项目简介)
- [核心特性](#核心特性)
- [安装方式](#安装方式)
- [快速开始](#快速开始)
- [完整使用教程](#完整使用教程)
  - [1. 全量扫描](#1-全量扫描)
  - [2. 模块化扫描](#2-模块化扫描)
  - [3. DAG 攻击链](#3-dag-攻击链)
  - [4. AI 模糊测试](#4-ai-模糊测试)
  - [5. CVE 漏洞库](#5-cve-漏洞库)
  - [6. 资产发现](#6-资产发现)
  - [7. 报告输出](#7-报告输出)
  - [8. TUI 仪表盘](#8-tui-仪表盘)
  - [9. 交互式 Shell](#9-交互式-shell)
  - [10. MCP Server](#10-mcp-server)
  - [11. 提取内嵌资源](#11-提取内嵌资源)
- [60 条 DAG 攻击链](#60-条-dag-攻击链)
- [Nuclei 模板](#nuclei-模板)
- [环境变量](#环境变量)
- [项目结构](#项目结构)
- [免责声明](#免责声明)
- [作者](#作者)
- [许可证](#许可证)

---

## 项目简介

**LobsterGuard** 是一款专门针对 [OpenClaw](https://github.com/anthropics/open-claw) / Open-WebUI（开源 AI 编程代理平台）的自动化安全评估工具。覆盖从资产发现到 RCE 验证的完整攻击生命周期，通过 60 条 DAG 攻击链、63 个 Exploit 模块全面测试 Gateway WebSocket API、HTTP 端点和集成接口的安全性。

v4.1.0 新增: PwnKit LLM Agent 攻击链（蜜罐检测/Skill 投毒/安全绕过/C2 外泄/Webhook 验证）、Nuclei 模板与字典内嵌二进制、TUI 增强（鼠标/帮助覆盖/面板快捷键）、extract 命令。

### 为什么需要 LobsterGuard？

| 场景 | 手动测试 | LobsterGuard |
|------|----------|-------------|
| **发现目标** | 手动搜索 Shodan/FOFA | `discover` 一键聚合 |
| **识别实例** | 逐个 HTTP 探测 | 零认证自动指纹识别 |
| **认证测试** | 手写脚本爆破 | 内置字典 + 智能延迟 |
| **漏洞验证** | 逐个手工构造 PoC | 55 条 DAG 链自动化验证 |
| **模糊测试** | 手动构造 payload | AI 生成 + 5 类 Fuzz |
| **攻击面覆盖** | 依赖经验 | WS + HTTP + OAuth + Webhook + Node 全覆盖 |
| **实时监控** | 无 | TUI 仪表盘实时进度 + 漏洞表格 |
| **报告输出** | 手动整理 | JSON + HTML 一键生成 |
| **AI 集成** | 无 | MCP Server 供 AI Agent 调用 |
| **CI/CD 集成** | 无 | 45 Nuclei 模板即插即用 |


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

- **60 条 DAG 攻击链** — 拓扑排序 + 并行执行 + 条件依赖
- **63 个 Exploit 模块** — 从 SSRF 到完整 RCE 链
- **CVE-2026 漏洞链** — 15 条最新 CVE 利用链
- **PwnKit LLM Agent 攻击** — 蜜罐/Skill 投毒/C2 外泄/安全绕过
- **零认证利用** — 无需 Token 即可触发的攻击链
- **自审批 RCE** — exec.approval → 自审批 → node.invoke

</td>
</tr>
<tr>
<td width="50%">

### 安全审计与 Fuzz

- **15+ 配置审计项** — 认证、权限、加密、日志等
- **AI 模糊测试** — XSS / SQL注入 / SSRF / 命令注入 / 提示词注入
- **Token 爆破** — 内置高频弱口令字典 + 自定义字典
- **CORS 检测** — Origin 反射 + 凭据泄露验证
- **CVE 漏洞库** — 内置 OpenClaw/Open-WebUI CVE 数据库

</td>
<td width="50%">

### 工具与交互

- **TUI 仪表盘** — 实时进度 / 漏洞表格 / 日志滚动 / 命令输入
- **交互式 Shell** — msfconsole 风格 REPL
- **MCP Server** — JSON-RPC stdio，供 AI Agent 集成
- **45 Nuclei 模板** — 直接集成 CI/CD 流水线
- **JSON + HTML 报告** — 按扩展名自动选择格式

</td>
</tr>
</table>


---

## 安装方式

### 方式一：下载预编译包（推荐）

从 [Releases](https://github.com/Coff0xc/lobster-guard/releases) 下载对应平台的压缩包，解压即用，无需安装 Go 环境。

| 平台 | 文件 |
|------|------|
| Windows x64 | `lobster-guard-v4.1.0-windows-amd64.tar.gz` |
| Linux x64 | `lobster-guard-v4.1.0-linux-amd64.tar.gz` |
| Linux ARM64 | `lobster-guard-v4.1.0-linux-arm64.tar.gz` |
| macOS Intel | `lobster-guard-v4.1.0-darwin-amd64.tar.gz` |
| macOS Apple Silicon | `lobster-guard-v4.1.0-darwin-arm64.tar.gz` |

```bash
# Linux / macOS
tar xzf lobster-guard-v4.1.0-linux-amd64.tar.gz
cd lobster-guard-v4.1.0-linux-amd64
chmod +x lobster-guard
./lobster-guard --help

# Windows (Git Bash / PowerShell)
tar xzf lobster-guard-v4.1.0-windows-amd64.tar.gz
cd lobster-guard-v4.1.0-windows-amd64
.\lobster-guard.exe --help
```

每个压缩包包含：
- `lobster-guard` 可执行文件（已内嵌 Nuclei 模板 + 爆破字典）
- `nuclei-templates/` — 45 个 Nuclei 扫描模板（也可通过 `extract` 命令从二进制释放）
- `rules/` — 爆破字典
- `README.md` / `LICENSE`

### 方式二：从源码编译

```bash
# 需要 Go 1.22+
git clone https://github.com/Coff0xc/lobster-guard.git
cd lobster-guard
go build -o lobster-guard ./cmd/lobster-guard/
./lobster-guard --help
```

### 方式三：交叉编译全平台

```bash
make release   # 编译 5 个平台
make dist      # 打包发行包
make checksum  # 生成 SHA256 校验和
```


---

## 快速开始

```bash
# 1. 全量扫描（最常用）
./lobster-guard scan -t 10.0.0.5:18789

# 2. 带 Token 扫描（覆盖更多检测项）
./lobster-guard scan -t 10.0.0.5:18789 --token "your-gateway-token"

# 3. 扫描并生成 HTML 报告
./lobster-guard scan -t 10.0.0.5:18789 -o report.html

# 4. 启动 TUI 仪表盘（实时可视化）
./lobster-guard tui

# 5. 启动交互式 Shell
./lobster-guard shell
```

---

## 完整使用教程

### 1. 全量扫描

`scan` 是最常用的命令，自动执行完整流水线：指纹识别 → 认证检测 → 爆破 → 信息收集 → 配置审计 → DAG 攻击链。

```bash
# 基础扫描
./lobster-guard scan -t 10.0.0.5:18789

# 带认证令牌（解锁更多检测项：配置审计、密钥提取等）
./lobster-guard scan -t 10.0.0.5:18789 --token "sk-xxx"

# TLS 加密连接
./lobster-guard scan -t 10.0.0.5:443 --tls

# 激进模式（最大并发，无延迟）
./lobster-guard scan -t 10.0.0.5:18789 --aggressive

# 多目标并发扫描
./lobster-guard scan -T targets.txt -c 10

# 扫描 + 输出报告
./lobster-guard scan -t 10.0.0.5:18789 -o result.html    # HTML 报告
./lobster-guard scan -t 10.0.0.5:18789 -o result.json    # JSON 报告

# 跳过爆破（加快速度）
./lobster-guard scan -t 10.0.0.5:18789 --no-brute

# 仅漏洞利用，跳过 exploit 阶段
./lobster-guard scan -t 10.0.0.5:18789 --no-exploit

# AI 分析扫描结果（需要 API Key）
./lobster-guard scan -t 10.0.0.5:18789 --ai-analyze
```

**targets.txt 格式：**
```
10.0.0.1:18789
10.0.0.2:18789
192.168.1.100:3000
```


### 2. 模块化扫描

不想跑全量？可以单独运行某个模块：

```bash
# 指纹识别 — 检测目标是否为 OpenClaw，提取版本
./lobster-guard fingerprint -t 10.0.0.5:18789

# 认证检测 — 无认证访问 + Token 爆破
./lobster-guard auth -t 10.0.0.5:18789
./lobster-guard auth -t 10.0.0.5:18789 -w custom_dict.txt  # 自定义字典
./lobster-guard auth -t 10.0.0.5:18789 --no-brute          # 跳过爆破

# 信息收集 — 端点枚举 + WS 方法发现 + 版本探测
./lobster-guard recon -t 10.0.0.5:18789 --token "tok"

# 配置审计 — 安全配置检查（需要 Token）
./lobster-guard audit -t 10.0.0.5:18789 --token "tok"
```

### 3. DAG 攻击链

55 条攻击链通过 DAG（有向无环图）编排，自动处理依赖关系，同层并行执行。

```bash
# 执行全部 60 条攻击链
./lobster-guard exploit -t 10.0.0.5:18789 --token "tok"

# 运行单条攻击链（按 ID）
./lobster-guard exploit -t 10.0.0.5:18789 --chain-id 7     # 仅 RCE 可达性
./lobster-guard exploit -t 10.0.0.5:18789 --chain-id 30    # 完整 RCE 链

# 激进模式（最大并发，无延迟）
./lobster-guard exploit -t 10.0.0.5:18789 --aggressive

# 极限模式（200 并发，无速率限制）
./lobster-guard exploit -t 10.0.0.5:18789 --ultra-aggressive

# 指定 Worker 数量
./lobster-guard exploit -t 10.0.0.5:18789 --workers 20

# 速率限制
./lobster-guard exploit -t 10.0.0.5:18789 --rate-limit 10  # 每秒 10 请求

# OOB 回调（SSRF 检测）
./lobster-guard exploit -t 10.0.0.5:18789 --callback "http://your-oob-server.com"

# Hook 注入测试
./lobster-guard exploit -t 10.0.0.5:18789 --hook-path "/webhooks" --hook-token "htok"
```

### 4. AI 模糊测试

使用 AI 生成智能 payload，覆盖 5 类漏洞：

```bash
# 全类别 Fuzz
./lobster-guard fuzz -t 10.0.0.5:18789 --token "tok"

# 指定类别
./lobster-guard fuzz -t 10.0.0.5:18789 --token "tok" --categories xss,sqli
./lobster-guard fuzz -t 10.0.0.5:18789 --token "tok" --categories ssrf,cmdi
./lobster-guard fuzz -t 10.0.0.5:18789 --token "tok" --categories prompt_inject
```

支持的类别：`xss` / `sqli` / `ssrf` / `cmdi` / `prompt_inject`

> 需要设置环境变量 `ANTHROPIC_API_KEY` 或 `OPENAI_API_KEY`

### 5. CVE 漏洞库

内置 OpenClaw / Open-WebUI 相关 CVE 数据库：

```bash
# 查看所有已知 CVE
./lobster-guard cve
```

### 6. 资产发现

通过 Shodan / FOFA 搜索互联网上的 OpenClaw 实例：

```bash
# Shodan 搜索
./lobster-guard discover --shodan-key "YOUR_SHODAN_KEY"

# FOFA 搜索
./lobster-guard discover --fofa-email "you@example.com" --fofa-key "YOUR_FOFA_KEY"

# 自定义搜索语句
./lobster-guard discover --shodan-key "KEY" --query "openclaw port:18789"

# 输出到文件，然后批量扫描
./lobster-guard discover --shodan-key "KEY" -o targets.txt
./lobster-guard scan -T targets.txt -c 10 -o report.html
```

### 7. 报告输出

`-o` 参数根据文件扩展名自动选择格式：

```bash
# HTML 报告（可视化，适合分享）
./lobster-guard scan -t 10.0.0.5:18789 -o report.html

# JSON 报告（结构化，适合程序处理）
./lobster-guard scan -t 10.0.0.5:18789 -o report.json
```

所有带 `-o` 参数的命令都支持此特性：`scan` / `exploit` / `fuzz` / `auth` / `recon` / `audit` / `fingerprint`


### 8. TUI 仪表盘

全新的交互式终端界面，实时可视化扫描过程：

```bash
# 启动 TUI
./lobster-guard tui

# 预设目标启动
./lobster-guard tui -t 10.0.0.5:18789 --token "tok" --tls
```

**界面布局：**

```
┌─ LobsterGuard v4.0.0 ── target:10.0.0.5:3000 ── token:abc...z ── TLS:ON ─┐
├─ 攻击链进度 [12/55] ──────────────┬─ 漏洞发现 (4) [排序:严重度] ──────────┤
│ ✓ #00 Platform Fingerprint   0.3s │ CRIT │ eval inject   │ RCE via eval   │
│ ✓ #01 SSRF + cloud meta     1.2s │ HIGH │ SSRF          │ Cloud metadata │
│ ▸ #02 eval() injection      ...  │ MED  │ CORS          │ Wildcard origin│
│ ◦ #03 API key theft         pend │ LOW  │ Log disclosure│ Version header │
│ ════════════▒▒▒▒░░░░ 12/55       │      │               │                │
├─ 日志 (42 行) ─────────────────────┴────────────────────────────────────────┤
│ [14:32:01] 阶段 1: 指纹识别...                                             │
│ [14:32:02] 检测到 OpenClaw: v0.50.5                                        │
│ [14:32:03] 阶段 5: DAG 攻击链...                                           │
├─ lobster🦞> scan                                                            │
└─ tab:下一面板  /:命令  s:排序  e:导出  C-x:取消扫描  q:退出 ──────────────┘
```

**TUI 命令：**

| 命令 | 说明 |
|------|------|
| `target <host:port>` | 设置扫描目标 |
| `token <value>` | 设置认证令牌 |
| `tls on\|off` | 切换 TLS 加密 |
| `timeout <秒数>` | 设置超时时间 |
| `scan` | 完整流水线 (指纹+认证+DAG攻击链) |
| `exploit [chain_id]` | DAG 攻击链 (可指定单条) |
| `fingerprint` | 仅平台指纹识别 |
| `auth` | 仅认证检测 |
| `recon` | 仅信息收集 |
| `audit` | 仅配置审计 |
| `cancel` | 取消当前扫描 |
| `export [路径]` | 导出报告 (.json/.html 自动识别) |
| `clear` | 清空日志 |
| `status` | 显示当前状态 |
| `help` | 显示帮助 |

**快捷键：**

| 键 | 说明 |
|----|------|
| `Tab` / `Shift+Tab` | 切换面板 |
| `/` | 聚焦命令输入 |
| `Esc` | 取消聚焦 |
| `j/k` 或 `↑/↓` | 上下滚动 |
| `g` / `G` | 跳到顶部 / 底部 |
| `s` | 切换排序 (严重度/模块/时间) |
| `e` | 快速导出报告 |
| `Enter` | 查看漏洞详情 |
| `?` | 显示完整帮助覆盖层 |
| `1/2/3/4` | 直接切换面板 (进度/漏洞/日志/输入) |
| `Ctrl+D` / `Ctrl+U` | 向下/向上翻页 (10行) |
| `鼠标滚轮` | 滚动当前面板 |
| `Ctrl+X` | 取消扫描 |
| `q` / `Ctrl+C` | 退出 |

### 9. 交互式 Shell

msfconsole 风格的命令行交互界面：

```
$ ./lobster-guard shell

lobster🦞> target 10.0.0.5:18789
[*] 目标已设置: 10.0.0.5:18789

lobster🦞> token my-gateway-token
[*] Token 已更新

lobster🦞> scan
[*] 开始 scan 扫描 10.0.0.5:18789 ...
[*] 阶段 1: 指纹识别...
[+] 检测到 OpenClaw: v0.50.5
...

lobster🦞> exploit 7
[*] 执行攻击链 #7 ...

lobster🦞> export report.html
[+] 已导出 12 个发现至 report.html
```

### 10. MCP Server

LobsterGuard 内置 MCP (Model Context Protocol) Server，可供 AI Agent（如 Claude、Cursor 等）直接调用：

```bash
# 启动 MCP Server（stdio JSON-RPC 模式）
./lobster-guard mcp
```

AI Agent 可通过 JSON-RPC 调用扫描、exploit、报告等功能，实现 AI 驱动的安全评估。

### 11. 提取内嵌资源

v4.1.0 将 Nuclei 模板和爆破字典内嵌到二进制文件中，无需额外携带文件。使用 `extract` 命令可将内嵌资源释放到磁盘：

```bash
# 提取所有内嵌资源到当前目录
./lobster-guard extract

# 提取到指定目录
./lobster-guard extract -d /tmp/lobster-assets
```

提取后的文件结构：
```
./nuclei-templates/          # 45 个 Nuclei YAML 模板
  ├── *.yaml                 # 23 个主模板
  ├── v3/*.yaml              # 7 个 v3 模板
  └── v4/*.yaml              # 15 个 v4 CVE-2026 模板
./rules/
  └── default_creds.txt      # 默认凭据字典
```

提取后可直接用于 Nuclei 扫描或自定义字典爆破：
```bash
./lobster-guard extract -d ./assets
nuclei -t ./assets/nuclei-templates/ -u http://target:18789
./lobster-guard auth -t target:18789 -w ./assets/rules/default_creds.txt
```


---

## 60 条 DAG 攻击链

v4.1.0 通过 DAG（有向无环图）编排攻击链，自动处理依赖关系，同层并行执行。

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
| 31 | ClawJacked WS | Critical | CVE-2026: WS Token 窃取 |
| 32 | Gateway URL SSRF | Critical | CVE-2026: Gateway URL 覆盖 SSRF |
| 33 | Keychain 命令注入 | Critical | CVE-2026: Keychain 命令注入 |
| 34 | 浏览器上传穿越 | Critical | CVE-2026: 浏览器上传路径穿越 |
| 35 | Cron Webhook SSRF | High | CVE-2026: Cron Webhook SSRF |
| 36 | 执行竞态 TOCTOU | Critical | CVE-2026: 执行审批竞态条件 |
| 37 | 链接模板注入 | High | CVE-2026: 链接模板注入 |
| 38 | 媒体 SSRF | High | CVE-2026: 媒体处理 SSRF |
| 39 | 内存数据泄露 | High | CVE-2026: 内存数据泄露 |
| 40 | OAuth Token 窃取 | Critical | CVE-2026: OAuth Token 窃取 |
| 41 | QMD 命令注入 | Critical | CVE-2026: QMD 命令注入 |
| 42 | 工具目录枚举 | Medium | tools.catalog 信息泄露 |
| 43 | 计算机使用滥用 | Critical | computer_use 工具未授权调用 |
| 44 | 零认证 SSRF | Critical | 无需 Token 的 SSRF 链 |
| 45 | 零认证 RCE | Critical | 无需 Token 的 RCE 链 |
| 46 | 零认证密钥窃取 | Critical | 无需 Token 的密钥提取 |
| 47 | 零认证 Agent 注入 | Critical | 无需 Token 的 Agent 后门 |
| 48 | 零认证会话劫持 | High | 无需 Token 的会话窃取 |
| 49 | 零认证配置篡改 | High | 无需 Token 的配置写入 |
| 50 | 零认证 Patch 逃逸 | Critical | 无需 Token 的文件写入 |
| 51 | 零认证 Hook 注入 | Critical | 无需 Token 的 Webhook 利用 |
| 52 | 零认证审批劫持 | Critical | 无需 Token 的审批绕过 |
| 53 | 零认证完整 RCE | Critical | 无需 Token 的完整 RCE 链 |
| 54 | 全链路验证 | Critical | 端到端: 指纹→认证→利用→持久化 |
| 55 | **CSS 隐藏内容 (蜜罐)** | High | PwnKit: CSS/aria-hidden 对抗性 payload 检测 |
| 56 | **Skill 文件投毒** | Critical | PwnKit: 恶意 Skill 文件注入 (XML/Shell/C2) |
| 57 | **bypass_soul 参数注入** | Critical | PwnKit: 安全护栏绕过参数注入测试 |
| 58 | **C2 外泄命令过滤** | Critical | PwnKit: curl/wget/nc 外泄命令执行检测 |
| 59 | **Webhook 签名验证** | High | PwnKit: Webhook 签名/来源/重放验证 |


---

## Nuclei 模板

45 个即用模板（23 主模板 + 7 v3 模板 + 15 v4 CVE-2026 模板），可直接集成 CI/CD：

```bash
# 扫描单个目标
nuclei -t nuclei-templates/ -u http://10.0.0.5:18789

# 扫描目标列表
nuclei -t nuclei-templates/ -l targets.txt

# 仅 Critical 级别
nuclei -t nuclei-templates/ -u http://10.0.0.5:18789 -severity critical

# 仅 v4 CVE-2026 模板
nuclei -t nuclei-templates/v4/ -u http://10.0.0.5:18789
```

覆盖：实例检测、无认证、默认 Token、弱 Token、CORS、会话暴露、执行审批、Webhook、OAuth 重定向、WebSocket、Slack/Mattermost/Discord 注入、Responses API、Agent 文件、流氓节点、密钥解析、会话窃取、完整 RCE、ClawJacked WS Token 窃取、Gateway URL SSRF、Keychain 命令注入、浏览器上传穿越等。

---

## 环境变量

| 变量 | 说明 |
|------|------|
| `LOBSTERGUARD_TOKEN` | Gateway 认证令牌（`--token` 未指定时的回退值） |
| `ANTHROPIC_API_KEY` | Anthropic API Key（`--ai-analyze` 和 `fuzz` 命令需要） |
| `OPENAI_API_KEY` | OpenAI API Key（`--ai-analyze` 和 `fuzz` 命令的备选） |

```bash
# 设置 Token 环境变量，避免每次输入
export LOBSTERGUARD_TOKEN="your-gateway-token"
./lobster-guard scan -t 10.0.0.5:18789

# 启用 AI 分析
export ANTHROPIC_API_KEY="sk-ant-xxx"
./lobster-guard scan -t 10.0.0.5:18789 --ai-analyze
./lobster-guard fuzz -t 10.0.0.5:18789 --token "tok"
```

---

## 项目结构

```
lobster-guard/
├── cmd/lobster-guard/        # CLI 入口 (Cobra)
├── internal/
│   └── assets/              # 内嵌资源 (Nuclei 模板 + 字典, go generate)
├── pkg/
│   ├── ai/                   # LLM 集成 (Anthropic/OpenAI)
│   ├── audit/                # 配置审计 (15+ 检查项)
│   ├── auth/                 # 无认证检测 + Token 爆破
│   ├── chain/                # DAG 攻击链编排 (60 条链)
│   ├── concurrent/           # 优先队列 + 速率限制 + Worker 池
│   ├── cve/                  # 内置 CVE 漏洞库
│   ├── discovery/            # Shodan/FOFA 资产发现
│   ├── exploit/              # 63 个 Exploit 模块
│   ├── fuzzer/               # AI 模糊测试引擎
│   ├── interactive/          # msfconsole 风格交互式 Shell
│   ├── mcp/                  # MCP Server (JSON-RPC stdio)
│   ├── recon/                # 端点 + WS 方法枚举
│   ├── report/               # JSON + HTML 报告生成
│   ├── scanner/              # 指纹识别引擎
│   ├── tui/                  # TUI 仪表盘 (Bubble Tea)
│   └── utils/                # HTTP/WS 客户端, 类型定义
├── nuclei-templates/         # 45 个 Nuclei YAML 模板
│   ├── v3/                   # v3 模板 (7 个)
│   └── v4/                   # v4 CVE-2026 模板 (15 个)
├── rules/                    # 默认凭据字典
├── scripts/                  # 打包脚本
└── Makefile                  # 构建 + 打包 + 测试
```

---

## 免责声明

本工具仅用于**授权安全测试**。请仅对您拥有或获得明确书面授权的系统进行测试。未经授权访问计算机系统属于违法行为。作者不对任何滥用行为承担责任。

## 作者

**coff0xc**

## 许可证

[GPL-3.0](LICENSE)
