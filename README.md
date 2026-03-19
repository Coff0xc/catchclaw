<h1 align="center">🦞 CatchClaw‌ v5.0.0</h1>

<p align="center">
  <b>OpenClaw / Open-WebUI AI 编程平台 — 自动化安全评估工具</b><br>
  <sub>59 条 DAG 攻击链 | 59 个 Exploit 模块 | Async Tokio 运行时 | WS Gateway | HTTP 探测 | JSON 报告</sub>
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
  <img src="https://img.shields.io/badge/Version-5.0.0-blue?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/Rust-1.75+-DEA584?style=flat-square&logo=rust&logoColor=white" alt="Rust">
  <img src="https://img.shields.io/badge/DAG_Chains-59-FF6B6B?style=flat-square" alt="Chains">
  <img src="https://img.shields.io/badge/Async-Tokio-4CAF50?style=flat-square" alt="Tokio">
  <img src="https://img.shields.io/badge/Exploits-59_Modules-orange?style=flat-square" alt="Exploits">
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


## 项目亮点

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                         CatchClaw v5.0.0                                  │
├──────────────────────────────────────────────────────────────────────────────┤
│  ● 59 条 DAG 攻击链     ● 59 个 Exploit 模块    ● Async Tokio 引擎       │
│  ● WS Gateway 客户端   ● HTTP 探测引擎        ● JSON 报告生成           │
│  ● 单二进制 4.3MB      ● 零依赖部署          ● ATT&CK 阶段映射         │
├──────────────────────────────────────────────────────────────────────────────┤
│  攻击面: Gateway WS API | HTTP REST | OAuth | Webhook | Node Pairing       │
│  覆盖: SSRF | RCE | 密钥窃取 | 会话劫持 | 提权 | 持久化 | 数据泄露       │
│  新增: C2 外泄 | Skill 投毒 | Agent 注入 | OAuth 窃取                  │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 目录

- [项目简介](#项目简介)
- [核心特性](#核心特性)
- [安装方式](#安装方式)
- [快速开始](#快速开始)
- [模块列表](#模块列表)
- [项目结构](#项目结构)

## 项目简介

CatchClaw 是一款基于 Rust 的 OpenClaw / Open-WebUI AI 编程平台安全评估工具。通过 59 条 DAG 攻击链和 59 个 Exploit 模块，覆盖从初始访问到数据泄露的完整 ATT&CK 攻击链路。

基于 Tokio 异步运行时，单二进制 4.3MB，零依赖部署。

## 核心特性

- **59 个 Exploit 模块** — 覆盖 SSRF、RCE、密钥窃取、会话劫持、提权、持久化、数据泄露
- **59 条 DAG 攻击链** — 5 个 ATT&CK 阶段自动编排（初始访问 → 凭证获取 → 执行 → 持久化 → 泄露）
- **Async Tokio 引擎** — 高并发异步扫描，原子计数器避免竞态
- **WS Gateway 客户端** — WebSocket 协议完整支持
- **HTTP 探测引擎** — REST API 端点自动探测
- **安全 UTF-8 处理** — truncate_str 防止运行时 panic
- **单二进制 4.3MB** — 零依赖，解压即用
- **JSON 报告** — 结构化扫描结果输出

## 安装方式

### 从源码构建

```bash
# 克隆仓库
git clone https://github.com/Coff0xc/catchclaw.git
cd catchclaw/rust

# 构建 Release 版本
cargo build --release

# 二进制位于 target/release/catchclaw
```

### 系统要求

- Rust 1.75+
- 支持 Windows / Linux / macOS

## 快速开始

```bash
# 查看所有模块
catchclaw list

# 全量扫描
catchclaw scan -t 目标IP:端口

# 扫描并输出报告
catchclaw scan -t 目标IP:端口 -o report.json

# 执行特定攻击链
catchclaw exploit -t 目标IP:端口 --token xxx
```

## 模块列表

59 个 Exploit 模块覆盖 6 大攻击类别：

| 类别 | 模块数 | 示例 |
|------|--------|------|
| Injection | 16 | MCP 注入、Prompt 注入、Agent 注入、Hook 注入、Eval 注入 |
| RCE | 9 | 完整 RCE、命令注入、文件写入、竞态条件、浏览器上传穿越 |
| SSRF | 5 | SSRF、DNS Rebind、代理绕过、浏览器请求 |
| Auth | 9 | OAuth 滥用、配对爆破、静默配对、审批劫持、ACP 绕过 |
| Credential | 5 | API Key 窃取、OAuth Token 窃取、密钥提取、会话劫持 |
| DataLeak | 7 | 记录窃取、日志泄露、内存数据泄露、C2 外泄 |
| Config/Transport | 8 | CORS 绕过、CSRF、WS 劫持、WS Fuzz、Webhook 验证 |

## 项目结构

```
catchclaw/
├── rust/
│   ├── Cargo.toml                # 项目配置
│   ├── Cargo.lock
│   └── src/
│       ├── main.rs               # CLI 入口 (clap)
│       ├── chain/                # DAG 攻击链编排引擎
│       │   ├── dag.rs            # DAG 执行器 + 拓扑排序
│       │   └── chains.rs         # 59 条攻击链定义
│       ├── config/               # 全局配置 + 协议常量
│       ├── exploit/              # 59 个 Exploit 模块
│       │   ├── base.rs           # ExploitCtx + Trait 定义
│       │   ├── registry.rs       # 自动注册宏
│       │   └── *.rs              # 各模块实现
│       ├── scan/                 # 扫描编排器
│       ├── report/               # JSON 报告生成
│       └── utils/                # HTTP/WS 客户端, 类型定义
├── scripts/
│   └── gen_dag_chains.py         # DAG 链生成脚本
├── LICENSE                           # CatchClaw Strict Non-Commercial License v2.0
└── README.md
```

---

## 免责声明

本工具仅用于**授权安全测试**。请仅对您拥有或获得明确书面授权的系统进行测试。未经授权访问计算机系统属于违法行为。作者不对任何滥用行为承担责任。

## 作者

**Coff0xc** — [https://github.com/Coff0xc](https://github.com/Coff0xc)

## 许可证

[CatchClaw Strict Non-Commercial License v2.0](LICENSE) — 严禁商业使用，违者必究。
