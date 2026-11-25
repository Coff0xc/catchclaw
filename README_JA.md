<h1 align="center">🦞 CatchClaw v6.0.0</h1>

<p align="center">
  <b>マルチプラットフォーム AI エージェント セキュリティ評価ツール</b><br>
  <sub>OpenClaw · Open-WebUI · LibreChat · LobeChat · Dify · FastGPT · NextChat · AnythingLLM · Flowise · RAGFlow · Langflow · LiteLLM · Ollama · vLLM</sub><br>
  <sub>87 DAG攻撃チェーン | 87 Exploitモジュール | ATT&CKフェーズマッピング | Goroutine並行エンジン | 攻撃グラフ可視化</sub>
</p>

<p align="center">
  <a href="README.md">简体中文</a> ·
  <a href="README_EN.md">English</a> ·
  <a href="README_JA.md"><b>日本語</b></a> ·
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
  <img src="https://img.shields.io/badge/Version-5.3.0-blue?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/Go-Edition_2024-DEA584?style=flat-square&logo=rust&logoColor=white" alt="Go">
  <img src="https://img.shields.io/badge/DAG_Nodes-412-FF6B6B?style=flat-square" alt="Chains">
  <img src="https://img.shields.io/badge/Concurrency-Goroutines-4CAF50?style=flat-square" alt="Goroutines">
  <img src="https://img.shields.io/badge/Modules-412-orange?style=flat-square" alt="Exploits">
  <img src="https://img.shields.io/badge/Platforms-9-purple?style=flat-square" alt="Platforms">
  <img src="https://img.shields.io/badge/License-Non--Commercial--v2.0-green?style=flat-square" alt="License">
</p>

---

> **⚠️ 商用利用は厳禁**
>
> 本プロジェクトは **CatchClaw Strict Non-Commercial License v2.0** に基づいています。
>
> **著作権者 (Coff0xc) の書面による事前承認なしに、いかなる商用利用も厳禁です。** 違反者は法的責任を追及されます。
>
> 禁止行為には以下が含まれますが、これに限定されません：
> - ソフトウェアまたは派生物の販売、サブライセンス、リース
> - SaaS、ペネトレーションテストサービス、コンサルティング等での利用
> - 商用製品、プラットフォーム、ツールへの統合
> - 商用AI/MLモデルのトレーニング
> - リブランド、リパッケージ、ホワイトラベル配布
> - 直接的・間接的に収益を生むあらゆる行為
>
> **著作権者は、利益の全額回収、法的費用、懲罰的損害賠償を含む、時効なしの遡及的執行権を保持します。**
>
> 詳細は [LICENSE](LICENSE) を参照してください。

---

## ハイライト

```
┌────────────────────────────────────────────────────────────────────────────┐
│                          CatchClaw v6.0.0                                │
├────────────────────────────────────────────────────────────────────────────┤
│  ● 87 DAG攻撃チェーン   ● 87 Exploitモジュール  ● Goroutine並行エンジン    │
│  ● ATT&CK 9フェーズ    ● Mermaid攻撃グラフ     ● JSON/HTML/MDレポート    │
│  ● Kahnトポロジカルソート ● Semaphore並行制御    ● 条件/フォールバック     │
│  ● マルチターゲット(CIDR) ● ポートスキャン/発見   ● 200+外部ペイロード     │
│  ● 15プラットフォーム対応  ● 自動プラットフォーム識別 ● --platform指定スキャン │
├────────────────────────────────────────────────────────────────────────────┤
│  攻撃面: Gateway WS API | HTTP REST | OAuth | Webhook | Node Pairing     │
│  カバレッジ: SSRF | RCE | 鍵窃取 | セッション乗っ取り | 権限昇格 | 持続  │
│  新規: C2データ流出 | Skill汚染 | Agent注入 | MCP注入 | DNS Rebind         │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## 目次

- [概要](#概要)
- [主要機能](#主要機能)
- [対応プラットフォーム](#対応プラットフォーム)
- [インストール](#インストール)
- [クイックスタート](#クイックスタート)
- [CLI使用方法](#cli使用方法)
- [87 Exploitモジュール](#87-exploitモジュール)
- [DAG攻撃チェーンアーキテクチャ](#dag攻撃チェーンアーキテクチャ)
- [Nucleiテンプレート](#nucleiテンプレート)
- [プロジェクト構成](#プロジェクト構成)
- [免責事項](#免責事項)

---

## 概要

**CatchClaw** は、マルチプラットフォームAIエージェントセキュリティ評価のために構築されたGoベースの自動化ツールです。OpenClaw / Open-WebUI を中心に、LibreChat、LobeChat、Dify、FastGPT、NextChat、AnythingLLM、Flowise、RAGFlow を含む15つのプラットフォームをサポートしています。87のExploitモジュールをDAG（有向非巡回グラフ）攻撃チェーンで編成し、偵察からデータ流出までの完全なATT&CKライフサイクルをカバーします。

Go goroutine上で動作し、DAGエンジンはKahnのトポロジカルソートによるレベル別並行実行、Semaphoreによる並行度制御、条件実行とフォールバックノードをサポートします。攻撃結果はMermaidフローチャートとして可視化可能です。

---

## 主要機能

<table>
<tr>
<td width="50%">

### 攻撃エンジン

- **87 Exploitモジュール** — 10カテゴリ、`inventory`マクロ自動登録
- **87 DAG攻撃チェーン** — 9つのATT&CKフェーズで自動編成
- **Kahnトポロジカルソート** — 依存関係解決付きレベル別並行実行
- **条件/フォールバック** — 前段の結果に基づく動的パス決定
- **攻撃グラフ可視化** — ヒット/スキップ/フォールバック状態付きMermaid出力

</td>
<td width="50%">

### プロトコルサポート

- **WebSocket Gateway** — チャレンジハンドシェイク検出、JSON-RPCコール
- **HTTP REST** — OAuth 302誤検知防止のためリダイレクト無効化
- **誤検知排除** — チャレンジページ / SPAフォールバック / LLM拒否検出
- **TLSサポート** — rustlsバックエンド、`--tls`でHTTPS/WSS有効化
- **マルチフォーマットレポート** — JSON + HTML（ダークテーマ）+ Markdown

</td>
</tr>
<tr>
<td width="50%">

### スキャン機能強化

- **マルチターゲットスキャン** — CIDR (/24)、IP範囲、カンマ区切り、ターゲットファイル
- **ポートスキャン** — TCPコネクトスキャン + カスタムポート範囲
- **マルチプラットフォーム識別** — 15プラットフォーム自動フィンガープリント（API/WebSocket/ヘルスチェック）
- **200+ ペイロード** — SSRF/インジェクション/Prompt/Auth/XSS外部YAMLライブラリ
- **スキャン設定** — TOML設定ファイル + プロファイルプリセット + プロキシ対応

</td>
<td width="50%">

### CLI体験

- **`--profile`** — プリセットスキャン設定（quick/stealth/full）
- **`--severity-filter`** — 重大度でフィルタリング
- **`--format`** — 出力フォーマット: json/html/markdown
- **`--dry-run`** — スキャンせずにDAG実行計画をプレビュー
- **`--targets-file`** — バッチターゲットファイル入力
- **`--platform`** — ターゲットプラットフォーム指定（auto/openclaw/librechat/lobechat等）

</td>
</tr>
</table>

---

## 対応プラットフォーム

| プラットフォーム | 説明 | プローブモジュール |
|-----------------|------|-------------------|
| **OpenClaw** | Anthropic AI コーディングエージェントプラットフォーム | 内蔵（全モジュール） |
| **Open-WebUI** | オープンソース AI Web UI | 内蔵（全モジュール） |
| **LibreChat** | マルチプロバイダー AI チャットプラットフォーム | librechat_probe |
| **LobeChat** | オープンソース AI チャットフレームワーク | lobechat_probe |
| **Dify** | LLMアプリケーション開発プラットフォーム | dify_probe |
| **FastGPT** | ナレッジベース AI プラットフォーム | fastgpt_probe |
| **NextChat** | ChatGPT Web UI | nextchat_probe |
| **AnythingLLM** | オールインワン AI デスクトップアプリ | anythingllm_probe |
| **Flowise** | ドラッグ&ドロップ LLM フロービルダー | flowise_probe |
| **RAGFlow** | RAG ベースのナレッジエンジン | ragflow_probe |

---

## インストール

```bash
git clone https://github.com/Coff0xc/catchclaw.git
cd catchclaw/rust

# Releaseビルド（最適化 + シンボル削除）
go build -o catchclaw .

# バイナリ: target/release/catchclaw
```

**要件:** Go 1.22+ | Windows / Linux / macOS

---

## クイックスタート

```bash
# 登録モジュール一覧
catchclaw list

# フルスキャン
catchclaw scan -t ターゲットIP:ポート

# JSONレポート付きスキャン
catchclaw scan -t ターゲットIP:ポート -o report.json

# トークン付きスキャン
catchclaw scan -t ターゲットIP:ポート --token "your-gateway-token"

# HTMLレポート出力
catchclaw scan -t ターゲットIP:ポート -o report.html --format html

# マルチターゲットスキャン (CIDR)
catchclaw scan --targets "192.168.1.0/24:8080"

# ファイルからバッチスキャン
catchclaw scan -f targets.txt -o results.json

# プロファイル使用
catchclaw scan -t ターゲットIP:ポート --profile stealth

# 重大/高のみ表示
catchclaw scan -t ターゲットIP:ポート --severity-filter critical,high

# 実行計画プレビュー
catchclaw scan -t ターゲットIP:ポート --dry-run

# プラットフォーム指定スキャン
catchclaw scan -t ターゲットIP:ポート --platform librechat

# 完全攻撃チェーン実行
catchclaw exploit -t ターゲットIP:ポート --token xxx

# 単一チェーンノード実行
catchclaw exploit -t ターゲットIP:ポート --chain-id 30
```

---

## CLI使用方法

```
CatchClaw v6.0.0 — マルチプラットフォーム AIエージェント セキュリティ評価ツール

Usage: catchclaw <COMMAND>

Commands:
  scan      フルセキュリティスキャン（DAG構築 → 実行 → 集計）
  exploit   攻撃チェーン実行（完全DAGまたは単一ノード）
  list      登録済み全Exploitモジュール一覧
  config    設定ファイルの生成または検証

Scan Flags:
  -t, --target <HOST:PORT>     ターゲットアドレス
      --targets <TARGETS>      マルチターゲット (CIDR、範囲、カンマ区切り)
  -f, --targets-file <FILE>    ターゲットファイル (1行1ターゲット)
      --token <TOKEN>          Gatewayトークン (またはCATCHCLAW_TOKEN環境変数)
      --timeout <SECS>         リクエストタイムアウト秒数 (デフォルト10)
  -o, --output <FILE>          レポート出力パス
      --format <FORMAT>        出力フォーマット: json/html/markdown (デフォルトjson)
      --profile <PROFILE>      スキャンプロファイル: quick/stealth/full
      --severity-filter <LVL>  重大度フィルタ (例: critical,high)
      --dry-run                実行せずにDAG計画をプレビュー
      --concurrency <N>        最大並行ワーカー数 (デフォルト10)
      --tls                    HTTPS/WSS使用
      --callback <URL>         SSRFコールバックURL
      --config <FILE>          TOML設定ファイル
      --platform <PLATFORM>    ターゲットプラットフォーム: auto/openclaw/librechat/lobechat/dify/fastgpt/nextchat/anythingllm/flowise/ragflow (デフォルトauto)

Exploit Flags:
  -t, --target <HOST:PORT>     ターゲットアドレス
      --token <TOKEN>          Gatewayトークン
      --chain-id <ID>          特定チェーンノードIDを実行
      --concurrency <N>        最大並行ワーカー数 (デフォルト10)
      --tls                    HTTPS/WSS使用
```

---

## 87 Exploitモジュール

ATT&CKフェーズと攻撃カテゴリ別:

| フェーズ | モジュール数 | 主要モジュール |
|---------|------------|-------------|
| **Recon** | 14 | cors_bypass, ws_hijack, auth_mode_abuse, log_disclosure, hidden_content, origin_wildcard, librechat_probe, lobechat_probe, dify_probe, fastgpt_probe, nextchat_probe, anythingllm_probe, flowise_probe, ragflow_probe |
| **Initial Access** | 13 | ssrf, eval_inject, prompt_inject, mcp_inject, pairing_brute, oauth_abuse, responses_exploit, ws_fuzz, acp_bypass, ssrf_rebind, ssrf_proxy_bypass, browser_request, csrf_no_origin |
| **Credential Access** | 5 | apikey_steal, oauth_token_theft, secret_extract, secrets_resolve, talk_secrets |
| **Execution** | 7 | rce, hook_inject, tools_invoke, keychain_cmd_inject, qmd_cmd_inject, exec_race_toctou, exec_socket_leak |
| **Persistence** | 8 | agent_inject, agent_file_inject, channel_inject, skill_poison, cron_bypass, session_file_write, patch_escape, link_template_inject |
| **Privilege Escalation** | 5 | approval_hijack, config_tamper, rogue_node, silent_pair_abuse, auth_disable_leak |
| **Lateral/Exfil** | 15 | session_hijack, transcript_theft, memory_data_leak, c2_exfil, browser_upload_traversal, secret_exec_abuse, bypass_soul, marker_spoof, redact_bypass, obfuscation_bypass, unicode_bypass, ratelimit_scope_bypass, flood_guard_reset, webhook_verify, skill_scanner_bypass |

---

## DAG攻撃チェーンアーキテクチャ

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
                   │  RCE / Hook / Tools     │
                   └────────────┬────────────┘
                                │
                   ┌────────────┼────────────┐
                   ▼                         ▼
         ┌─────────────────┐       ┌─────────────────┐
         │ Level 3 (Persis)│       │ Level 3 (Priv)  │
         │ Agent / Cron    │       │ Approval / Node │
         └────────┬────────┘       └────────┬────────┘
                  └────────────┬────────────┘
                               ▼
                  ┌─────────────────────────┐
                  │   Level 4 (Exfil)       │
                  │  C2 / Transcript / Leak │
                  └─────────────────────────┘
```

**実行特性:** Kahnトポロジカルソート → レベル別並行実行 | Semaphore並行度制御 | `depends_on` 依存関係 | `fallback_for` フォールバック | `condition` 条件実行 | `AttackGraph` Mermaid出力

---

## Nucleiテンプレート

`nuclei-templates/` に24+のNuclei互換YAMLテンプレートを同梱:

```bash
nuclei -t nuclei-templates/ -u http://ターゲット:ポート
nuclei -t nuclei-templates/ -l targets.txt
nuclei -t nuclei-templates/ -u http://ターゲット:ポート -severity critical
```

---

## プロジェクト構成

```
catchclaw/
├── go/
│   ├── main.go                      # CLIエントリポイント
│   ├── go.mod                       # Goモジュール定義
│   └── internal/
│       ├── cli/                     # CLIコマンドとフラグ
│       ├── config/                  # 設定読み込み (YAML/TOML/JSON)
│       ├── core/                    # Target, Finding, Severity, DAGエンジン
│       ├── exploit/                 # モジュールレジストリ + コンテキスト
│       │   └── modules/             # 87 Exploitモジュール実装
│       ├── platform/                # 15プラットフォーンプロファイル
│       ├── payload/                 # YAMLペイロードレジストリ + 変異
│       ├── nuclei/                  # Nucleiテンプレートランナー
│       ├── scan/                    # スキャン編成 + サービス発見
│       ├── report/                  # JSON/HTML/Markdown/Mermaid出力
│       └── utils/                   # HTTPクライアント、誤検知フィルタ、WS
├── payloads/                        # 200+外部ペイロード (YAML)
├── nuclei-templates/                # 24のNuclei YAMLテンプレート
├── LICENSE                          # CatchClaw Strict Non-Commercial License v2.0
└── README.md
```

---

## 免責事項

本ツールは**許可されたセキュリティテスト**のみを目的としています。所有または明示的な書面による許可を得たシステムのみテストしてください。コンピュータシステムへの不正アクセスは違法です。作者はいかなる悪用に対しても責任を負いません。

## 著者

**Coff0xc** — [https://github.com/Coff0xc](https://github.com/Coff0xc)

## ライセンス

[CatchClaw Strict Non-Commercial License v2.0](LICENSE) — 商用利用厳禁。
