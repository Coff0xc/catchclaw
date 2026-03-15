<h1 align="center">🦞 LobsterGuard</h1>

<p align="center">
  <b>OpenClaw 専用セキュリティ評価ツール</b><br>
  <sub>31 攻撃チェーン | 23 Nuclei テンプレート | インタラクティブシェル | Shodan/FOFA アセット探索 | フルパイプライン自動化</sub>
</p>

<p align="center">
  <a href="README.md">简体中文</a> ·
  <a href="README_EN.md">English</a> ·
  <b>日本語</b> ·
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

## 主な特徴

```
┌──────────────────────────────────────────────────────────────────────────┐
│                        LobsterGuard v1.0.0                              │
├──────────────────────────────────────────────────────────────────────────┤
│  ● 31 攻撃チェーン  ● 30 エクスプロイトモジュール  ● 23 Nuclei テンプレート  │
│  ● インタラクティブシェル  ● Shodan/FOFA 探索  ● JSON + HTML レポート    │
│  ● WebSocket 完全対応  ● 無認証フィンガープリント  ● マルチターゲット並列処理  │
├──────────────────────────────────────────────────────────────────────────┤
│  攻撃対象: Gateway WS API | HTTP REST | OAuth | Webhook | ノードペアリング   │
│  カバレッジ: SSRF | RCE | キー窃取 | セッションハイジャック | 権限昇格 | 永続化 | データ漏洩   │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 目次

- [概要](#概要)
- [コア機能](#コア機能)
- [クイックスタート](#クイックスタート)
- [使い方](#使い方)
- [インタラクティブシェル](#インタラクティブシェル)
- [31 攻撃チェーン](#31-攻撃チェーン)
- [Nuclei テンプレート](#nuclei-テンプレート)
- [アセット探索](#アセット探索)
- [プロジェクト構成](#プロジェクト構成)
- [免責事項](#免責事項)
- [作者](#作者)
- [ライセンス](#ライセンス)

---

## 概要

**LobsterGuard** は、オープンソース AI コーディングエージェントプラットフォーム [OpenClaw](https://github.com/anthropics/open-claw) を専門に対象とした自動ペネトレーションテストツールです。アセット探索から RCE 検証までの完全な攻撃ライフサイクルをカバーし、31 のチェーン型エクスプロイトモジュールを使用して OpenClaw Gateway WebSocket API、HTTP エンドポイント、および統合インターフェースのセキュリティを包括的にテストします。

### なぜ LobsterGuard なのか？

| シナリオ | 手動テスト | LobsterGuard |
|----------|-----------|-------------|
| **ターゲット発見** | Shodan/FOFA を手動検索 | `discover` ワンクリック集約 |
| **インスタンス識別** | HTTP を一つずつ探索 | 無認証の自動フィンガープリント |
| **認証テスト** | カスタムブルートフォーススクリプトを作成 | 組み込みワードリスト + スマート遅延 |
| **脆弱性検証** | PoC を一つずつ手動作成 | 31 チェーン自動検証 |
| **攻撃対象カバレッジ** | 経験依存 | WS + HTTP + OAuth + Webhook + ノード完全対応 |
| **レポート出力** | 手動作成 | JSON + HTML ワンクリック生成 |
| **CI/CD 統合** | なし | 23 Nuclei テンプレートをプラグアンドプレイ |

---

## コア機能

<table>
<tr>
<td width="50%">

### 偵察と発見

- **Shodan / FOFA アセット探索** — インターネット全体の OpenClaw インスタンス検索
- **無認証フィンガープリント** — OpenClaw を自動検出してバージョン情報を抽出
- **HTTP エンドポイント列挙** — 包括的な REST API ルートスキャン
- **WebSocket メソッド発見** — 利用可能な Gateway WS メソッドを列挙
- **認証モード検出** — 無認証 / トークン / OAuth モードを識別

</td>
<td width="50%">

### 攻撃とエクスプロイト

- **31 攻撃チェーン** — SSRF から完全 RCE チェーンまで
- **自動エクスプロイトオーケストレーション** — チェーンオーケストレーターが順次実行
- **自己承認 RCE** — exec.approval.request → 自己承認 → node.invoke
- **キー窃取** — secrets.resolve / talk.config / API キー抽出
- **永続的バックドア** — エージェント注入 + ファイル書き込み + Cron バイパス

</td>
</tr>
<tr>
<td width="50%">

### セキュリティ監査

- **15 以上の設定監査項目** — 認証、権限、暗号化、ログ記録など
- **トークンブルートフォース** — 組み込み高頻度弱パスワードワードリスト + カスタムワードリスト
- **CORS 検出** — Origin リフレクション + 認証情報漏洩検証
- **OAuth セキュリティ** — リダイレクトハイジャック + State 固定攻撃

</td>
<td width="50%">

### ツールとレポート

- **インタラクティブシェル** — msfconsole スタイルの REPL、チェーンごとの実行
- **23 Nuclei テンプレート** — CI/CD パイプラインへの直接統合
- **JSON + HTML レポート** — 深刻度分類 + 修正アドバイス
- **マルチターゲット並列処理** — `-c` フラグで並列数を制御

</td>
</tr>
</table>

---

## クイックスタート

### 要件

- Go 1.22+
- ネットワーク到達可能な OpenClaw インスタンス

### ビルドとインストール

```bash
git clone https://github.com/Coff0xc/lobster-guard.git
cd lobster-guard
go build -o lobster-guard ./cmd/lobster-guard/
```

### 基本的な使い方

```bash
# フルスキャン
./lobster-guard scan -t 10.0.0.1:18789

# トークン付きスキャン
./lobster-guard scan -t 10.0.0.1:18789 --token "your-gateway-token"

# エクスプロイトのみ
./lobster-guard exploit -t 10.0.0.1:18789 --token "tok"

# インタラクティブシェル
./lobster-guard shell
```

---

## 使い方

```
使い方:
  lobster-guard [command]

コマンド:
  scan          フルパイプライン: フィンガープリント + 認証 + ブルートフォース + 偵察 + 監査 + エクスプロイト
  fingerprint   OpenClaw インスタンスを検出
  auth          認証テスト: 無認証検出 + トークンブルートフォース
  recon         エンドポイント列挙 + WS メソッド発見 + バージョン検出
  audit         設定監査 (トークン必須)
  exploit       31 攻撃チェーンをすべて実行
  discover      Shodan/FOFA アセット探索
  shell         インタラクティブシェル (msfconsole スタイル)

フラグ:
  -t, --target string     ターゲット host:port
  -T, --targets string    ターゲットリストファイル (1行1件)
  -c, --concurrency int   並列スキャン数 (デフォルト 1)
  -o, --output string     JSON レポート出力パス
      --token string      Gateway Token
      --tls               HTTPS/WSS を使用
      --timeout int       HTTP タイムアウト秒数 (デフォルト 10)
```

---

## インタラクティブシェル

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

## 31 攻撃チェーン

| # | チェーン | 深刻度 | 説明 |
|---|---------|--------|------|
| 0 | プラットフォームフィンガープリント | Info | 無認証 OpenClaw 検出 |
| 1 | SSRF | Critical | browser.request/navigate → クラウドメタデータ (AWS/GCP/Azure/DO) |
| 2 | eval() インジェクション | Critical | ツールパラメータ経由の eval/exec コード実行 |
| 3 | API キー窃取 | Critical | config/env エンドポイント経由でプロバイダー API キーを抽出 |
| 4 | ペアリングコードブルートフォース | High | DM ペアリングコード 6 桁ブルートフォース |
| 5 | Cron バイパス | High | Cron ブラックリストバイパス + 永続化 |
| 6 | プロンプトインジェクション | High | システムプロンプト抽出 + 命令上書き |
| 7 | RCE 到達可能性 | Critical | system.run コマンド実行プローブ |
| 8 | フックインジェクション | Critical | Webhook エンドポイント注入によるコマンド実行 |
| 9 | シークレット抽出 | Critical | secrets.list + secrets.get 平文窃取 |
| 10 | 設定改ざん | High | config.set によるセキュリティ設定への書き込み |
| 11 | 直接ツール呼び出し | Critical | tools.invoke が Chat レイヤーのセキュリティをバイパス |
| 12 | セッションハイジャック | High | sessions.preview IDOR + クロスセッションインジェクション |
| 13 | CORS バイパス | Medium | Origin リフレクション → クロスオリジン WS/API アクセス |
| 14 | チャンネルインジェクション | High | Mattermost/Slack/Discord 未署名コマンドインジェクション |
| 15 | ログ漏洩 | Medium | logs.query による認証情報/機密データ露出 |
| 16 | パッチエスケープ | Critical | apply_patch パストラバーサル → 任意ファイル書き込み |
| 17 | WS ハイジャック | High | クロスオリジン WebSocket アップグレード + トークンリプレイ |
| 18 | エージェントインジェクション | Critical | agents.create/update バックドア + システムプロンプト漏洩 |
| 19 | OAuth 悪用 | High | Slack OAuth リダイレクトハイジャック + State 固定 |
| 20 | Responses API | Critical | /v1/responses 認証バイパス + ツールインジェクション |
| 21 | WS ファジング | Medium | 不正形式 JSON-RPC + メソッドインジェクション |
| 22 | エージェントファイルインジェクション | Critical | agents.files.set 永続的プロンプトバックドア |
| 23 | セッションファイル書き込み | Critical | sessions.patch + compact による任意ファイル書き込み |
| 24 | 承認ハイジャック | Critical | プレフィックス ID マッチング + 実行ポリシー改ざん |
| 25 | Talk シークレット | Critical | talk.config(includeSecrets) による API キー窃取 |
| 26 | ブラウザ SSRF | High | browser.request 内部ディスパッチ |
| 27 | Secrets Resolve | Critical | secrets.resolve 平文抽出 (内部インジェクション API) |
| 28 | セッション記録窃取 | High | 未サニタイズのセッション履歴 + ツール出力窃取 |
| 29 | 不正ノード | Critical | 自己承認ノードペアリング → コマンドインターセプト |
| 30 | 完全 RCE | Critical | nodes.list → 自己承認 → node.invoke system.run |

---

## Nuclei テンプレート

すぐに使える 23 テンプレートを CI/CD に直接統合できます:

```bash
# 単一ターゲットをスキャン
nuclei -t nuclei-templates/ -u http://10.0.0.1:18789

# ターゲットリストをスキャン
nuclei -t nuclei-templates/ -l targets.txt

# Critical のみ
nuclei -t nuclei-templates/ -u http://target:18789 -severity critical
```

カバレッジ: インスタンス検出、無認証、デフォルトトークン、弱トークン、CORS、セッション露出、実行承認、Webhook、OAuth リダイレクト、WebSocket、Slack/Mattermost/Discord インジェクション、Responses API、エージェントファイル、不正ノード、シークレット解決、セッション窃取、完全 RCE など。

---

## アセット探索

```bash
# Shodan
./lobster-guard discover --shodan-key "YOUR_KEY" -o targets.txt

# FOFA
./lobster-guard discover --fofa-email "you@x.com" --fofa-key "KEY" -o targets.txt

# 発見したすべてのターゲットをスキャン
./lobster-guard scan -T targets.txt -c 10
```

---

## プロジェクト構成

```
lobster-guard/
├── cmd/lobster-guard/     # CLI エントリーポイント
├── pkg/
│   ├── audit/             # 設定監査
│   ├── auth/              # 無認証検出 + トークンブルートフォース
│   ├── chain/             # 攻撃チェーンオーケストレーター
│   ├── discovery/         # Shodan/FOFA アセット探索
│   ├── exploit/           # 30 エクスプロイトモジュール (4500+ 行)
│   ├── interactive/       # msfconsole スタイルのインタラクティブシェル
│   ├── recon/             # エンドポイント + WS メソッド列挙
│   ├── report/            # JSON + HTML レポート生成
│   ├── scanner/           # フィンガープリントエンジン
│   └── utils/             # HTTP クライアント、WS クライアント、型定義
├── nuclei-templates/      # 23 Nuclei YAML テンプレート
└── rules/                 # デフォルト認証情報ワードリスト
```

---

## 免責事項

このツールは**認可されたセキュリティテストのみ**を目的としています。自分が所有するシステム、または明示的な書面による許可を得たシステムのみをテストしてください。コンピューターシステムへの不正アクセスは違法です。作者はいかなる悪用に対しても責任を負いません。

## 作者

**coff0xc**

## ライセンス

[GPL-3.0](LICENSE)

