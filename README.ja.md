# Argus

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

> *セキュリティのための全てを見通す目*

[English README](README.md)

**Argus**は、AI を活用した攻撃対象領域の偵察ツールです。ギリシャ神話に登場する百の目を持つ巨人アルゴス・パノプテースにちなんで名付けられました。包括的なセキュリティスキャンとインテリジェントなリスク評価を提供します。

## 特徴

- **17種類以上のスキャナーモジュール**: DNS、WHOIS、ポート、SSL/TLS、メールセキュリティ、脆弱性など
- **AI分析**: Claude、GPT-4o、またはローカルOllamaモデルによるリスク評価
- **複数の出力形式**: リッチなターミナルテーブル、JSON、プロフェッショナルなHTMLレポート
- **非同期アーキテクチャ**: 設定可能なレート制限による高速な並行スキャン
- **REST API**: Swagger/ReDocドキュメント付きのFastAPIベースAPI
- **拡張性**: 簡単にカスタマイズできるプラグインベースのスキャナーアーキテクチャ

## スキャナーモジュール

| モジュール | 説明 | 主な機能 |
| ---------- | ---- | -------- |
| **dns** | DNS列挙 | A/AAAA/MX/NS/TXT/CNAME/SOA、サブドメイン発見、DNSSEC、ゾーン転送検出 |
| **whois** | WHOISルックアップ | 登録データ、レジストラ情報、有効期限 |
| **rdap** | RDAPプロトコル | 最新のWHOIS代替、ASNデータ |
| **ports** | ポートスキャン | 非同期TCPスキャン、サービス検出、設定可能なプロファイル (top 20/100/1000) |
| **webtech** | Web技術検出 | フレームワーク、CMS、サーバー情報、セキュリティヘッダー |
| **crtsh** | 証明書透明性 | CTログによるサブドメイン発見 |
| **ssl** | SSL/TLS分析 | 証明書情報、暗号スイート、プロトコルバージョン、SSL Labsグレード |
| **email** | メールセキュリティ | SPF/DKIM/DMARC検証、MTA-STS、TLS-RPT、セキュリティスコアリング |
| **security** | セキュリティスキャン | 公開ファイル、CORS、WAF検出、クラウドストレージ、アクチュエーターエンドポイント |
| **vuln** | 脆弱性 | CVE検出、CVSSスコアリング、重大度分類 |
| **js** | JavaScript分析 | シークレット抽出、APIエンドポイント発見 |
| **subdomain** | 拡張列挙 | 包括的なサブドメイン発見のための20以上のソース |
| **takeover** | 乗っ取り検出 | サブドメイン乗っ取り脆弱性チェック |
| **kev** | CISA KEV | 既知の悪用された脆弱性カタログとのマッチング |
| **headers** | HTTPヘッダー | セキュリティヘッダー分析とスコアリング |
| **discovery** | ディスカバリファイル | robots.txt、sitemap.xml、security.txt |
| **favicon** | Faviconフィンガープリント | MMH3ハッシュ、Shodan連携 |
| **asn** | ASNルックアップ | IPからASN、組織情報、位置情報 |
| **wayback** | Wayback Machine | 過去のURL抽出 |
| **graphql** | GraphQL検出 | イントロスペクション、機密フィールド、危険なミューテーション |

## インストール

### 前提条件

- Python 3.11以上
- [uv](https://github.com/astral-sh/uv)（推奨）またはpip

### インストール

```bash
# リポジトリをクローン
git clone https://github.com/ngc-shj/argus.git
cd argus

# uvでインストール（推奨）
uv sync

# 開発用依存関係を含めてインストール
uv sync --all-extras
```

## クイックスタート

### 基本スキャン

```bash
# デフォルトスキャン（dns、whois、ports、crtsh）
uv run argus scan example.com

# 全モジュールでフルスキャン
uv run argus scan example.com --full

# 特定のモジュールを指定
uv run argus scan example.com --modules dns,ports,ssl,email
```

### AI分析

```bash
# AI によるリスク評価（APIキーが必要）
uv run argus scan example.com --analyze

# 異なるAIプロバイダーの使用
uv run argus scan example.com --analyze --ai-provider anthropic  # Claude（デフォルト）
uv run argus scan example.com --analyze --ai-provider openai     # GPT-4o
uv run argus scan example.com --analyze --ai-provider ollama     # ローカルLLM
```

### 出力形式

```bash
# リッチなターミナルテーブル（デフォルト）
uv run argus scan example.com

# JSON出力
uv run argus scan example.com --format json --output report.json

# HTMLレポート
uv run argus scan example.com --html report.html
```

### 高度なオプション

```bash
# 拡張サブドメイン列挙（20以上のソース）
uv run argus scan example.com --extended-subdomains

# サブドメイン乗っ取り脆弱性のチェック
uv run argus scan example.com --takeover

# Wayback Machine URL抽出を含む（低速）
uv run argus scan example.com --wayback

# CISA KEVカタログチェック（デフォルトで有効）
uv run argus scan example.com --kev
```

## CLIリファレンス

```text
Usage: argus scan [OPTIONS] TARGET

Arguments:
  TARGET    対象のドメインまたはIPアドレス [必須]

Options:
  -m, --modules TEXT          実行するモジュール（カンマ区切り）
  -f, --full                  全モジュールを実行
  -a, --analyze               AI分析を有効化
  -p, --ai-provider TEXT      AIプロバイダー: anthropic, openai, ollama [デフォルト: anthropic]
  -o, --output PATH           出力ファイルパス（JSONまたはHTML）
  --format TEXT               出力形式: json, table, html [デフォルト: table]
  --html PATH                 HTMLレポートを生成
  --extended-subdomains       拡張サブドメイン列挙
  --takeover                  サブドメイン乗っ取り脆弱性をチェック
  --kev                       CISA KEVカタログをチェック [デフォルト: True]
  --wayback                   Wayback Machine URLを抽出
  --help                      ヘルプメッセージを表示

その他のコマンド:
  argus config --show         現在の設定を表示
  argus config --validate     設定を検証
  argus serve                 REST APIサーバーを起動
  argus serve --port 9000     カスタムポートで起動
```

## 設定

プロジェクトルートに`.env`ファイルを作成:

```bash
# AIプロバイダーAPIキー
ANTHROPIC_API_KEY=sk-ant-your-key-here
OPENAI_API_KEY=sk-your-key-here

# Ollama設定（ローカルLLM用）
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=llama3.2

# データベース
DATABASE_URL=sqlite+aiosqlite:///./argus.db

# APIサーバー
API_HOST=0.0.0.0
API_PORT=8000

# スキャン設定
MAX_CONCURRENT_SCANS=5          # 1-50、デフォルト: 5
DNS_TIMEOUT=10                   # 1-60秒、デフォルト: 10
PORT_SCAN_TIMEOUT=5              # 1-30秒、デフォルト: 5
HTTP_TIMEOUT=30                  # 1-120秒、デフォルト: 30

# レート制限
DNS_QUERIES_PER_SECOND=50        # 1-500、デフォルト: 50
WHOIS_QUERIES_PER_MINUTE=10      # 1-60、デフォルト: 10
PORT_SCANS_PER_SECOND=100        # 1-1000、デフォルト: 100

# ロギング
LOG_LEVEL=INFO                   # DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_FORMAT=json                  # json, text

# デフォルトAIプロバイダー
DEFAULT_AI_PROVIDER=anthropic    # anthropic, openai, ollama
```

## AIプロバイダー

### Anthropic (Claude) - 推奨

```bash
export ANTHROPIC_API_KEY=sk-ant-your-key
uv run argus scan example.com --analyze --ai-provider anthropic
```

包括的なリスク評価のために`claude-3-5-sonnet-20241022`を使用。

### OpenAI (GPT-4o)

```bash
export OPENAI_API_KEY=sk-your-key
uv run argus scan example.com --analyze --ai-provider openai
```

### Ollama（ローカルLLM）

```bash
# Ollamaサービスを起動
ollama serve

# モデルをプル
ollama pull llama3.2

# ローカルAIでスキャン実行
uv run argus scan example.com --analyze --ai-provider ollama
```

### AI分析機能

- **リスク評価**: 全体スコア（0-100）とDNS、ネットワーク、Web、インフラストラクチャのサブスコア
- **発見事項の抽出**: 自動重大度分類（Critical、High、Medium、Low）
- **推奨事項**: 優先順位付けされた実行可能なセキュリティ改善策
- **攻撃ベクター分析**: 潜在的な攻撃経路と悪用の優先順位

## REST API

### サーバー起動

```bash
uv run argus serve
uv run argus serve --host 0.0.0.0 --port 9000  # カスタムホスト/ポート
uv run argus serve --reload                      # 開発モード
```

### エンドポイント

| メソッド | エンドポイント | 説明 |
| -------- | -------------- | ---- |
| POST | `/api/v1/scans` | スキャンを作成・開始 |
| GET | `/api/v1/scans` | 全スキャンを一覧表示 |
| GET | `/api/v1/scans/{scan_id}` | スキャン状態を取得 |
| GET | `/api/v1/scans/{scan_id}/results` | スキャン結果を取得 |
| GET | `/health` | ヘルスチェック |

### APIドキュメント

- Swagger UI: <http://localhost:8000/docs>
- ReDoc: <http://localhost:8000/redoc>

### 使用例

```bash
# スキャンを作成
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target": {"domain": "example.com"}}'

# 結果を取得
curl http://localhost:8000/api/v1/scans/{scan_id}/results
```

## アーキテクチャ

```text
src/argus/
├── core/              # 設定、ロギング、インターフェース
│   ├── config.py      # 設定管理（pydantic-settings）
│   ├── logging.py     # 構造化ロギング（structlog）
│   └── exceptions.py  # カスタム例外
│
├── models/            # Pydanticデータモデル（25以上）
│   ├── scan.py        # スキャンセッションと進捗
│   ├── target.py      # ScanTargetとScanOptions
│   ├── dns.py         # DNS結果
│   ├── ports.py       # ポートスキャン結果
│   ├── ssl.py         # SSL/TLS結果
│   ├── email.py       # メールセキュリティ結果
│   └── ...            # その他の結果モデル
│
├── scanners/          # スキャナーモジュール（17以上）
│   ├── base.py        # BaseScanner抽象クラス
│   ├── registry.py    # スキャナープラグインレジストリ
│   ├── dns/           # DNS列挙
│   ├── ports/         # ポートスキャン
│   ├── ssl/           # SSL/TLS分析
│   ├── email/         # メールセキュリティ
│   ├── vuln/          # 脆弱性検出
│   └── ...            # その他のスキャナー
│
├── ai/                # AI分析
│   ├── analyzer.py    # AIAnalyzerオーケストレーター
│   ├── prompts/       # プロンプトテンプレート
│   └── providers/     # Anthropic、OpenAI、Ollama
│
├── orchestration/     # スキャン調整
│   └── coordinator.py # ScanCoordinator
│
├── cli/               # コマンドラインインターフェース
│   ├── app.py         # Typer CLIアプリケーション
│   └── formatters/    # テーブル、JSONフォーマッター
│
├── api/               # REST API
│   ├── app.py         # FastAPIアプリケーション
│   └── routers/       # APIエンドポイント
│
└── reports/           # レポート生成
    └── html.py        # HTMLレポートジェネレーター
```

## ユースケース

### クイックセキュリティ評価

```bash
uv run argus scan company.com --full --analyze
```

### メールセキュリティ監査

```bash
uv run argus scan company.com --modules email
```

### インフラストラクチャ評価

```bash
uv run argus scan company.com --modules ports,ssl,asn
```

### Webアプリケーションセキュリティ

```bash
uv run argus scan company.com --modules webtech,security,headers,js
```

### クライアント向けレポート生成

```bash
uv run argus scan company.com --full --analyze --html security_report.html
```

### 継続的モニタリング

```bash
uv run argus scan company.com --format json --output scan-$(date +%Y%m%d).json
```

## セキュリティ機能

- **プライベートIPブロック**: localhostおよびプライベート範囲のスキャンを防止
- **ターゲット検証**: 厳格なドメインおよびIP形式の検証
- **レート制限**: ターゲットへの過負荷を防ぐ設定可能な制限
- **タイムアウト設定**: ハングした接続を防止
- **エラー分離**: モジュールの障害が他のスキャンに影響しない
- **安全な設定**: APIキーにSecretStrを使用

## 開発

```bash
# 開発用依存関係を含めてインストール
uv sync --all-extras

# テスト実行
uv run pytest
uv run pytest -v --cov=src/  # カバレッジ付き

# コード品質
uv run ruff check src/        # リンティング
uv run ruff format src/       # フォーマット
uv run mypy src/              # 型チェック

# プリコミットフック
pre-commit install
pre-commit run --all-files
```

## 依存関係

### コア

- **pydantic** / **pydantic-settings**: 設定とデータ検証
- **dnspython**: DNSクエリ
- **asyncwhois**: WHOISルックアップ
- **httpx[http2]**: HTTP/2対応HTTPクライアント

### AI

- **anthropic**: Claude API
- **openai**: OpenAI API
- **ollama**: ローカルLLM

### CLI & API

- **typer**: CLIフレームワーク
- **rich**: ターミナルフォーマット
- **fastapi**: REST API
- **uvicorn**: ASGIサーバー

### インフラストラクチャ

- **structlog**: 構造化ロギング
- **aiolimiter**: 非同期レート制限
- **sqlmodel**: データベースORM

## ライセンス

MIT License - 詳細は[LICENSE](LICENSE)を参照してください。

## 免責事項

このツールは、許可されたセキュリティテストと偵察のみを目的としています。所有していないシステムをスキャンする前に、必ず適切な許可を得てください。作者はこのツールの誤用について責任を負いません。
