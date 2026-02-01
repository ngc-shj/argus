# Argus

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

> *The all-seeing eye for your security*

[日本語版 README](README.ja.md)

**Argus** is an AI-powered attack surface reconnaissance tool. Named after Argus Panoptes, the hundred-eyed giant of Greek mythology who sees all, this tool provides comprehensive security scanning with intelligent risk assessment.

## Features

- **17+ Scanner Modules**: DNS, WHOIS, Ports, SSL/TLS, Email Security, Vulnerabilities, and more
- **AI-Powered Analysis**: Risk assessment using Claude, GPT-4o, or local Ollama models
- **Multiple Output Formats**: Rich terminal tables, JSON, and professional HTML reports
- **Async Architecture**: Fast concurrent scanning with configurable rate limiting
- **REST API**: FastAPI-based API with Swagger/ReDoc documentation
- **Extensible**: Plugin-based scanner architecture for easy customization

## Scanner Modules

| Module | Description | Key Features |
| ------ | ----------- | ------------ |
| **dns** | DNS enumeration | A/AAAA/MX/NS/TXT/CNAME/SOA, subdomain discovery, DNSSEC, zone transfer detection |
| **whois** | WHOIS lookup | Registration data, registrar info, expiration dates |
| **rdap** | RDAP protocol | Modern WHOIS alternative, ASN data |
| **ports** | Port scanning | Async TCP scan, service detection, configurable profiles (top 20/100/1000) |
| **webtech** | Web technologies | Frameworks, CMS, server info, security headers |
| **crtsh** | Certificate Transparency | Subdomain discovery via CT logs |
| **ssl** | SSL/TLS analysis | Certificate info, cipher suites, protocol versions, SSL Labs grade |
| **email** | Email security | SPF/DKIM/DMARC validation, MTA-STS, TLS-RPT, security scoring |
| **security** | Security scan | Exposed files, CORS, WAF detection, cloud storage, actuator endpoints |
| **vuln** | Vulnerabilities | CVE detection, CVSS scoring, severity classification |
| **js** | JavaScript analysis | Secret extraction, API endpoint discovery |
| **subdomain** | Extended enumeration | 20+ sources for comprehensive subdomain discovery |
| **takeover** | Takeover detection | Subdomain takeover vulnerability checks |
| **kev** | CISA KEV | Known Exploited Vulnerabilities catalog matching |
| **headers** | HTTP headers | Security header analysis and scoring |
| **discovery** | Discovery files | robots.txt, sitemap.xml, security.txt |
| **favicon** | Favicon fingerprint | MMH3 hash, Shodan integration |
| **asn** | ASN lookup | IP to ASN, organization info, geolocation |
| **wayback** | Wayback Machine | Historical URL extraction |
| **graphql** | GraphQL detection | Introspection, sensitive fields, dangerous mutations |

## Installation

### Prerequisites

- Python 3.11+
- [uv](https://github.com/astral-sh/uv) (recommended) or pip

### Install

```bash
# Clone the repository
git clone https://github.com/ngc-shj/argus.git
cd argus

# Install with uv (recommended)
uv sync

# Or install with dev dependencies
uv sync --all-extras
```

## Quick Start

### Basic Scan

```bash
# Default scan (dns, whois, ports, crtsh)
uv run argus scan example.com

# Full scan with all modules
uv run argus scan example.com --full

# Specific modules
uv run argus scan example.com --modules dns,ports,ssl,email
```

### AI Analysis

```bash
# With AI-powered risk assessment (requires API key)
uv run argus scan example.com --analyze

# Using different AI providers
uv run argus scan example.com --analyze --ai-provider anthropic  # Claude (default)
uv run argus scan example.com --analyze --ai-provider openai     # GPT-4o
uv run argus scan example.com --analyze --ai-provider ollama     # Local LLM
```

### Output Formats

```bash
# Rich terminal table (default)
uv run argus scan example.com

# JSON output
uv run argus scan example.com --format json --output report.json

# HTML report
uv run argus scan example.com --html report.html
```

### Advanced Options

```bash
# Extended subdomain enumeration (20+ sources)
uv run argus scan example.com --extended-subdomains

# Check for subdomain takeover vulnerabilities
uv run argus scan example.com --takeover

# Include Wayback Machine URL extraction (slower)
uv run argus scan example.com --wayback

# CISA KEV catalog check (enabled by default)
uv run argus scan example.com --kev
```

## CLI Reference

```text
Usage: argus scan [OPTIONS] TARGET

Arguments:
  TARGET    Target domain or IP address [required]

Options:
  -m, --modules TEXT          Modules to run (comma-separated)
  -f, --full                  Run all modules
  -a, --analyze               Enable AI analysis
  -p, --ai-provider TEXT      AI provider: anthropic, openai, ollama [default: anthropic]
  -o, --output PATH           Output file path (JSON or HTML)
  --format TEXT               Output format: json, table, html [default: table]
  --html PATH                 Generate HTML report
  --extended-subdomains       Extended subdomain enumeration
  --takeover                  Check subdomain takeover vulnerabilities
  --kev                       Check CISA KEV catalog [default: True]
  --wayback                   Extract Wayback Machine URLs
  --help                      Show help message

Other Commands:
  argus config --show         Show current configuration
  argus config --validate     Validate configuration
  argus serve                 Start REST API server
  argus serve --port 9000     Start on custom port
```

## Configuration

Create a `.env` file in the project root:

```bash
# AI Provider API Keys
ANTHROPIC_API_KEY=sk-ant-your-key-here
OPENAI_API_KEY=sk-your-key-here

# Ollama Configuration (for local LLM)
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=gpt-oss:20b

# Database
DATABASE_URL=sqlite+aiosqlite:///./argus.db

# API Server
API_HOST=0.0.0.0
API_PORT=8000

# Scan Configuration
MAX_CONCURRENT_SCANS=5          # 1-50, default: 5
DNS_TIMEOUT=10                   # 1-60 seconds, default: 10
PORT_SCAN_TIMEOUT=5              # 1-30 seconds, default: 5
HTTP_TIMEOUT=30                  # 1-120 seconds, default: 30

# Rate Limiting
DNS_QUERIES_PER_SECOND=50        # 1-500, default: 50
WHOIS_QUERIES_PER_MINUTE=10      # 1-60, default: 10
PORT_SCANS_PER_SECOND=100        # 1-1000, default: 100

# Logging
LOG_LEVEL=INFO                   # DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_FORMAT=json                  # json, text

# Default AI Provider
DEFAULT_AI_PROVIDER=anthropic    # anthropic, openai, ollama
```

## AI Providers

### Anthropic (Claude) - Recommended

```bash
export ANTHROPIC_API_KEY=sk-ant-your-key
uv run argus scan example.com --analyze --ai-provider anthropic
```

Uses `claude-sonnet-4-20250514` for comprehensive risk assessment.

### OpenAI (GPT-4o)

```bash
export OPENAI_API_KEY=sk-your-key
uv run argus scan example.com --analyze --ai-provider openai
```

### Ollama (Local LLM)

```bash
# Start Ollama service
ollama serve

# Pull a model
ollama pull gpt-oss:20b

# Run scan with local AI
uv run argus scan example.com --analyze --ai-provider ollama
```

### AI Analysis Features

- **Risk Assessment**: Overall score (0-100) with DNS, Network, Web, and Infrastructure sub-scores
- **Finding Extraction**: Automatic severity classification (Critical, High, Medium, Low)
- **Recommendations**: Prioritized, actionable security improvements
- **Attack Vector Analysis**: Potential attack paths and exploitation priorities

## REST API

### Start Server

```bash
uv run argus serve
uv run argus serve --host 0.0.0.0 --port 9000  # Custom host/port
uv run argus serve --reload                      # Development mode
```

### Endpoints

| Method | Endpoint | Description |
| ------ | -------- | ----------- |
| POST | `/api/v1/scans` | Create and start a scan |
| GET | `/api/v1/scans` | List all scans |
| GET | `/api/v1/scans/{scan_id}` | Get scan status |
| GET | `/api/v1/scans/{scan_id}/results` | Get scan results |
| GET | `/health` | Health check |

### API Documentation

- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

### Example

```bash
# Create a scan
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target": {"domain": "example.com"}}'

# Get results
curl http://localhost:8000/api/v1/scans/{scan_id}/results
```

## Architecture

```
src/argus/
├── core/              # Configuration, logging, interfaces
│   ├── config.py      # Settings management (pydantic-settings)
│   ├── logging.py     # Structured logging (structlog)
│   └── exceptions.py  # Custom exceptions
│
├── models/            # Pydantic data models (25+ models)
│   ├── scan.py        # Scan session and progress
│   ├── target.py      # ScanTarget and ScanOptions
│   ├── dns.py         # DNS results
│   ├── ports.py       # Port scan results
│   ├── ssl.py         # SSL/TLS results
│   ├── email.py       # Email security results
│   └── ...            # Other result models
│
├── scanners/          # Scanner modules (17+)
│   ├── base.py        # BaseScanner abstract class
│   ├── registry.py    # Scanner plugin registry
│   ├── dns/           # DNS enumeration
│   ├── ports/         # Port scanning
│   ├── ssl/           # SSL/TLS analysis
│   ├── email/         # Email security
│   ├── vuln/          # Vulnerability detection
│   └── ...            # Other scanners
│
├── ai/                # AI analysis
│   ├── analyzer.py    # AIAnalyzer orchestrator
│   ├── prompts/       # Prompt templates
│   └── providers/     # Anthropic, OpenAI, Ollama
│
├── orchestration/     # Scan coordination
│   └── coordinator.py # ScanCoordinator
│
├── cli/               # Command-line interface
│   ├── app.py         # Typer CLI application
│   └── formatters/    # Table, JSON formatters
│
├── api/               # REST API
│   ├── app.py         # FastAPI application
│   └── routers/       # API endpoints
│
└── reports/           # Report generation
    └── html.py        # HTML report generator
```

## Use Cases

### Quick Security Assessment

```bash
uv run argus scan company.com --full --analyze
```

### Email Security Audit

```bash
uv run argus scan company.com --modules email
```

### Infrastructure Assessment

```bash
uv run argus scan company.com --modules ports,ssl,asn
```

### Web Application Security

```bash
uv run argus scan company.com --modules webtech,security,headers,js
```

### Generate Report for Client

```bash
uv run argus scan company.com --full --analyze --html security_report.html
```

### Continuous Monitoring

```bash
uv run argus scan company.com --format json --output scan-$(date +%Y%m%d).json
```

## Security Features

- **Private IP Blocking**: Prevents scanning of localhost and private ranges
- **Target Validation**: Strict domain and IP format validation
- **Rate Limiting**: Configurable limits to prevent overwhelming targets
- **Timeout Configuration**: Prevents hanging connections
- **Error Isolation**: Module failures don't affect other scans
- **Secure Configuration**: SecretStr for API keys

## Development

```bash
# Install with dev dependencies
uv sync --all-extras

# Run tests
uv run pytest
uv run pytest -v --cov=src/  # With coverage

# Code quality
uv run ruff check src/        # Linting
uv run ruff format src/       # Formatting
uv run mypy src/              # Type checking

# Pre-commit hooks
pre-commit install
pre-commit run --all-files
```

## Dependencies

### Core

- **pydantic** / **pydantic-settings**: Configuration and data validation
- **dnspython**: DNS queries
- **asyncwhois**: WHOIS lookups
- **httpx[http2]**: HTTP client with HTTP/2 support

### AI

- **anthropic**: Claude API
- **openai**: OpenAI API
- **ollama**: Local LLM

### CLI & API

- **typer**: CLI framework
- **rich**: Terminal formatting
- **fastapi**: REST API
- **uvicorn**: ASGI server

### Infrastructure

- **structlog**: Structured logging
- **aiolimiter**: Async rate limiting
- **sqlmodel**: Database ORM

## License

MIT License - see [LICENSE](LICENSE) for details.

## Disclaimer

This tool is intended for authorized security testing and reconnaissance only. Always obtain proper authorization before scanning any systems you do not own. The authors are not responsible for any misuse of this tool.
