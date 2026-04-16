# 🛡️ AIcap: Continuous AI-BOM & Compliance Automator

[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-AIcap-indigo.svg)](https://github.com/marketplace/actions/continuous-ai-bom-scanner)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Go Tests](https://img.shields.io/badge/tests-47%20passing-brightgreen.svg)]()
[![CycloneDX](https://img.shields.io/badge/SBOM-CycloneDX%201.5-orange.svg)]()
[![OWASP ML](https://img.shields.io/badge/OWASP-ML%20Top%2010-red.svg)]()

**AIcap** is the developer-first compliance and FinOps scanner for the AI supply chain. It shifts EU AI Act compliance left into CI/CD, detects expensive GPU misconfigurations, and generates audit-ready documentation — all in a single binary.

> **Why AIcap?** Every AI system shipped to the EU market must comply with the AI Act by August 2026. AIcap automates the hardest parts: dependency tracking, model governance, license auditing, and Annex IV documentation — so your team ships faster, not slower.

---

## ✨ Features

### 🔍 AI Supply Chain Scanner
| What it scans | How |
|---|---|
| **Python** (`requirements.txt`, `pyproject.toml`, source imports) | Detects AI libraries + hardcoded model IDs |
| **Node.js** (`package.json`) | Matches against 70+ known AI/ML packages |
| **Go** (`go.mod`, AST analysis) | Parses module dependencies + string literals |
| **Docker** (`Dockerfile`, `Dockerfile.*`) | Detects AI base images, model weight COPY, pip installs |
| **Model weights** (`.safetensors`, `.onnx`, `.pt`, `.h5`, `.gguf`, etc.) | Flags local model files with license enrichment |
| **Secrets** (`.env`, source code) | Detects 13+ AI platform API key patterns (OpenAI, Anthropic, HF, etc.) |

### ⚖️ Compliance Automation
- **EU AI Act Annex IV** — Auto-generates technical documentation with risk register, licensing summary, and policy compliance
- **OWASP ML Top 10** — Cross-references dependencies with known ML attack vectors (supply chain, prompt injection, model theft, data poisoning)
- **Policy-as-Code** — `.aicap.yml` configuration for model governance (blocked/allowed models, risk thresholds, license restrictions)
- **CycloneDX 1.5** — Industry-standard SBOM output with Package URLs (PURLs) for enterprise toolchain integration

### 💸 AI FinOps
- **Kubernetes** — Detects unoptimized GPU requests (missing MIG/time-slicing)
- **Terraform** — Identifies GPU instances across AWS/Azure/GCP with hourly cost data and spot pricing analysis
- **Helm** — Analyzes `values.yaml` for GPU allocation without autoscaling, detects model serving frameworks

### 🔒 Immutable Audit Ledger
- SHA-256 cryptographic hashing of every scan (commit + BOM + documentation)
- Cloud dashboard for historical Proof Drills with timestamp verification
- Enterprise-grade API key management with Stripe subscription lifecycle

---

## 🚀 Quick Start

### GitHub Actions (Recommended)

```yaml
name: AI Compliance Scan

on:
  push:
    branches: [ "main" ]
  pull_request:
    branches: [ "main" ]

jobs:
  aicap-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4

      - name: Run AIcap Compliance Scan
        uses: istrategeorge/AIcap@v1.0.0-alpha
        with:
          api-key: ${{ secrets.AICAP_API_KEY }}
          scan-directory: '.'
```

### CLI Mode

```bash
# Standard AI-BOM output (JSON)
aicap --cli ./my-project

# CycloneDX SBOM format (for enterprise toolchains)
aicap --cli ./my-project --cyclonedx

# Auto-sync to AIcap Cloud
AICAP_API_KEY=aicap_pro_sk_xxx aicap --cli ./my-project
```

### Local Development

```bash
# Clone & run backend
git clone https://github.com/istrategeorge/AIcap.git
cd AIcap
go run .

# Run frontend (separate terminal)
cd frontend && npm install && npm run dev
```

---

## 📋 Policy-as-Code (`.aicap.yml`)

Create a `.aicap.yml` in your project root to enforce model governance policies:

```yaml
# Block specific models
blocked_models:
  - gpt-3.5-turbo
  - claude-2

# Or use an allowlist (anything not listed is blocked)
allowed_models:
  - gpt-4-turbo
  - claude-3-opus

# Block pipeline on any high-risk dependency
block_on_high_risk: true

# Require license information for all high-risk components
require_licenses: true

# Only permit specific license types
allowed_licenses:
  - MIT
  - Apache-2.0
  - llama3.1
```

---

## 📥 Inputs

| Input | Description | Required | Default |
|---|---|---|---|
| `api-key` | AIcap Pro API key for cloud sync | No | `""` |
| `scan-directory` | Target directory to scan | No | `.` |

## 📤 CLI Flags

| Flag | Description |
|---|---|
| `--cli` | Run in headless CI/CD mode |
| `--cyclonedx` | Output CycloneDX 1.5 JSON instead of AIcap format |

## 🌍 Environment Variables

| Variable | Description |
|---|---|
| `AICAP_API_KEY` | Pro API key for cloud sync |
| `GITHUB_REPOSITORY` | Auto-detected in GitHub Actions |
| `GITHUB_SHA` | Auto-detected commit SHA |
| `SUPABASE_DB_URL` | PostgreSQL connection for SaaS mode |
| `STRIPE_SECRET_KEY` | Stripe integration for Pro subscriptions |
| `STRIPE_WEBHOOK_SECRET` | Stripe webhook signature verification |

---

## 🛠️ Architecture

AIcap uses multi-layered parsing written in optimized Go:

```
┌─────────────────────────────────────────────────────┐
│                    AIcap Scanner                     │
├──────────────┬──────────────┬───────────────────────┤
│  Manifests   │  Source Code │  Infrastructure       │
│              │              │                       │
│ requirements │  Go AST      │  Kubernetes YAML      │
│ package.json │  Python      │  Terraform .tf        │
│ go.mod       │  imports     │  Helm values.yaml     │
│ pyproject    │  .env files  │  Dockerfile           │
│ Dockerfile   │  secrets     │  Model weight files   │
├──────────────┴──────────────┴───────────────────────┤
│              AI-BOM + FinOps Findings                │
├─────────────────────────────────────────────────────┤
│  OWASP ML Top 10 Enrichment                         │
├─────────────────────────────────────────────────────┤
│  Policy-as-Code Evaluation (.aicap.yml)             │
├─────────────────────────────────────────────────────┤
│  Output: JSON │ CycloneDX 1.5 │ Annex IV Markdown   │
└─────────────────────────────────────────────────────┘
```

### Scanned File Types

| File | Parser | Detection |
|---|---|---|
| `requirements.txt` | Regex | AI libraries by name |
| `package.json` | JSON | Dependencies + devDependencies |
| `go.mod` | Line parser | AI Go modules in require blocks |
| `pyproject.toml` | Section parser | Poetry/PEP dependencies |
| `Dockerfile` | Line parser | Base images, COPY weights, pip install |
| `*.py` | Regex + import | `import torch`, hardcoded model strings, secrets |
| `*.go` | Go AST | String literal analysis for models & secrets |
| `.env` | Key-value parser | 13+ AI platform API key patterns |
| `*.yaml` / `*.yml` | Line parser | Kubernetes GPU requests, MIG detection |
| `values.yaml` | Helm parser | GPU resources, autoscaling, model serving |
| `*.tf` | Terraform parser | AWS/Azure/GCP GPU instances, spot pricing |
| `*.safetensors`, `.onnx`, `.pt`, etc. | File detection | Local model weight flagging |

---

## ☁️ AIcap Pro (Cloud Dashboard)

The CLI scanner is **free forever**. AIcap Pro adds:

- 📊 **Historical Proof Drills** — Timestamped, cryptographically hashed compliance records
- 🔑 **Secure API Keys** — Server-side generated with `crypto/rand`
- 📜 **Annex IV Reports** — Auto-generated EU AI Act documentation with audit trail
- 💳 **Stripe Integration** — Full subscription lifecycle (auto-provisioning, cancellation, payment failure handling)

### Setup
1. Sign up at the AIcap Dashboard
2. Generate your API key (Settings → API Keys)
3. Add `AICAP_API_KEY` to your repo's GitHub Secrets
4. Auditors can retrieve timestamped Markdown reports for any historical release

---

## 🧪 Testing

```bash
# Run all 47 tests
go test -v ./...

# Run specific test category
go test -v -run "TestParseTerraform" ./...
go test -v -run "TestEnrichWithOWASP" ./...
go test -v -run "TestParseEnvFile" ./...
```

**Test Coverage:**
| Category | Tests |
|---|---|
| Python parsers (requirements, imports, source) | 6 |
| Package.json parser | 2 |
| Go AST parser | 3 |
| Go module parser | 3 |
| PyProject.toml parser | 3 |
| Dockerfile parser | 4 |
| Terraform FinOps parser | 4 |
| Helm values parser | 3 |
| .env secret scanner | 4 |
| Policy engine | 5 |
| CycloneDX SBOM | 3 |
| OWASP ML enrichment | 2 |
| Annex IV generation | 1 |
| Integration tests | 2 |
| Serialization | 1 |
| **Total** | **47** |

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

*Built with ❤️ for DevOps and Security Engineers who ship AI responsibly.*