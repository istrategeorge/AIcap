# 🛡️ AIcap: Continuous AI-BOM & Compliance Automator

[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-AIcap-indigo.svg)](https://github.com/marketplace/actions/continuous-ai-bom-scanner)
[!License: MIT](https://opensource.org/licenses/MIT)

**AIcap** is a developer-first compliance and FinOps scanner designed to secure your AI supply chain. 

Running natively within your CI/CD pipeline, AIcap automatically detects AI models, validates dependencies, highlights expensive GPU misconfigurations, and dynamically generates the technical documentation required by the **EU AI Act (Annex IV)**.

## ✨ Key Features

- 📦 **AI-BOM Generation:** Automatically discovers foundation models, ML libraries (PyTorch, TensorFlow, Hugging Face), and API SDKs (OpenAI, Anthropic) in your codebase.
- ⚖️ **EU AI Act Compliance:** Enforces continuous risk management (Article 9) and shifts legal compliance to the left by tracking AI inventory.
- 💸 **AI FinOps Warnings:** Scans Kubernetes manifests (`.yaml`) to detect unoptimized, highly expensive GPU resource requests (e.g., missing MIG or time-slicing configurations).
- 🔒 **Immutable Audit Ledger:** Syncs your pipeline scans to the AIcap Cloud Dashboard, providing cryptographically hashed "Proof Drills" for enterprise auditors.

## 🚀 Usage

Add the AIcap action to your existing GitHub Actions workflow. We recommend running this during the `pull_request` or `push` phase to catch compliance violations before they hit production.

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
          # (Optional) Pro Tier API Key to sync historical Proof Drills to the cloud dashboard
          api-key: ${{ secrets.AICAP_API_KEY }}
          
          # (Optional) Specify a sub-directory to scan. Defaults to the repository root.
          scan-directory: '.'
```

## 📥 Inputs

| Input | Description | Required | Default |
| --- | --- | --- | --- |
| `api-key` | Your AIcap Pro API Key. Used to securely transmit the AI-BOM to your cloud dashboard to maintain an immutable audit ledger. | No | `""` |
| `scan-directory` | The target directory to scan for dependencies, models, and manifests. | No | `.` |

## ☁️ AIcap Pro Cloud Dashboard

While the CLI scanner runs completely free in your pipeline, managing compliance for enterprise teams requires a historical record of what controls were active during a specific deployment.

By providing an `api-key`, AIcap securely hashes your commit data and AI-BOM, pushing it to an immutable ledger. 

1. Sign up at AIcap Dashboard *(Replace with your live URL)*
2. Generate a Secret API Key.
3. Add it to your repository's **Settings > Secrets and variables > Actions**.
4. Auditors can now log in to instantly retrieve timestamped Markdown reports for any historical release!

## 🛠️ How it Works

AIcap utilizes multi-layered Abstract Syntax Tree (AST) and manifest parsing written in highly optimized Go. It scans:
- `package.json`, `requirements.txt`, and `go.mod` for AI-specific libraries.
- `.py` and `.go` source files for hardcoded external API models (e.g., `gpt-4`).
- `.pt`, `.safetensors`, and `.onnx` files to identify local weights.
- `.yaml` and `.yml` files for FinOps and GPU infrastructure evaluation.

---

*Built with ❤️ for DevOps and Security Engineers.*