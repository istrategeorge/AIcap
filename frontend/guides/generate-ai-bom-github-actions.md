---
title: How to generate an AI-BOM in GitHub Actions (5-minute tutorial)
description: Add continuous AI Bill-of-Materials generation to your CI pipeline — dependency detection, model weights, CycloneDX SBOM output, and EU AI Act posture in one job.
date: 2026-07-06
---

# How to generate an AI-BOM in GitHub Actions

An **AI-BOM** (AI Bill of Materials) is the inventory of AI components in
your system: ML frameworks, model APIs, local model weights, GPU
infrastructure. It is the raw material for EU AI Act Annex IV Section 2, for
supply-chain security reviews, and for the "what AI do we even run?"
question every CTO gets asked eventually.

The wrong way to build one is a spreadsheet. Inventories rot; pipelines
don't. Here is the CI-native way, in five minutes.

## Step 1 — add the workflow

Create `.github/workflows/ai-compliance.yml`:

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
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Run AIcap compliance scan
        uses: aicaplabs/AIcap@v1.7.2
        with:
          scan-directory: '.'
```

That is a complete, working setup. No API key needed — the scanner runs
entirely inside your runner and your source code never leaves it.

## Step 2 — read the output

On every push you get a JSON AI-BOM in the job log. What the scanner
detects:

| Surface | What it finds |
|---|---|
| `requirements.txt`, `pyproject.toml`, `poetry.lock`, `Pipfile.lock`, Conda `environment.yml` | Python ML/AI libraries with versions and licences |
| `package.json`, `pnpm-lock.yaml`, `yarn.lock` | Node AI SDKs (OpenAI, Anthropic, LangChain.js, …) |
| `go.mod` + Go AST | Go AI dependencies and hardcoded model IDs |
| Source imports | Model IDs, bias-monitoring and guardrail tooling |
| `Dockerfile` | AI base images, weight `COPY` instructions |
| `.safetensors`, `.onnx`, `.pt`, `.gguf`, `.h5`, … | Local model weight files |
| Kubernetes / Terraform / Helm | GPU requests with cost estimates |
| `.env` and source | 13+ AI-platform API key patterns (leak detection) |

Each dependency is cross-referenced against a curated risk catalog (OWASP ML
Top 10, MITRE ATLAS, EU AI Act articles) and live CVE/GHSA data from OSV.dev.

## Step 3 — SBOM output for your security team

Need a standards-compliant SBOM for enterprise toolchains (Dependency-Track,
GUAC)? Run the CLI directly with the CycloneDX flag:

```yaml
      - name: Generate CycloneDX SBOM
        run: |
          curl -sL https://github.com/aicaplabs/AIcap/releases/download/v1.7.2/aicap-linux-amd64 -o aicap
          chmod +x aicap
          ./aicap --cli . --cyclonedx > ai-sbom.cdx.json

      - name: Upload SBOM artifact
        uses: actions/upload-artifact@v4
        with:
          name: ai-sbom
          path: ai-sbom.cdx.json
```

## Step 4 — scan container images too

Model weights have a habit of hiding in image layers rather than the repo.
The CLI walks OCI layers without a Docker daemon:

```yaml
          ./aicap --cli . --image ghcr.io/your-org/inference:latest
```

Findings are attributed back to the exact layer and path
(`image#layer3:/models/pytorch_model.bin`), so you know *where* the weight
came from.

## Step 5 — enforce policy, not just visibility

Add an `.aicap.yml` to the repo root to turn the scan into a gate:

```yaml
blocked_models:
  - gpt-3.5-turbo        # deprecated internally
block_on_high_risk: true
license_allowlist:
  - Apache-2.0
  - MIT
  - BSD-3-Clause
```

The CLI exits **2** on a blocker-severity policy breach and **1** on
unmitigated high-risk findings, so your branch protection does the
enforcing. Exit 0 prints a compliance badge snippet for your README.

## Where this connects to the EU AI Act

Annex IV Section 2(a) requires documenting "pre-trained systems and
components used". A hand-written list satisfies an auditor on the day it is
written; a CI-generated one satisfies them on every commit — and Article 9
explicitly requires risk management to be **continuous and iterative**.
With an API key (Pro tier), each scan is also anchored to a hash-chained,
tamper-evident audit ledger with the full Annex IV draft attached — the
artefact you hand the auditor.
