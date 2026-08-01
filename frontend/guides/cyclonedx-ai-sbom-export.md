---
title: Exporting an AI SBOM in CycloneDX 1.5 (for Dependency-Track & friends)
description: How to emit a CycloneDX SBOM of your AI components from CI so your existing security toolchain — Dependency-Track, GUAC, procurement portals — ingests your ML supply chain like any other.
date: 2026-07-06
---

# Exporting an AI SBOM in CycloneDX 1.5

Your security team already has SBOM plumbing: Dependency-Track watching for
new CVEs, procurement portals demanding SBOM attachments, maybe GUAC or an
internal artifact store. The fastest way to get your AI supply chain into
that machinery is to speak the format it already ingests: **CycloneDX**.

## Why CycloneDX for AI components

CycloneDX 1.5 is an OWASP flagship standard with two properties that matter
here:

- **Package URLs (PURLs)** give every component a canonical identity
  (`pkg:pypi/transformers@4.44.2`), which is what downstream tools key
  vulnerability matching on.
- The spec added **ML-aware component types** (`machine-learning-model`,
  `data`) and model-card support, so a model is not forced to masquerade as
  a library.

An AI-BOM in CycloneDX form means one pipeline, one policy engine, one
dashboard for both `openssl` and `pytorch_model.bin`.

## Generating it in CI

The AIcap CLI emits CycloneDX with a single flag. In GitHub Actions:

```yaml
jobs:
  ai-sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Generate CycloneDX AI SBOM
        run: |
          curl -sL https://github.com/aicaplabs/AIcap/releases/download/v1.7.3/aicap-linux-amd64 -o aicap
          chmod +x aicap
          ./aicap --cli . --cyclonedx > ai-sbom.cdx.json

      - name: Upload SBOM artifact
        uses: actions/upload-artifact@v4
        with:
          name: ai-sbom
          path: ai-sbom.cdx.json
```

GitLab CI and Bitbucket Pipelines templates ship in the repository
(`templates/`), pre-wired with the same artifact step.

## What lands in the document

The export covers the full AI-BOM, not just pip packages:

- **Libraries** with versions, PURLs, and licences from every supported
  manifest (Python, Node, Go, Conda, poetry/pnpm/yarn lockfiles)
- **Local model weights** discovered on disk or inside container image
  layers, with their location as evidence
- **Hosted-model dependencies** detected from SDK usage and hardcoded
  model IDs
- **Licence metadata** where detectable — including model licences whose
  restrictions your policy engine may care about more than MIT-vs-Apache

## Feeding Dependency-Track

Dependency-Track ingests the file as-is:

```bash
curl -X POST "https://dtrack.example.com/api/v1/bom" \
  -H "X-Api-Key: $DTRACK_API_KEY" \
  -F "project=$PROJECT_UUID" \
  -F "bom=@ai-sbom.cdx.json"
```

From there your existing alerting applies: a new GHSA against
`transformers` pages the same on-call as one against `log4j`. That single
sentence is the entire business case — AI components stop being a separate,
unmonitored universe.

## The advisories travel with the SBOM

The export carries a CycloneDX 1.5 `vulnerabilities` array populated from
the live OSV.dev lookup AIcap performs during the scan. Each entry links to
the component it affects by `bom-ref`, quotes the severity exactly as the
advisory database published it (with the CVSS vector, never a score AIcap
computed itself), and names an upgrade target:

```json
{
  "id": "GHSA-37mw-44qp-f5jm",
  "source": { "name": "OSV", "url": "https://osv.dev/vulnerability/GHSA-37mw-44qp-f5jm" },
  "ratings": [{ "severity": "moderate", "method": "CVSSv31", "vector": "CVSS:3.1/AV:N/..." }],
  "recommendation": "Upgrade to 4.52.1 or later.",
  "affects": [{ "ref": "pkg:pypi/transformers@4.30.0" }]
}
```

So a consumer ingesting the file does not have to rediscover what the scan
already found. Note what is *not* in that array: curated OWASP ML / MITRE
ATLAS mappings stay in the risk register. Those are risk-management
entries, not CVEs, and emitting them here would make your scanner report
vulnerabilities that do not exist.

## Where the standard still falls short

Honesty section. CycloneDX's ML support is young:

- Vulnerability databases key on package PURLs; **weight files don't have
  CVE identifiers**, so a poisoned checkpoint won't page anyone. Treat the
  SBOM entry as inventory and provenance, not as vulnerability coverage.
- Hosted models (a `gpt-4o` API dependency) have no registry to resolve
  against — they appear as components with evidence, and policy on them is
  yours to write.
- Model cards in the wild are sparse; the spec supports more metadata than
  most sources provide. AIcap deliberately does not emit a `modelCard`
  block for detected models: we know the identifier, the licence, and
  where it was referenced, and inventing the fields we do not know
  (training data, evaluation, intended use) would put fabricated
  metadata into an audit artefact.

These gaps are why the AI-BOM itself (with its OWASP ML / MITRE ATLAS risk
register) remains the richer artefact — the CycloneDX export is the
interoperability layer, not the whole story.

## Compliance double-duty

The same export answers the EU AI Act. Annex IV Section 2 requires a
description of system components including pre-trained models; attaching a
standards-formatted, per-commit SBOM is a stronger answer than prose. Run
both outputs from one scan: the JSON AI-BOM + Annex IV draft for the
compliance file, the `--cyclonedx` document for the security toolchain.
