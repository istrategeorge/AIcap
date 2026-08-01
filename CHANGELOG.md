# Changelog

All notable changes to AIcap are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Trial of new features lands on `development` first. Once a stable
batch is ready, it is merged to `main` and tagged.

## [1.7.2] — 2026-07-24 — Deterministic scans, grouped findings, honest policy status

Found by reading a complete generated report end to end. The third such
read, and the one that surfaced a defect with consequences beyond the
document.

### Fixed

- **Scans were not deterministic.** Three loops iterated Go maps while
  emitting findings, and Go randomises map iteration: the Dockerfile
  pip-install match, the Dockerfile base-image match, and the GPU cost
  lookup. The visible symptom was a report that reshuffled itself — an
  image matching two catalog keys was labelled "NVIDIA Container
  Registry Image" on one run and "PyTorch Container Image" on the next,
  and a Terraform file naming two GPU families reported whichever the
  runtime reached first, with its cost figures.

  The real problem is that the AI-BOM is what `/api/save-proof` hashes
  into the audit chain. Two scans of an unchanged tree therefore
  produced two different `crypto_hash` values, so the chain could not
  distinguish "the code changed" from "a map iterated differently" —
  undercutting the guarantee the hosted ledger exists to provide. All
  three loops now iterate in sorted order, and the GPU lookup takes the
  longest matching prefix so overlapping catalog keys (`p4d`/`p4de`,
  `g5`/`g5g`) resolve to the more specific entry.

  Existing ledger entries remain valid and verify normally. A rescan of
  an unchanged repository after this release will produce a different
  hash than it did before, because the previous value depended on
  iteration order.

- **§ 2(a) printed one line per detection and omitted the location.** A
  model identifier used in eight files produced eight identical
  sentences, indistinguishable from one another because the field that
  separated them — where each was found — was the one the section never
  rendered. Now one entry per distinct component with an occurrence
  count and the detection sites, capped at five with "and N more".

- **§ 3(b) reported "no policy file" as a passed policy check.** The
  line read "No policy violations detected (or no `.aicap.yml`
  configured)" beside a ticked box, so a project with no governance
  policy at all appeared to have satisfied one — in the section an
  auditor reads to judge exactly that. The two cases are now distinct
  and the absent-policy case is explicitly not a pass.

- The dashboard's client-side renderer received the § 2(a) grouping and
  the version-prefix fix. It is a hand-maintained mirror of the Go
  template and had silently diverged for a third time; it now carries
  parity tests.

## [1.7.1] — 2026-07-24 — Report defects found by reading a generated PDF

Four defects in the produced document, none of which the test suite
caught because every one of them was about how the report *reads*
rather than what it computes.

### Fixed

- **Blockquotes were not rendered.** The markdown-to-HTML converter had
  no branch for them, so quoted lines were escaped to `&gt;` and joined
  into a run-on paragraph. Every legally protective statement in the
  product is a blockquote — the Article 5 "this is not a finding that
  you are committing a prohibited practice" disclaimer, the Article 50
  framing that these are disclosure duties rather than prohibitions,
  and the § 5 warning that a locally generated document is unattested
  and cannot be independently verified. All three reached the reader as
  garbled prose. Now rendered as a styled callout in the PDF export,
  the shared report page, and the published guides.
- **The risk register listed the same component twice.** A finding was
  emitted per detection site, so a package found in both a manifest and
  a lockfile appeared twice. Because OSV enrichment attached advisories
  by component name, only one of the two rows received them — a reader
  saw the same component and version listed twice, once with ten CVEs
  and once with none. Findings are now unique per (component, version),
  and enrichment is keyed the same way so advisories land on the
  version they were actually reported against. Distinct versions of one
  package remain distinct rows.
- **Import-only rows sat beside versioned ones.** A detection with no
  resolvable version cannot be checked against OSV, so it rendered an
  empty advisory column next to a row listing real CVEs for the same
  library. Dropped when a concrete version of that component is known;
  kept when it is the only evidence available.
- **The `v` prefix was applied to values that are not versions.** The
  version field also carries model identifiers, manifest constraints,
  and scanner placeholders, producing `vgpt-5`,
  `vmodels/llama-3-8b.gguf`, `v>=2.0` and `vdocker-install` in an
  auditor-facing document.

## [1.7.0] — 2026-07-24 — SPDX output, and cost figures out of the compliance document

A short release with one addition and one subtraction. The subtraction
is the more consequential of the two.

### Added

- **SPDX 2.3 SBOM export** (`--spdx`). CycloneDX and SPDX are the two
  halves of the SBOM world and neither subsumes the other — a
  procurement questionnaire asking for "an SPDX SBOM" is not satisfied
  by a CycloneDX file however complete it is. Targets 2.3 rather than
  3.0 deliberately: 3.0's AI profile models this product's output
  better on paper, but it is a JSON-LD element graph that little
  tooling ingests today, and the point of emitting SPDX at all is to be
  consumed. The AI-specific data 3.0 would carry natively travels in
  annotations and external references.

  Three correctness problems the AI-BOM's data makes acute are handled:
  identifiers are sanitised to the `SPDXRef-[a-zA-Z0-9.-]+` grammar
  **with collision disambiguation**, since two `Hardcoded Model`
  findings sharing an SPDXID would silently merge two components in the
  consumer's view; vendor licence strings such as `Proprietary (OpenAI)`
  become `LicenseRef` entries with the original text preserved, rather
  than being passed off as valid SPDX expressions; and
  `licenseConcluded` stays `NOASSERTION` throughout, because "concluded"
  asserts a legal determination and AIcap reads what registries report.

### Changed

- **Cost estimates are no longer in the Annex IV document by default.**
  Annex IV Section 2 requires a description of the computational
  resources a system uses. It does not require what those resources
  cost. The two shared a heading, which put a list-price, on-demand,
  USD, 730-hours-a-month estimate directly beside the Article 9 risk
  register and the ledger provenance.

  That placement carried a cost the estimate itself does not. Any
  platform engineer reads "$23,922/month for a p4d" and knows within
  seconds that it ignores committed-use discounts, savings plans,
  reserved instances, and regional variance — and having found one
  easily challenged number, has every reason to ask what else in the
  document is a guess. The risk register and the provenance claims are
  the parts that have to be believed.

  So § 2(c) becomes "Compute & Hardware Resources" and always describes
  the hardware, including the detected instance family. Cost figures,
  spot projections, and rightsizing recommendations move behind
  `--finops`, off by default. The JSON output and the dashboard keep the
  cost data unconditionally — their audience is engineers, who can weigh
  a list-price estimate for what it is.

- **Positioning.** The README no longer describes AIcap as a
  "compliance and FinOps scanner". That was two products in one
  sentence, sold to two different buyers with two different budgets.
  Compute telemetry is a capability underneath a compliance product,
  not a co-headline.

## [1.6.0] — 2026-07-24 — Regulatory breadth: Article 5, Article 50, CycloneDX advisories

v1.5.0 closed the gaps in what the scanner could *see*. This release
widens what it can say about it: two chapters of the AI Act that the
product previously ignored, and the advisories it already held reaching
the SBOM that downstream tooling actually consumes.

### Added

- **EU AI Act Article 5 — prohibited-practice indicators.** The first
  coverage of a chapter already in force (2 February 2025) and carrying
  the Act's heaviest penalties (Article 99(3): up to EUR 35M or 7% of
  worldwide turnover). Detects components implementing emotion
  inference, facial recognition, and biometric categorisation.
  Deliberately never a verdict: Article 5 turns on purpose and
  deployment setting that a static scan cannot observe, so each signal
  states what the cited paragraph prohibits, the carve-outs, and the
  question a human must answer. The section is omitted entirely when
  nothing matches — social scoring, crime-risk prediction and
  manipulative design leave no manifest trace, so "none detected" would
  read as a clearance the scan cannot give.
- **EU AI Act Article 50 — transparency obligations.** The four
  disclosure duties that apply from 2 August 2026: tell people they are
  interacting with an AI, mark synthetic output machine-readably,
  inform people subject to emotion or biometric analysis, and disclose
  deep fakes and AI-generated public-interest text. Grouped per
  obligation rather than per component. Where a duty can be discharged
  by a technical control that leaves a dependency trace — watermarking,
  C2PA provenance — the report shows the evidence found; where it is
  discharged by interface copy or an editorial process, it says so
  rather than reporting a false gap.
- **CycloneDX `vulnerabilities` array.** The export listed components
  while the same scan held live OSV advisories for them, so every
  consumer had to rediscover what AIcap already knew. Each entry links
  to its component by `bom-ref`, quotes severity as published, carries
  the CVSS vector rather than a derived score, and names an upgrade
  target. Curated OWASP/MITRE findings are deliberately excluded — they
  are risk-management entries, not CVEs, and emitting them would make a
  consumer's scanner report vulnerabilities that do not exist.
- **46 further catalog entries** (154 → 176): biometric and affect
  analysis, voice cloning, face swap and talking-head video, plus the
  watermarking and C2PA libraries that serve as Article 50 discharge
  evidence.

### Changed

- No `modelCard` is emitted for detected models. We know a model's
  identifier, licence, and where it was referenced; the fields that
  make a model card useful — training data, evaluation, intended use —
  we do not, and inventing them would put fabricated metadata into an
  audit artefact. The CycloneDX guide states this openly.

## [1.5.0] — 2026-07-24 — Detection coverage, live advisories, signed ledger, drift

The through-line of this release: a compliance tool's failure modes are
asymmetric. A missed component produces a document that is confidently
wrong, and a claim the product cannot back produces a document an
auditor should not accept. Both were present. Both are closed.

### Fixed

- **The scanner could report a clean "Passed" on a project full of
  undeclared AI.** Found by scanning synthetic modern-stack projects
  rather than reading the catalogs. Three independent causes, each
  enough on its own: PEP 621 `dependencies = [...]` arrays under
  `[project]` were not parsed (only the Poetry table form was, while
  the array form is the standard and what uv/hatch/flit/setuptools
  emit); the requirements-file family was matched by exact name, so
  `requirements-dev.txt` and `requirements/base.txt` were invisible;
  and `.ipynb` notebooks were not scanned at all, despite being where
  most ML code and a good share of pasted API keys live. A probe
  project declaring its stack in all three places produced zero
  findings and status "Passed" — a verdict that then gets hash-chained
  into the audit ledger as an attestation. It now produces five.
- **Remediation advice named git commit SHAs as upgrade targets.**
  Found by running against live OSV data rather than fixtures: OSV
  records a `fixed` event per affected range, and projects publishing
  source-range advisories put a commit hash there. `vllm` 0.6.0 (62
  advisories) produced a mitigation listing roughly twenty "versions",
  six of them 40-character SHAs. Non-version values are now filtered
  and a single upgrade target is named — the highest fixed version,
  which clears every affected branch. Version comparison is numeric, so
  0.24.0 correctly beats 0.9.0.
- **Pricing copy contradicted the product in both directions.** The
  Free column advertised Annex IV generation the CLI did not perform;
  the Pro column advertised OSV enrichment and GPU cost estimates that
  in fact run locally at no charge. One overpromises to a buyer, the
  other hides value from them.

### Added

- **Model families.** Hardcoded-model detection matched a flat list of
  literal names last extended in the gpt-4o / claude-3.5 / o1-preview
  generation, so every model shipped since was invisible. 18 compiled
  regex families (OpenAI GPT and o-series, Claude, Gemini, Gemma,
  Llama, Mistral/Mixtral, DeepSeek, Qwen, Grok, Command, Phi,
  Nova/Titan, Jamba, DBRX, Yi, image models) match case-insensitively
  anywhere in a literal, so vendor prefixes and date suffixes work.
  Proprietary families supply a licence; open-weight families
  deliberately do not, because the licence varies per checkpoint and a
  visible gap beats a guess.
- **AI library catalog: 31 → 130 entries.** The largest hole was npm —
  three JS lockfile parsers existed but not one scoped AI package was
  catalogued, so JS/TS projects scanned clean. `boto3` was deliberately
  excluded: a generic cloud SDK in every BOM is noise, and noise
  discredits a report as fast as a gap does.
- **`AICAP_CATALOG_URL`** — detection catalogs refreshable without a
  binary release, mirroring the existing GPU-pricing contract. Embedded
  catalogs survive any failure, so detection never degrades below what
  shipped.
- **The free CLI now emits the Article 9 risk register and the Annex IV
  draft** (`--annex-iv <path>`, `--no-annex-iv` to skip), with OSV
  enrichment running in the caller's own pipeline. Both are pure
  functions in an MIT-licensed package, so gating them protected
  nothing while withholding the artefact that demonstrates the product.
  A locally generated document states plainly in its § 5 that it is
  unattested, cannot be independently verified, and can be regenerated
  or back-dated by anyone with access to the machine.
- **Ed25519 signatures on every ledger entry.** The hash chain proved
  the rows were consistent with each other, not who wrote them — anyone
  with database write access could rewrite a payload, recompute every
  hash, and verify clean. The signing key lives in the process
  environment and never in the database. `GET /api/ledger/public-key`
  publishes the verifying key unauthenticated, and shared reports carry
  the signature plus the exact signed bytes, so a recipient can verify
  offline against the party who sent them the link. `/api/verify-chain`
  reports signed and unsigned counts rather than a bare `ok`.
- **Scan-to-scan drift** (`GET /api/drift`, dashboard card). The ledger
  had stored consecutive proof drills since Wave 4 without ever
  comparing two of them. The signal it exists for is an advisory
  appearing against a component nobody touched — the case a
  point-in-time audit structurally cannot surface, and the evidence EU
  AI Act Article 72 post-market monitoring asks for.
- **OSV lookups decoupled from the static risk catalog.** A dependency
  was only queried if its name already appeared in the ten-entry
  `vulns.json`, so the register could never report a vulnerability that
  catalog had not anticipated. Every dependency with a mappable
  ecosystem and a concrete version is now checked, and one with a live
  advisory but no catalog entry gets a finding of its own. The full
  advisory is kept — summary, severity as published, CVSS vector, and
  the fixed version. Severity is quoted, never recomputed.
- **Documentation split.** `documentation/internal/` is gitignored as a
  whole directory, so a private note is private by default rather than
  by remembering to write an ignore rule. The data-residency statement
  became a published page with a URL that can be pasted into a security
  questionnaire.

### Changed

- Placeholder versions (`imported`, `local`, `docker-install`) are no
  longer sent to OSV. `/v1/query` without a parseable version returns
  every advisory ever filed against a package, including ones fixed
  long before the version in use; attributing those would be a
  fabricated finding.
- OSV results are sorted before being applied, so identical inputs
  produce a byte-stable register and Annex IV.

## [1.4.0] — 2026-07-22 — Organization move + domain consolidation

### Changed
- **Repository moved to the `aicaplabs` organization.** Every reference
  updated from `istrategeorge/AIcap` to `aicaplabs/AIcap`: the Action's
  binary download URL, README quick-start and clone URL, GitLab and
  Bitbucket CI templates, the Helm chart's `home`/`sources`/maintainer
  and image repository, the OpenAPI contact/description, the dashboard
  CI snippet, and the CI-tutorial guides. GitHub redirects keep existing
  `uses: istrategeorge/AIcap@…` pipelines working, but pinning the new
  path is the durable form — the redirect only survives while no repo of
  the old name is recreated.
- **Primary domain is now `aicap.dev`** (registered; Cloudflare DNS +
  Email Routing). Consolidates the earlier domain sweep: the CLI's
  README badge link and the Annex IV PDF provenance footer point at
  `aicap.dev` instead of the never-owned `aicap.eu`, and the OpenAPI
  production server URL replaces the third-party-owned `aicap.app`.
  Removing references to domains the project does not control closes a
  squatting/phishing vector on distributed badges.
- CI-tutorial guides now pin `v1.4.0` (they still referenced `v1.2.0`).

## [1.3.3] — 2026-07-17 — Marketplace listing assets

### Added
- **README screenshots** — five images under `documentation/screenshots/`
  showing the product end-to-end: a passing and a blocking CI run
  (verdict + README badge snippet), the generated Annex IV preview
  (Export PDF / Share / Download), a public shared report page, and
  the immutable audit-ledger table. Embedded in a new "See it in
  action" section near the top of the README, ahead of the feature
  list — this is also the asset set for the GitHub Marketplace
  listing (`github.com/marketplace/actions/continuous-ai-bom-scanner`).

## [1.3.2] — 2026-07-09 — Scanner false-positive fix

### Fixed
- **Hardcoded-model detector no longer flags prose.** Any string
  literal containing a model-name substring (test-assertion messages,
  log lines, format strings — "expected 2 deps (openai + llama-3
  weight), got %d") was reported as a High-risk "Hardcoded Model"
  finding, polluting Annex IV output. Real model identifiers never
  contain whitespace, so literals with whitespace are now treated as
  prose. `parseGoAST` also unquotes literals (`strconv.Unquote`) so
  escaped whitespace counts.

## [1.3.1] — 2026-07-09 — Release self-reference fix

### Fixed
- v1.3.0 was tagged before `action.yml`'s own download URL was
  bumped, so `uses: aicaplabs/AIcap@v1.3.0` fetched the v1.2.0
  binary. No source changes beyond version strings — use v1.3.1+
  instead of v1.3.0.

## [1.3.0] — 2026-07-09 — Conversion & distribution (Waves 14–15) + fixes

### Added — GTM: SEO guides + Marketplace prep (Wave 14)
- **10 static, crawlable guide pages** at `/guides/`, generated at
  build time from `frontend/guides/*.md` by
  `frontend/scripts/build-guides.mjs` (wired into `npm run build`, so
  Vercel regenerates them on every deploy). Each page gets a canonical
  URL, Open Graph tags, and Article JSON-LD. Topics span the
  highest-intent pre-deadline queries: Annex IV checklist, AI-BOM vs
  SBOM, CycloneDX export, Article 9 continuous risk management, Annex
  III high-risk classification, Article 53 GPAI documentation,
  container-image weight scanning, GPU cost detection, the GitHub
  Actions tutorial, and the penalties explainer.
- **`sitemap.xml` + `robots.txt`** emitted alongside the guides so
  crawlers enumerate them without relying on link discovery from the
  SPA landing page.
- **Markdown renderer** (`lib/annexIVPdf.js`) gained fenced-code-block
  support and now re-renders wrapped list items from their
  accumulated raw source, so inline formatting (bold/italic) spanning
  a hard line-wrap renders correctly instead of leaking literal `**`.
- **`action.yml`** gains a `compliance-status` output (extracted from
  the scan JSON with the CLI's gating exit code preserved) so
  downstream workflow steps can branch on the verdict.
- **`documentation/marketplace-listing.md`** — GitHub Marketplace
  publication checklist, category choices, release-notes copy, and a
  README screenshot shot list.

### Added — Conversion & distribution features (Wave 15)
- **Annex IV PDF export** — `lib/annexIVPdf.js` renders report
  markdown to a print-ready HTML document via a hidden iframe
  (`exportAnnexIVPdf`); every export carries a provenance footer with
  the ledger hash. Export buttons added to the dashboard preview and
  the public report page.
- **Sample report landing section** — a full Annex IV sample for a
  fictional high-risk hiring system, rendered on the public landing
  page with a download-as-PDF CTA.
- **EU AI Act deadline countdown** — landing-page badge counting down
  to 2 August 2026, switching to "obligations are now in force" copy
  once the date passes.
- **CLI README badge** — `badgeMarkdown` prints a shields.io snippet
  reflecting the scan posture (passing / action required / policy
  breach) after every `--cli` run, linking back to aicap.eu.
- **Shareable public report links** — migration `00013` adds
  `proof_drills.share_token` (partial unique index, NULL until
  explicitly shared). `POST /api/share-report {hash}` mints a 256-bit
  capability token (idempotent — re-sharing returns the same token
  with 200); `DELETE ?hash=` revokes it instantly. Public
  `GET /api/public/report?token=` resolves it unauthenticated
  (malformed / unknown / revoked tokens are all indistinguishable
  404s). Frontend: `/?report=<token>` renders `PublicReport.jsx`,
  bypassing the auth state machine entirely; a Share button on the
  Pro dashboard copies the link.
- **Legal & trust pages** — Terms, Privacy Policy, DPA summary, and
  Security pages at `/?page=terms|privacy|dpa|security`, linked from
  a new Legal footer column. Includes the compliance disclaimer that
  generated Annex IV documents are drafts, not legal advice.

### Fixed
- **`pkg/finops/rightsize.go`** — the rightsizing savings range could
  invert (`estimatedSavingsMonthlyUsdLow > ...High`) when the
  recommended family's price spread was wider than the current
  family's (e.g. a single-size `p4d.` vs. `inf2.`, which spans
  `xlarge`–`48xlarge`). The two scenario values are now ordered
  before being returned.
- **CLI cloud sync** — `/api/save-proof` has returned `200` (not just
  `201`) for an idempotent replay of an already-recorded commit since
  Wave 6, but the CLI only treated `201` as success. Every workflow
  re-run on an unchanged commit printed "Failed to sync (Is the
  server reachable?)" against a healthy backend. `syncStatusMessage`
  now distinguishes created (201) and idempotent-replay (200) success
  from named rejections (402 quota, 401 bad key) and unknown errors.

## [1.2.0] — 2026-06-17 — Waves 9c–13: reverse trial, FinOps, image scanning, EU hosting

### Added — Compliance polish, policy exit codes, Playwright (Wave 12)
- **`.aicap.yml` expanded fields** — `contact_email`, `data_inputs`,
  `training_datasets` parsed by `LoadPolicyConfig`. Annex IV § 1 now
  renders them when present and keeps the `[REQUIRES MANUAL INPUT]`
  placeholder when absent — a fully populated policy file means the
  generated document needs zero manual editing post-scan. Surfaces
  `Provider Contact`, `Data Inputs`, and `Training Datasets` lines.
- **Policy-violation exit codes** — `aicap --cli` now exits **2** when
  the BOM has any Blocker-severity policy violation (blocked model,
  allowlist miss, `block_on_high_risk`), **1** for non-policy compliance
  failures (high-risk dep without mitigation), **0** when clean. Allows
  CI pipelines to fail fast on explicit policy breaches without
  conflating them with informational risk warnings. New `complianceExitCode`
  helper + 4 unit tests in `main_test.go`.
- **Playwright E2E scaffolding** — `frontend/playwright.config.js` +
  `frontend/e2e/`. One actively-exercised spec (`scan-to-annex.spec.js`)
  runs against `npm run dev` in local mode with `/api/scan`,
  `/api/db-config`, `/api/history` mocked via route handlers; asserts
  the BOM table hydrates, the FinOps spot column renders, the Annex IV
  preview opens, and the download CTA produces a markdown file. Two
  auth-dependent specs (`signup-checkout-key.spec.js`,
  `rotate-key.spec.js`) ship as `test.fixme` placeholders with TODOs
  describing the Supabase auth-mocking layer the next iteration needs.
  CI job added to `.github/workflows/go-test.yml`.

### Added — FinOps spot/rightsizing + dev-ex headers + OpenAPI (Wave 11)
- **Spot/preemptible projection** — `pkg/finops/gpu_costs.json` carries
  per-cloud `spot_multipliers` (0.30 AWS / Azure / GCP defaults).
  `LookupGPUCost` populates `SpotHourly/MonthlyUSD*` fields on every
  matched `FinOpsCost`; `EstimateBOMCost` aggregates
  `TotalSpotMonthlyUSD*` and derives `SpotSavingsMonthlyUSD*`. Annex IV
  § 2(c) and the dashboard FinOps table now show the spot projection
  alongside the on-demand figure with a savings callout.
- **Rightsizing recommendations** — `pkg/finops/rightsize.go` emits
  `FinOpsRightsizing` suggestions when `HasTrainingSignals(bom)` is
  false and the finding's family is in a curated training→inference
  map (AWS `p4d`/`p4de`/`p5`/`p3`/`trn1` → `inf2`/`g5`; GCP
  `a3-highgpu`/`a2-*` → `g2-standard`). Skips findings on
  already-inference families. Surfaces under § 2(c) "Rightsizing
  recommendations" with rationale + estimated savings range.
- **Rate-limit response headers** — `/api/save-proof` emits
  `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`
  on free post-trial responses (both 201 and 402). Remaining is
  post-decrement (GitHub convention). Pro/trial callers receive no
  headers (treated as unlimited). Reset = oldest in-window scan +
  30 days. New `strconv` import + single round-trip count query.
- **OpenAPI 3.0.3 spec** — `pkg/api/openapi.json` embedded via
  `//go:embed`; `GET /api/openapi.json` serves it with
  `Cache-Control: public, max-age=3600`. Covers all routes
  (`save-proof`, `history`, `proof`, `verify-chain`, `me`,
  `generate-key`, `rotate-key`, `create-checkout-session`,
  `verify-checkout`, `customer-portal`, `stripe-webhook`, `livez`,
  `readyz`), both auth schemes (`apiKey` / `supabaseJWT`), and the
  new rate-limit headers.

### Added — Live FinOps catalog refresh (Wave 9e)
- **`AICAP_GPU_COSTS_URL`** — optional remote catalog URL fetched at
  server boot via `finops.LoadCatalogFromURL`. Lets ops refresh GPU
  pricing without cutting a binary release. Fail-soft: any fetch /
  non-200 / parse failure leaves the embedded `gpu_costs.json`
  intact, logged at WARN. 5-second client timeout.

### Added — 14-day reverse trial (Wave 9c)
- **Migration 00012** — `api_keys` gains `trial_ends_at TIMESTAMPTZ`.
  New signups land with `trial_ends_at = NOW() + INTERVAL '14 days'`
  so they have full Pro-equivalent access from day one without a card.
- **Rate limiter** checks `trial_ends_at > NOW()` before applying the
  free-tier quota — trial users see no `402` ceiling.
- **`/api/me`** returns `trialDaysRemaining` so the frontend can show
  a countdown ribbon. `App.jsx` routes trial users to `ProDashboard`
  even when `tier === 'free'`. `Paywall` differentiates "trial just
  expired" vs "free from day one" with separate copy.

### Added — Daemonless container-image filesystem scanning (Wave 10)
- **`pkg/imagescan/`** — walks OCI / Docker image layers without a
  running Docker daemon, via `github.com/google/go-containerregistry`.
  Two entry points: `ScanImage(ctx, ref)` pulls from a registry
  (auth via `authn.DefaultKeychain`, so existing `docker login`
  state and CI provider helpers Just Work), and
  `ScanTarball(ctx, path)` reads a local `docker save` tarball
  before push.
- Per-layer detection: model-weight files (same extensions as the
  directory scanner — `.safetensors`, `.onnx`, `.pt`, `.gguf`, …)
  and the `pytorch_model.bin` / `model.safetensors` sentinel names;
  Python package metadata at `*.dist-info/METADATA` (PEP 566,
  cross-referenced against the curated AI library catalog so
  `numpy` doesn't fire but `openai` does); Node.js package metadata
  at `node_modules/.../package.json`. Whiteout markers ignored;
  oversized "METADATA" entries (>256 KB) skipped to prevent
  memory abuse from hostile layers.
- **`scanner.LookupLibrary`** exposed for cross-package
  cross-referencing — `pkg/imagescan` looks up Python / Node
  package names against the same `libraries.json` catalog the
  directory scanner uses.
- **CLI**: `aicap --cli [dir] --image <ref> --image-tar <path>` —
  both flags repeatable; failures (unreachable registry, malformed
  tarball) surface as warnings without aborting the directory scan.
  Findings merge into `bom.Dependencies` so risk register / OWASP
  cross-referencing / Annex IV all apply transparently. Unknown
  flags are silently dropped for forward compatibility with newer
  `action.yml` releases.
- **`types.AIBOM.ScannedImages`** records the inspected images
  (reference, digest, source=registry|tarball, layer count, finding
  count) so Annex IV § 2(d) "Container Images Inspected" attributes
  each layer-derived finding back to its image. Per-finding
  `Location` strings carry `image#layerN:path` for layer-level
  traceability.
- **Tests**: 20 new unit tests in `pkg/imagescan/` (in-memory tar
  fixtures, AI / non-AI lookup, model-weight extensions, sentinel
  filenames, whiteout markers, oversized-entry safety, node_modules
  scoping, `tarball.WriteToFile` round-trip via `ScanTarball`, and
  an in-process `registry.New()` httptest server for `ScanImage`).
  5 new CLI-arg tests in `main_test.go` covering repeatable
  flag parsing + forward-compat unknown-flag tolerance. 2 new
  Annex IV § 2(d) rendering tests in `pkg/scanner/scanner_test.go`
  (rendered when present, omitted when empty). Phase 2 → ~100%.

### Added — EU data residency: backend migrated Render (US) → Scaleway (Wave 13)
- **Backend compute moved to Scaleway Serverless Containers** (`fr-par`,
  Paris). The database was already on Supabase `eu-west-1` (Ireland),
  so this migration was compute-only — no data migration needed. All
  persisted application data now resides in the EU.
- **`deploy/terraform/scaleway/`** — Terraform module provisioning a
  private Container Registry namespace, a Serverless Container
  namespace, and the backend container. Scale-to-zero (`min_scale=0`)
  by default to stay within Scaleway's free tier.
- **`documentation/data-residency.md`** — per-data-class location
  table and sub-processor list for enterprise DPA due diligence.
- Backend URL moved to `*.functions.fnc.fr-par.scw.cloud`; frontend
  `VITE_API_URL` on Vercel repointed; Render retired.

## [1.1.0] — 2026-05-02 — Self-host, GTM surface, billing self-serve & live CVE enrichment

### Added — Helm chart for self-hosted Enterprise tier (Wave 8a)
- **`deploy/helm/aicap/`** — production-grade Helm chart so Enterprise
  customers can `helm install aicap ./deploy/helm/aicap -f my-values.yaml`
  and run the backend in their own cluster against their own Postgres.
- Probes wired to the Wave 4 split: `livenessProbe → /livez` (never
  restarts pods on DB outage), `readinessProbe → /readyz` (pulls out
  of LB when DB ping fails).
- Dual secrets mode: inline values for dev/quick-start; `existingSecret`
  for production with sealed-secrets / external-secrets / Vault.
- Migration strategy: `config.runMigrations=true` (startup mode, default)
  or `migrationJob.enabled=true` (pre-upgrade Helm hook Job).
- Security defaults: non-root uid 65532, `readOnlyRootFilesystem: true`,
  all caps dropped, `automountServiceAccountToken: false`,
  `seccompProfile: RuntimeDefault`.
- Optional `Ingress`, `HorizontalPodAutoscaler`, and `PodDisruptionBudget`
  (all off by default; recommended values documented in chart README).

### Added — GTM surface & public marketing (Wave 8b)
- **SEO-shaped `<head>`** in `frontend/index.html`: title, meta
  description, Open Graph, Twitter card, JSON-LD `SoftwareApplication`
  structured data with `Offer` blocks for Free + Pro pricing.
- **`PricingSection.jsx`** — three-tier card (Free CLI / Pro $49/mo /
  Enterprise self-host) with feature lists and CTAs.
- **`FAQSection.jsx`** — 8 entries answering the questions a prospect
  asks before signing up; native `<details>` for keyboard accessibility
  and crawler readability.
- **`MarketingFooter.jsx`** — four-column footer (Product, Resources,
  Compliance, Contact).
- **`templates/gitlab-ci.yml`** rewrite — pulls the pre-built
  `aicap-linux-amd64` release binary instead of building from source;
  optional `aicap_cyclonedx_sbom` job as a 30-day artifact.
- **`templates/bitbucket-pipelines.yml`** rewrite — anchored steps for
  default / PR / branch flows; CycloneDX SBOM artifact on `main` and
  `master`.
- **`CONTRIBUTING.md`** — branch model, local workflows, ranked list of
  high-impact contribution types, "what we won't merge" list, and
  security-disclosure email.

### Added — Annex IV § 1 auto-fill + Helm CI smoke (Wave 9)
- **`.aicap.yml`** project config file: declare `system_name`,
  `version`, `provider`, `intended_purpose`, `deployment_context`,
  and `high_risk_category` in the repo; the scanner reads these and
  populates Annex IV § 1 (General Description) automatically instead
  of emitting `[REQUIRES MANUAL INPUT]` placeholders.
- **Helm lint + template CI** — `.github/workflows/helm-lint.yml` runs
  `helm lint` and five `helm template` variant renders (defaults,
  inline secrets, external secrets, migrationJob mode, HPA + Ingress +
  PDB) on every push/PR touching the chart.

### Added — Stripe billing self-serve (Wave 7e)
- `POST /api/customer-portal` — Supabase JWT-gated; creates a Stripe
  BillingPortal session and returns `{url}`. Returns 400 for free-tier
  users (no Stripe customer). Frontend "Manage subscription" button
  POSTs via `apiFetch` (401 refresh-and-retry applies) and redirects
  same-tab.

### Added — Live CVE/GHSA enrichment via OSV.dev (Wave 7f)
- `pkg/compliance/osv.go` — `OSVClient` wraps `api.osv.dev/v1/query`
  with configurable timeout + 5-worker concurrent fan-out.
  `EnrichWithOSV` attaches `LiveVulnIDs` to catalog-matched findings.
- Annex IV § 3(a) gains a "Live CVE/GHSA" column rendering live IDs
  as inline code spans; "—" when absent.
- Curated catalog stays primary; OSV failures fall back to
  catalog-only findings deterministically so compliance reports stay
  reproducible in CI.
- Configurable via `AICAP_OSV_DISABLED` / `AICAP_OSV_URL` /
  `AICAP_OSV_TIMEOUT_MS`.

### Fixed — CI reliability
- Security-scan steps in `staging-scan.yml` and `test-scan.yml` now
  use `continue-on-error: true` so a compliance finding (intended
  scanner output) shows as a warning rather than failing the job.
- Helm `NOTES.txt` type error: `config.runMigrations` changed from
  string `"true"` to boolean `true` in `values.yaml`; template
  condition updated to a truthiness check so `--set
  config.runMigrations=false` no longer triggers an incompatible-types
  comparison error.

### Maturity snapshot (vs v1.0.0-alpha baseline)
| Phase | v1.0.0-alpha | v1.1.0 | Δ |
|---|---|---|---|
| Phase 1 (Stack) | 70% | 95% | +25 |
| Phase 2 (Scanning) | 40% | 92% | +52 |
| Phase 3 (Compliance) | 20% | 95% | +75 |
| Phase 4 (CI/CD) | 60% | 98% | +38 |
| Phase 5 (Sovereignty) | 10% | 60% | +50 |
| Phase 6 (FinOps) | 15% | 75% | +60 |
| Phase 7 (Pricing) | 30% | 95% | +65 |
| Phase 8 (GTM) | 10% | 55% | +45 |
| **Overall MVP readiness** | **~32%** | **~83%** | **+51** |

## [0.7.0] — internal milestone, 2026-04-30 — Compliance intelligence + FinOps cost + multi-manifest

Internal development milestone. Not released as a GitHub tag; all
changes below shipped in v1.1.0.

### Added — scanning depth (Wave 7c)
- **Lockfile parsers** — `poetry.lock`, `Pipfile.lock`, `pnpm-lock.yaml`,
  `yarn.lock`, `environment.yml` (Conda). Lockfiles are the authoritative
  version source; previous waves only saw the looser-pinned manifests.
- **Multi-language SBOM coverage**: Python (pip / Poetry / Pipenv /
  Conda), Node.js (npm / pnpm / yarn), Go (`go.mod`), and container
  images (`Dockerfile` base images + `pip install` lines in `RUN`).

### Added — FinOps cost estimation (Wave 7b)
- **`pkg/finops/`** new package with embedded `gpu_costs.json` curated
  catalog covering AWS p3/p4d/p4de/p5/g4dn/g5/g5g/g6/inf1/inf2/trn1,
  Azure NC/ND/NV, and GCP a2-highgpu/a2-megagpu/a3-highgpu/g2-standard.
- `LookupGPUCost(content)` returns hourly + monthly USD ranges per
  detected instance family; nil when the catalog has no match.
- `EstimateBOMCost(bom)` aggregates per-finding costs into a BOM-level
  summary with costed/uncosted finding counters so auditors know when
  the headline figure is missing detections.
- Per-finding cost line + BOM-level total + assumptions disclaimer
  rendered into Annex IV § 2(c) and the dashboard FinOps table.

### Added — Annex IV § 3(c) + § 4 auto-population (Wave 7a)
- `pkg/scanner/governance.go` — six conservative IaC detectors:
  - **HITL** from k8s `metadata.name` patterns (word-bounded
    `review|approval|human|hitl|moderation|feedback|judge|reviewer|escalation`),
    Argo Workflow `suspend:` steps, GitHub Actions `environment:` keys.
  - **Training data** from `*.dvc` / `dvc.yaml` / `dvc.lock`, Terraform
    `aws_s3_bucket` / `google_storage_bucket` matching training-data
    name patterns, and HuggingFace `from datasets import load_dataset(...)`.
  - **Bias monitoring** from Python imports of `fairlearn` / `aif360` /
    `responsibleai` / `equalized_odds` plus their entries in
    `requirements.txt` / `pyproject.toml`.
  - **Prompt-injection defences** from imports of `lakera` /
    `lakera_guard` / `rebuff` / `nemoguardrails` / `presidio_analyzer`
    / `garak` / `llm_guard` plus same names in dependency manifests.
- Annex IV § 3(c) and § 4 sub-sections render evidence when found,
  keep `[REQUIRES MANUAL INPUT]` when not — never both at once.
  Frontend `lib/annexIV.js` mirrors backend rendering.

### Added — Article 9 risk register (Wave 6 Phase B)
- `pkg/compliance/vulns.json` — embedded curated AI risk catalog
  (tensorflow, torch, pytorch, transformers, langchain, openai,
  anthropic, huggingface_hub, scikit-learn, diffusers) mapping each
  to OWASP ML Top 10 / MITRE ATLAS / EU AI Act articles / mitigation.
- `ComputeRiskRegister(bom)` cross-references detected deps; result
  persists into `proof_drills.risk_register_state` (the JSONB column
  that had been empty since migration 00002).
- Annex IV § 3(a) "Cross-Referenced Risk Register (OWASP ML Top 10 /
  MITRE ATLAS)" replaces the previous minimal heuristic table.

### Changed — Stripe lifecycle correctness (Wave 6 Phase A)
- **Idempotent `/api/save-proof` by `(user_id, commit_sha)`**.
  Migration 00011 adds a partial UNIQUE index. The handler does a
  SELECT-first short-circuit inside the existing per-user advisory
  lock; CI retries return 200 OK with the existing `cryptoHash` and
  `{idempotent: true}`, no duplicate audit row.
- **`customer.subscription.updated`** now reflects Stripe status into
  `api_keys.subscription_tier`. `active`/`trialing` → `pro`,
  anything else (`past_due`, `canceled`, `incomplete_expired`,
  `unpaid`, `paused`) → `free`. Users whose card declines lose Pro
  on the next save-proof.
- **Soft revoke** — `subscription.deleted` and `payment_failed`
  (after 3 attempts) now `UPDATE … SET subscription_tier = 'free'`
  instead of `DELETE FROM api_keys`. The `token_hash` survives, so
  re-subscribers don't have to regenerate their CI key.

### Changed — frontend split + first tests (Wave 5)
- `frontend/src/App.jsx` reduced from **1059 → 316 lines** (−70%) by
  extracting `lib/supabase.js` (client + `apiFetch`), `lib/annexIV.js`
  (markdown builder + download), and 9 components under
  `components/`. App.jsx is now a top-level state machine + view
  router only.
- First-ever frontend tests via Vitest + React Testing Library:
  `apiFetch.test.js` covers the 401 refresh-and-retry contract;
  `KeyVault.test.jsx` covers the three-state UI machine.

### Added — Wave 4 platform hardening
- **Hash-chain ledger anchoring** — migration 00010 adds `prev_hash`
  on `proof_drills`. Each save-proof opens a transaction, takes a
  per-user `pg_advisory_xact_lock`, and writes a row whose
  `crypto_hash` is `sha256(commit_sha || ai_bom_json || prev_hash)`.
  `GET /api/verify-chain` walks the chain and reports the first
  divergence.
- **Refresh-token recovery** — `onAuthStateChange` branches on
  `TOKEN_REFRESHED` to update only `accessToken` without re-running
  the bootstrap flow. `apiFetch` reads the live token from
  supabase-js's cache and on a 401 calls `refreshSession()` once
  and retries.
- **`/livez` + `/readyz` split** — liveness stays 200 on DB outage;
  readiness pulls out of LB. `/healthz` kept as a `/readyz` alias.
- **CI integration tests** — GitHub Actions runs unit +
  `go test -tags=integration` against a Postgres 16 service container.

### Added — Wave 3 SaaS readiness (3a / 3b / 3c)
- Stripe webhook replay protection via `stripe_events` PK idempotency.
- `pkg/httplog` slog JSON handler with per-request `X-Request-ID`.
- Graceful shutdown with 25 s SIGTERM drain.
- API keys hashed at rest (SHA-256). Plaintext returned exactly once
  from `/api/generate-key` or `/api/rotate-key`. Migration 00009.
- `/api/me` (RLS-independent reads via the direct Postgres connection).
- `/api/verify-checkout` Stripe API fallback when the webhook is
  delayed or misconfigured.

### Added — Wave 2 ops baseline
- Embedded SQL migration runner (`pkg/migrate`) with idempotency.
- Docker multi-stage build + `docker-compose.yml` for local Postgres.
- Integration test suite behind `//go:build integration`.
- Rolling 30-day rate-limit query.

### Added — Wave 1 tenant + auth baseline
- Supabase JWT auth on dashboard routes; API key auth on CI route.
- Tenant scoping on `/api/history` and `/api/proof` (user_id isolation).
- CORS preflight fix (OPTIONS passes through auth middleware).
- Free tier: 10 scans / 30-day rolling window.

[Unreleased]: https://github.com/aicaplabs/AIcap/compare/v1.4.0...HEAD
[1.4.0]: https://github.com/aicaplabs/AIcap/compare/v1.3.3...v1.4.0
[1.1.0]: https://github.com/aicaplabs/AIcap/compare/v1.0.0-beta...v1.1.0
