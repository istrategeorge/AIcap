package compliance

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"aicap/pkg/types"
)

// GenerateAnnexIVMarkdown is the convenience entry point used by
// callers (e.g. the CLI) that don't have a pre-computed risk
// register on hand. It just delegates to the with-register variant
// after computing the catalog-only register internally.
func GenerateAnnexIVMarkdown(bom types.AIBOM) string {
	return GenerateAnnexIVMarkdownWithRegister(bom, ComputeRiskRegister(bom))
}

// GenerateAnnexIVMarkdownWithRegister renders Annex IV using a
// caller-supplied register. /api/save-proof uses this so the
// rendered markdown reflects the OSV-enriched register (Wave 7f),
// not just the catalog-only one. Pure formatter — does no I/O.
//
// The document is rendered as ledger-anchored, which is correct for the
// save-proof path this serves. Local renders must use
// GenerateAnnexIVMarkdownWithAttestation and say so.
func GenerateAnnexIVMarkdownWithRegister(bom types.AIBOM, register types.RiskRegister) string {
	return GenerateAnnexIVMarkdownWithAttestation(bom, register, types.Attestation{Anchored: true})
}

// GenerateAnnexIVMarkdownWithAttestation renders Annex IV and states, in
// § 5, whether the result is anchored in the audit ledger or was
// generated locally and is unattested.
//
// Splitting this out (Wave 16) is what made it safe to emit Annex IV
// from the free CLI: the document is genuinely useful on its own, but
// the § 5 boilerplate previously asserted an "immutable audit trail"
// unconditionally, which is false for a local run. The reader is told
// which artefact they hold.
func GenerateAnnexIVMarkdownWithAttestation(bom types.AIBOM, register types.RiskRegister, att types.Attestation) string {
	return GenerateAnnexIVMarkdownWithOptions(bom, register, AnnexIVOptions{Attestation: att})
}

// AnnexIVOptions controls what goes into the rendered document.
type AnnexIVOptions struct {
	Attestation types.Attestation

	// IncludeCostEstimates adds monetary figures — per-resource cost,
	// spot projections, and rightsizing savings — to § 2(c). Off by
	// default, which is the important part.
	//
	// The hardware and compute description belongs in Annex IV: Section 2
	// requires the computational resources used to develop and run the
	// system. What a p4d costs per month does not. That is a FinOps
	// insight, not a compliance fact, and putting it in this document
	// carries a cost of its own — the figures are list-price, on-demand,
	// USD, 730-hours-a-month, and a reader who notices that (any platform
	// engineer will, in seconds) has just been handed a reason to ask
	// what *else* in the document is an estimate. The Article 9 risk
	// register and the ledger provenance cannot afford to sit beside an
	// easily falsified number.
	//
	// So costs stay available to the audiences that want them — the JSON
	// output and the dashboard, read by engineers — and stay out of the
	// artefact handed to an auditor unless explicitly requested.
	IncludeCostEstimates bool
}

// GenerateAnnexIVMarkdownWithOptions is the full renderer that the three
// convenience entry points above delegate to.
func GenerateAnnexIVMarkdownWithOptions(bom types.AIBOM, register types.RiskRegister, opts AnnexIVOptions) string {
	att := opts.Attestation
	var sb strings.Builder
	sb.WriteString("# EU AI Act - Annex IV Technical Documentation\n\n")
	sb.WriteString(fmt.Sprintf("*Generated: %s*\n\n", time.Now().UTC().Format(time.RFC3339)))

	// Section 1: General Description
	sb.WriteString("## 1. General System Description (Annex IV, Section 1)\n")
	sb.WriteString(fmt.Sprintf("- **System Name:** %s\n", bom.ProjectName))
	sb.WriteString(fmt.Sprintf("- **Version / Commit SHA:** `%s`\n", bom.CommitSha))
	sb.WriteString(fmt.Sprintf("- **Total Files Scanned:** %d\n", bom.ScannedFiles))
	// Distinct components, with the raw detection count beside it.
	//
	// § 2(a) groups repeated detections into one entry per component, so
	// reporting only len(bom.Dependencies) here left the headline count
	// forty higher than the number of entries a reader can actually
	// count in the section below it. Two numbers that disagree in a
	// compliance document invite the reader to distrust both, and the
	// distinct-component figure is the one that answers "how much AI is
	// in this system".
	distinct := countDistinctComponents(bom.Dependencies)
	if distinct == len(bom.Dependencies) {
		sb.WriteString(fmt.Sprintf("- **AI Components Detected:** %d\n", distinct))
	} else {
		sb.WriteString(fmt.Sprintf("- **AI Components Detected:** %d distinct (%d total detections across all files)\n",
			distinct, len(bom.Dependencies)))
	}
	if bom.Policy != nil && bom.Policy.Purpose != "" {
		sb.WriteString(fmt.Sprintf("- **Intended Purpose:** %s\n", bom.Policy.Purpose))
	} else {
		sb.WriteString("- **Intended Purpose:** `[REQUIRES MANUAL INPUT: Describe the exact purpose of this AI system]`\n")
	}
	// Wave 12: declarative Annex IV § 1 fields from .aicap.yml. Each
	// renders evidence when populated and the [REQUIRES MANUAL INPUT]
	// placeholder otherwise, so an auditor reading the document always
	// sees one or the other — never a silent omission.
	if bom.Policy != nil && bom.Policy.ContactEmail != "" {
		sb.WriteString(fmt.Sprintf("- **Provider Contact:** %s\n", bom.Policy.ContactEmail))
	} else {
		sb.WriteString("- **Provider Contact:** `[REQUIRES MANUAL INPUT: Email of the provider's regulatory point-of-contact]`\n")
	}
	if bom.Policy != nil && len(bom.Policy.DataInputs) > 0 {
		sb.WriteString("- **Data Inputs:**\n")
		for _, in := range bom.Policy.DataInputs {
			sb.WriteString(fmt.Sprintf("  - %s\n", in))
		}
	} else {
		sb.WriteString("- **Data Inputs:** `[REQUIRES MANUAL INPUT: List the modalities and sources of input data the system accepts]`\n")
	}
	if bom.Policy != nil && len(bom.Policy.TrainingDatasets) > 0 {
		sb.WriteString("- **Training Datasets:**\n")
		for _, ds := range bom.Policy.TrainingDatasets {
			sb.WriteString(fmt.Sprintf("  - %s\n", ds))
		}
	} else {
		sb.WriteString("- **Training Datasets:** `[REQUIRES MANUAL INPUT: List the datasets used to train or fine-tune the system, with version + provenance]`\n")
	}
	sb.WriteString("\n")

	// Section 2: Architecture & Components
	sb.WriteString("## 2. System Architecture & Components (Annex IV, Section 2)\n\n")

	// 2(a): Dependencies grouped by ecosystem
	sb.WriteString("### 2(a) Pre-trained Systems & Dependencies (AI-BOM)\n")
	if len(bom.Dependencies) == 0 {
		sb.WriteString("No AI dependencies detected.\n\n")
	} else {
		// Group by ecosystem, then collapse identical components within
		// each group and report where they were found.
		//
		// The same component is legitimately detected many times — one
		// hardcoded model identifier used in eight files produced eight
		// identical lines. Because this section never rendered the
		// Location field, those lines were literally indistinguishable:
		// eight copies of the same sentence, conveying nothing beyond
		// the first. The information that made them distinct — *where* —
		// was the one thing omitted, and it is precisely what an auditor
		// checking a finding needs.
		//
		// So: one line per distinct component, with the occurrence count
		// and the locations. Same facts, a fraction of the page, and
		// actually actionable.
		ecosystems := map[string][]types.AIDependency{}
		for _, dep := range bom.Dependencies {
			ecosystems[dep.Ecosystem] = append(ecosystems[dep.Ecosystem], dep)
		}
		// Sorted: a map range gave the sections a different order on
		// every run, so two scans of an unchanged repo produced
		// documents that differed only by shuffling.
		ecosystemNames := make([]string, 0, len(ecosystems))
		for name := range ecosystems {
			ecosystemNames = append(ecosystemNames, name)
		}
		sort.Strings(ecosystemNames)

		for _, ecosystem := range ecosystemNames {
			sb.WriteString(fmt.Sprintf("\n**%s:**\n", ecosystem))
			for _, g := range groupDependencies(ecosystems[ecosystem]) {
				licenseText := ""
				if g.dep.License != "" {
					licenseText = fmt.Sprintf(" [License: %s]", g.dep.License)
				}
				sb.WriteString(fmt.Sprintf("- **%s** (%s)%s: %s (Risk: %s)",
					g.dep.Name, DisplayVersion(g.dep.Version), licenseText,
					g.dep.Description, g.dep.RiskLevel))
				if loc := formatLocations(g.locations); loc != "" {
					sb.WriteString(" — ")
					sb.WriteString(loc)
				}
				sb.WriteString("\n")
			}
		}
		sb.WriteString("\n")
	}

	// 2(b): Licensing Summary (auto-generated)
	//
	// Counted over distinct components, matching § 1 and the entries
	// § 2(a) renders. Counting raw detection sites made "62 / 87" a
	// statement about occurrences rather than components, which is not
	// what a licensing summary is asked for.
	sb.WriteString("### 2(b) Licensing Compliance Summary\n")
	licensedCount := 0
	unlicensedHighRisk := 0
	licenseTypes := map[string]int{}
	seenComponent := map[string]bool{}
	for _, dep := range bom.Dependencies {
		key := componentIdentity(dep)
		if seenComponent[key] {
			continue
		}
		seenComponent[key] = true
		if dep.License != "" {
			licensedCount++
			licenseTypes[dep.License]++
		} else if dep.RiskLevel == "High" {
			unlicensedHighRisk++
		}
	}
	sb.WriteString(fmt.Sprintf("- **Components with license data:** %d / %d\n", licensedCount, len(seenComponent)))
	sb.WriteString(fmt.Sprintf("- **High-risk components missing license:** %d\n", unlicensedHighRisk))
	if len(licenseTypes) > 0 {
		sb.WriteString("- **License distribution:**\n")
		// Sorted for the same reason § 2(a) is: a map range reordered
		// this list on every run.
		licNames := make([]string, 0, len(licenseTypes))
		for lic := range licenseTypes {
			licNames = append(licNames, lic)
		}
		sort.Strings(licNames)
		for _, lic := range licNames {
			sb.WriteString(fmt.Sprintf("  - %s: %d component(s)\n", lic, licenseTypes[lic]))
		}
	}
	sb.WriteString("\n")

	// 2(c): Hardware & Infrastructure
	// § 2(c) describes the compute the system needs, which Annex IV
	// Section 2 requires. Monetary figures are a separate concern gated
	// behind AnnexIVOptions.IncludeCostEstimates — see the comment there.
	if opts.IncludeCostEstimates {
		sb.WriteString("### 2(c) Compute & Hardware Resources (with cost estimates)\n")
	} else {
		sb.WriteString("### 2(c) Compute & Hardware Resources\n")
	}
	if len(bom.FinOps) == 0 {
		sb.WriteString("No specific hardware constraints or GPU requests detected in infrastructure manifests.\n\n")
	} else {
		// Wave 7b: each finding now optionally carries an EstimatedCost
		// from the curated catalog (pkg/finops/gpu_costs.json). Render
		// it inline so auditors see the dollar figure per resource;
		// the summary block below aggregates the total range.
		for _, fin := range bom.FinOps {
			sb.WriteString(fmt.Sprintf("- **Resource:** %s\n", fin.Resource))
			sb.WriteString(fmt.Sprintf("  - **Finding:** %s\n", fin.Description))
			sb.WriteString(fmt.Sprintf("  - **Severity:** %s\n", fin.Severity))
			// The instance family is compute description and stays in
			// regardless; the price attached to it is what the option
			// gates.
			if fin.EstimatedCost != nil && !opts.IncludeCostEstimates {
				sb.WriteString(fmt.Sprintf("  - **Instance family:** %s `%s`\n",
					fin.EstimatedCost.Cloud, fin.EstimatedCost.InstanceFamily))
			}
			if fin.EstimatedCost != nil && opts.IncludeCostEstimates {
				sb.WriteString(fmt.Sprintf(
					"  - **Estimated cost:** $%.2f–$%.2f /hr → **$%.0f–$%.0f /month** (%s family `%s`)\n",
					fin.EstimatedCost.HourlyUSDLow, fin.EstimatedCost.HourlyUSDHigh,
					fin.EstimatedCost.MonthlyUSDLow, fin.EstimatedCost.MonthlyUSDHigh,
					fin.EstimatedCost.Cloud, fin.EstimatedCost.InstanceFamily,
				))
				if fin.EstimatedCost.SpotMultiplier > 0 {
					sb.WriteString(fmt.Sprintf(
						"  - **Spot/preemptible projection:** **$%.0f–$%.0f /month** (%.0f%% of on-demand)\n",
						fin.EstimatedCost.SpotMonthlyUSDLow, fin.EstimatedCost.SpotMonthlyUSDHigh,
						fin.EstimatedCost.SpotMultiplier*100,
					))
				}
			}
		}
		// BOM-level summary surfaces the aggregate, which is what the
		// FinOps user actually budgets against. Costed-vs-uncosted
		// counters tell auditors when the headline figure is missing
		// detections.
		if est := bom.FinOpsCostEstimate; opts.IncludeCostEstimates && est != nil && (est.CostedFindings > 0 || est.UncostedFindings > 0) {
			sb.WriteString(fmt.Sprintf("\n**Estimated total monthly cost:** $%.0f–$%.0f %s "+
				"(across %d costed finding(s); %d additional finding(s) had no catalog match).\n",
				est.TotalMonthlyUSDLow, est.TotalMonthlyUSDHigh, est.Currency,
				est.CostedFindings, est.UncostedFindings))
			if est.TotalSpotMonthlyUSDLow > 0 || est.TotalSpotMonthlyUSDHigh > 0 {
				sb.WriteString(fmt.Sprintf("**Spot/preemptible projection:** $%.0f–$%.0f %s — potential monthly savings **$%.0f–$%.0f**.\n",
					est.TotalSpotMonthlyUSDLow, est.TotalSpotMonthlyUSDHigh, est.Currency,
					est.SpotSavingsMonthlyUSDLow, est.SpotSavingsMonthlyUSDHigh))
			}
			sb.WriteString(fmt.Sprintf("_Assumptions: %d hours/month. %s_\n",
				est.AssumedHoursPerMonth, est.Disclaimer))
			if est.SpotDisclaimer != "" {
				sb.WriteString(fmt.Sprintf("_Spot assumptions: %s_\n", est.SpotDisclaimer))
			}
		}
		// Wave 11: rightsizing suggestions sit alongside the cost
		// summary so the auditor reading § 2(c) sees both the current
		// projection and the cheaper alternative in one place.
		if opts.IncludeCostEstimates && len(bom.FinOpsRecommendations) > 0 {
			sb.WriteString("\n**Rightsizing recommendations:**\n")
			for _, rec := range bom.FinOpsRecommendations {
				sb.WriteString(fmt.Sprintf(
					"- **%s** (%s family `%s`) → consider %s family `%s` (%s). "+
						"Estimated savings **$%.0f–$%.0f /month**. _%s_\n",
					rec.Resource, rec.CurrentCloud, rec.CurrentFamily,
					rec.CurrentCloud, rec.RecommendedFamily, rec.RecommendedAccelerator,
					rec.EstimatedSavingsLow, rec.EstimatedSavingsHigh,
					rec.Rationale,
				))
			}
		}
		sb.WriteString("\n")
	}

	// 2(d) Container Image Provenance (Wave 10) — only renders when
	// the CLI was invoked with --image / --image-tar. The list lets
	// auditors confirm which images contributed findings; per-finding
	// Location strings (image#layerN:path) tie individual entries in
	// 2(a) back to the layer they came from.
	if len(bom.ScannedImages) > 0 {
		sb.WriteString("### 2(d) Container Images Inspected (Daemonless Layer Scan)\n")
		for _, img := range bom.ScannedImages {
			digest := img.Digest
			if digest == "" {
				digest = "(unknown digest)"
			}
			sb.WriteString(fmt.Sprintf(
				"- **%s** [%s] — %d layer(s), %d AI finding(s); digest `%s`\n",
				img.Reference, img.Source, img.Layers, img.FindingCount, digest,
			))
		}
		sb.WriteString("\n")
	}

	// Section 3: Risk Management
	sb.WriteString("## 3. Continuous Risk Management (Article 9 & Annex IV, Section 4)\n")
	sb.WriteString(fmt.Sprintf("**Current Automated Posture:** %s\n\n", bom.Compliance))

	// 3(a) Auto-generated risk register (Wave 6) — every detected dep
	// cross-referenced against the curated catalog of OWASP ML Top 10
	// categories, MITRE ATLAS techniques, and EU AI Act articles.
	// Same data lives in proof_drills.risk_register_state (JSONB) so
	// the dashboard / API can render the register without re-parsing
	// markdown. Wave 7f: caller passes in the register so live OSV
	// vuln IDs (when enrichment ran) show up in the rendered table.
	sb.WriteString("### 3(a) Cross-Referenced Risk Register (OWASP ML Top 10 / MITRE ATLAS)\n\n")
	sb.WriteString(fmt.Sprintf(
		"**Findings:** %d total — High: %d, Medium: %d, Low: %d\n\n",
		register.Summary.Total, register.Summary.High,
		register.Summary.Medium, register.Summary.Low,
	))
	if rendered := RenderRiskRegisterMarkdown(register); rendered != "" {
		sb.WriteString(rendered)
		sb.WriteString("\n")
		// Per-finding mitigation guidance — kept below the summary table
		// because the table is what auditors scan first.
		sb.WriteString("**Recommended mitigations:**\n\n")
		for _, f := range register.Findings {
			sb.WriteString(fmt.Sprintf("- **%s**: %s\n", f.Component, f.Mitigation))
		}
		sb.WriteString("\n")

		// Live advisory detail (Wave 16). The table above answers "is
		// there a problem"; this answers "what do I change", which is
		// the question the engineer reading it actually has. Omitted
		// entirely when enrichment didn't run or returned nothing, so
		// an empty heading never implies a clean result.
		if advisories := RenderLiveAdvisoriesMarkdown(register); advisories != "" {
			sb.WriteString("**Live advisories (OSV.dev, at scan time):**\n\n")
			sb.WriteString(advisories)
			sb.WriteString("\nSeverity labels and CVSS vectors are quoted as published by the ")
			sb.WriteString("advisory database; AIcap does not recompute them. Advisories reflect ")
			sb.WriteString("the state of OSV.dev at the moment of this scan.\n\n")
		}
	} else {
		sb.WriteString("No catalogued AI risks detected. (Catalog scope is intentionally MVP — see pkg/compliance/vulns.json.)\n\n")
	}

	// Exposed-secret findings stay separate because they're an immediate
	// remediation requirement, not an Article 9 risk-management item.
	secretFindings := []types.AIDependency{}
	for _, dep := range bom.Dependencies {
		if dep.Name == "Exposed Secret" {
			secretFindings = append(secretFindings, dep)
		}
	}
	if len(secretFindings) > 0 {
		sb.WriteString(fmt.Sprintf("⚠️ **CRITICAL:** %d exposed secret(s) detected in source code. Immediate remediation required.\n\n", len(secretFindings)))
	}

	// 3(b): Policy compliance
	sb.WriteString("### 3(b) Policy-as-Code Compliance\n")
	if len(bom.PolicyViolations) == 0 {
		// "No violations" and "no policy to violate" are different facts
		// and must not share a tick. The original line said "No policy
		// violations detected (or no .aicap.yml configured)" with a
		// checked box, so a project with no governance policy at all
		// read as having passed one.
		if bom.Policy == nil {
			sb.WriteString("- [ ] No `.aicap.yml` policy file was found, so no policy was evaluated. ")
			sb.WriteString("This is not a pass: define a policy to enforce model governance ")
			sb.WriteString("(blocked models, risk thresholds, licence restrictions) in CI.\n\n")
		} else {
			sb.WriteString("- [x] Policy evaluated against `.aicap.yml`; no violations detected.\n\n")
		}
	} else {
		blockers := 0
		warnings := 0
		for _, v := range bom.PolicyViolations {
			if v.Severity == "Blocker" {
				blockers++
			} else {
				warnings++
			}
		}
		sb.WriteString(fmt.Sprintf("- **Blockers:** %d\n", blockers))
		sb.WriteString(fmt.Sprintf("- **Warnings:** %d\n\n", warnings))
		for _, v := range bom.PolicyViolations {
			icon := "⚠️"
			if v.Severity == "Blocker" {
				icon = "🚫"
			}
			sb.WriteString(fmt.Sprintf("- %s [%s] %s (%s)\n", icon, v.Rule, v.Description, v.Location))
		}
		sb.WriteString("\n")
	}

	// CI/CD controls
	sb.WriteString("### 3(c) Automated CI/CD Pipeline Controls\n")
	if bom.Compliance == "Passed" {
		sb.WriteString("- [x] High-risk dependency constraints validated.\n")
	} else {
		sb.WriteString("- [ ] **BLOCKER:** High-risk AI dependencies detected without explicit mitigation.\n")
	}
	// 3(c) prompt-injection mitigation — Wave 7a auto-populates from
	// detected guardrail libraries (lakera, rebuff, nemoguardrails, …).
	// If none were found we keep the manual-input prompt; pretending we
	// have a defence we can't see is exactly the kind of false-positive
	// the original analysis warned against.
	if defs := bom.Governance.PromptInjectionDefenses; len(defs) > 0 {
		sb.WriteString(fmt.Sprintf("- [x] Prompt-injection defences detected: %s\n", joinEvidence(defs)))
		for _, s := range defs {
			sb.WriteString(fmt.Sprintf("  - %s _(source: %s, location: %s)_\n", s.Description, s.Source, s.Location))
		}
		sb.WriteString("\n")
	} else {
		sb.WriteString("- [ ] `[REQUIRES MANUAL INPUT: Detail prompt injection mitigation strategy]`\n\n")
	}

	// Section 4: Human Oversight & Data Governance.
	// Wave 7a fills in HITL, Training Data, and Bias Monitoring from
	// scanner signals when available. Each subsection falls back to
	// the original `[REQUIRES MANUAL INPUT]` placeholder when no
	// signal was detected — auditors get evidence-or-prompt, never
	// silent omission.
	sb.WriteString("## 4. Human Oversight & Data Governance (Annex IV, Section 3)\n")
	renderGovernanceSection(&sb, "Human-in-the-loop (HITL) Controls", bom.Governance.HITL)
	renderGovernanceSection(&sb, "Training Data Provenance", bom.Governance.TrainingData)
	renderGovernanceSection(&sb, "Bias Monitoring", bom.Governance.BiasMonitoring)
	sb.WriteString("\n")

	// EU AI Act Article 5 review (Wave 20). Placed immediately before the
	// provenance section so it is the last substantive thing a reader
	// encounters — Article 5 is already in force and carries the Act's
	// heaviest penalties, so it should not be buried mid-document.
	// Omitted entirely when nothing matched, because printing "none
	// detected" would read as a clearance this scan cannot give.
	if art5 := RenderArticle5Markdown(bom.ProhibitedPractices); art5 != "" {
		sb.WriteString(art5)
	}

	// Article 50 transparency duties follow Article 5: same "already
	// dated" framing, and 50(3) is the floor that remains for emotion
	// and biometric systems once the Article 5 analysis clears them.
	if art50 := RenderArticle50Markdown(bom.TransparencyObligations); art50 != "" {
		sb.WriteString(art50)
	}

	// Section 5: Proof Drill / provenance.
	//
	// The wording branches on attestation because the two artefacts make
	// materially different claims, and a reader must not have to guess
	// which one they are holding.
	if att.Anchored {
		sb.WriteString("## 5. Immutable Compliance Proof (AIcap Proof Drill)\n")
		sb.WriteString("This document was generated by **AIcap** — an automated AI compliance scanner.\n")
		sb.WriteString("The AI-BOM, this Annex IV template, and the commit SHA have been cryptographically\n")
		sb.WriteString("hashed together to create an immutable audit trail.\n\n")
		sb.WriteString(fmt.Sprintf("- **Commit SHA:** `%s`\n", bom.CommitSha))
		sb.WriteString(fmt.Sprintf("- **Scan Timestamp:** %s\n", time.Now().UTC().Format(time.RFC3339)))
		if att.LedgerHash != "" {
			sb.WriteString(fmt.Sprintf("- **Ledger hash:** `%s`\n", att.LedgerHash))
		}
		if att.VerifyURL != "" {
			sb.WriteString(fmt.Sprintf("- **Independently verifiable at:** %s\n", att.VerifyURL))
		} else {
			sb.WriteString("- **Cryptographic proof hash available in the AIcap Cloud dashboard.**\n")
		}
		return sb.String()
	}

	sb.WriteString("## 5. Provenance (Unattested — Local Generation)\n")
	sb.WriteString("This document was generated by **AIcap** — an automated AI compliance scanner —\n")
	sb.WriteString("running locally in your own environment.\n\n")
	sb.WriteString(fmt.Sprintf("- **Commit SHA:** `%s`\n", bom.CommitSha))
	sb.WriteString(fmt.Sprintf("- **Generated:** %s\n", time.Now().UTC().Format(time.RFC3339)))
	sb.WriteString("\n")
	sb.WriteString("> ⚠️ **This document is not anchored to an audit ledger.**\n")
	sb.WriteString(">\n")
	sb.WriteString("> It cannot be independently verified. It was produced on the same machine that\n")
	sb.WriteString("> holds the code it describes, and can be regenerated, edited, or back-dated by\n")
	sb.WriteString("> anyone with access to that machine — so its contents are not evidence that the\n")
	sb.WriteString("> described state existed at the stated commit or time.\n")
	sb.WriteString(">\n")
	sb.WriteString("> The content above is unaffected — the analysis is the same either way. What is\n")
	sb.WriteString("> missing is provenance: a tamper-evident record, held outside your control, that\n")
	sb.WriteString("> an auditor can check without relying on your cooperation.\n")
	sb.WriteString(">\n")
	sb.WriteString("> To anchor this document, set `AICAP_API_KEY` in your pipeline. Each scan is then\n")
	sb.WriteString("> hash-chained to its predecessor, so editing, reordering, or deleting any\n")
	sb.WriteString("> historical entry breaks verification at every later link — and the record can be\n")
	sb.WriteString("> shared with an auditor by link, without giving them an account. See aicap.dev.\n")

	return sb.String()
}

// renderGovernanceSection writes one Annex IV § 4 sub-bullet, either
// with detected evidence or the `[REQUIRES MANUAL INPUT]` placeholder.
// Pulled out of GenerateAnnexIVMarkdown so the three sub-sections (HITL,
// Training Data, Bias Monitoring) share identical formatting — auditors
// reading three different shapes is a needless cognitive load.
func renderGovernanceSection(sb *strings.Builder, title string, signals []types.GovernanceSignal) {
	if len(signals) == 0 {
		sb.WriteString(fmt.Sprintf("- **%s:** `[REQUIRES MANUAL INPUT]`\n", title))
		return
	}
	sb.WriteString(fmt.Sprintf("- **%s:** %d signal(s) detected — see evidence below.\n", title, len(signals)))
	for _, s := range signals {
		sb.WriteString(fmt.Sprintf("  - %s _(source: %s, location: `%s`)_\n", s.Description, s.Source, s.Location))
	}
}

// joinEvidence collapses a slice of GovernanceSignal evidence strings
// into a comma-separated list for the inline summary line at the top
// of a § 3(c) entry. Deliberately simple — no de-duping, since multiple
// detections of the same lib in different files are independently
// useful audit signals.
func joinEvidence(signals []types.GovernanceSignal) string {
	parts := make([]string, 0, len(signals))
	for _, s := range signals {
		parts = append(parts, "`"+s.Evidence+"`")
	}
	return strings.Join(parts, ", ")
}

// CycloneDX SBOM structures — minimal CycloneDX 1.5 compatible output
func LoadPolicyConfig(scanDir string) *types.PolicyConfig {
	policyPath := filepath.Join(scanDir, ".aicap.yml")
	data, err := os.ReadFile(policyPath)
	if err != nil {
		return nil // No policy file — that's okay
	}

	policy := &types.PolicyConfig{}

	// Simple YAML-like parser for our specific format (avoids yaml dependency)
	lines := strings.Split(string(data), "\n")
	var currentList *[]string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip comments and empty lines
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Handle list items
		if strings.HasPrefix(trimmed, "- ") && currentList != nil {
			item := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
			item = strings.Trim(item, "\"'")
			*currentList = append(*currentList, item)
			continue
		}

		// Handle key-value pairs
		if strings.Contains(trimmed, ":") {
			parts := strings.SplitN(trimmed, ":", 2)
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			val = strings.Trim(val, "\"'")
			currentList = nil

			switch key {
			case "allowed_models":
				currentList = &policy.AllowedModels
			case "blocked_models":
				currentList = &policy.BlockedModels
			case "allowed_licenses":
				currentList = &policy.AllowedLicenses
			case "data_inputs":
				currentList = &policy.DataInputs
			case "training_datasets":
				currentList = &policy.TrainingDatasets
			case "max_risk_level":
				policy.MaxRiskLevel = val
			case "block_on_high_risk":
				policy.BlockOnHighRisk = val == "true"
			case "require_licenses":
				policy.RequireLicenses = val == "true"
			case "purpose":
				policy.Purpose = val
			case "contact_email":
				policy.ContactEmail = val
			}
		}
	}

	return policy
}

// evaluatePolicy checks detected dependencies against the policy configuration
func EvaluatePolicy(policy *types.PolicyConfig, bom types.AIBOM) []types.PolicyViolation {
	var violations []types.PolicyViolation

	for _, dep := range bom.Dependencies {
		depNameLower := strings.ToLower(dep.Name)
		depVersionLower := strings.ToLower(dep.Version)

		// Check blocked models
		for _, blocked := range policy.BlockedModels {
			blockedLower := strings.ToLower(blocked)
			if strings.Contains(depNameLower, blockedLower) || strings.Contains(depVersionLower, blockedLower) {
				violations = append(violations, types.PolicyViolation{
					Rule:        "blocked_model",
					Severity:    "Blocker",
					Description: fmt.Sprintf("Model '%s' is explicitly blocked by .aicap.yml policy", dep.Version),
					Location:    dep.Location,
				})
			}
		}

		// Check allowed models (if allowlist is specified, anything not in it is blocked)
		if len(policy.AllowedModels) > 0 && (dep.Name == "Hardcoded Model" || strings.HasPrefix(dep.Ecosystem, "Model Weight")) {
			isAllowed := false
			for _, allowed := range policy.AllowedModels {
				allowedLower := strings.ToLower(allowed)
				if strings.Contains(depVersionLower, allowedLower) || strings.Contains(depNameLower, allowedLower) {
					isAllowed = true
					break
				}
			}
			if !isAllowed {
				violations = append(violations, types.PolicyViolation{
					Rule:        "allowed_model_violation",
					Severity:    "Blocker",
					Description: fmt.Sprintf("Model '%s' is not in the approved model allowlist defined in .aicap.yml", dep.Version),
					Location:    dep.Location,
				})
			}
		}

		// Check risk level threshold
		if policy.BlockOnHighRisk && dep.RiskLevel == "High" {
			violations = append(violations, types.PolicyViolation{
				Rule:        "high_risk_blocked",
				Severity:    "Blocker",
				Description: fmt.Sprintf("High-risk dependency '%s' blocked by policy (block_on_high_risk: true)", dep.Name),
				Location:    dep.Location,
			})
		}

		// Check license requirements
		if policy.RequireLicenses && dep.License == "" && dep.RiskLevel == "High" {
			violations = append(violations, types.PolicyViolation{
				Rule:        "missing_license",
				Severity:    "Warning",
				Description: fmt.Sprintf("High-risk dependency '%s' has no license information. Policy requires licenses for all high-risk components.", dep.Name),
				Location:    dep.Location,
			})
		}

		// Check allowed licenses
		if len(policy.AllowedLicenses) > 0 && dep.License != "" {
			isAllowed := false
			for _, allowedLic := range policy.AllowedLicenses {
				if strings.EqualFold(dep.License, allowedLic) {
					isAllowed = true
					break
				}
			}
			if !isAllowed {
				violations = append(violations, types.PolicyViolation{
					Rule:        "license_not_allowed",
					Severity:    "Warning",
					Description: fmt.Sprintf("License '%s' for '%s' is not in the approved license list", dep.License, dep.Name),
					Location:    dep.Location,
				})
			}
		}
	}

	return violations
}

// parseRequirementsTxt parses Python dependencies
func GenerateCycloneDXBOM(bom types.AIBOM) types.CycloneDXBOM {
	return GenerateCycloneDXBOMWithRegister(bom, types.RiskRegister{})
}

// GenerateCycloneDXBOMWithRegister emits the SBOM with the CycloneDX 1.5
// `vulnerabilities` array populated from the risk register.
//
// AIcap held live OSV advisories and emitted an SBOM without them, so
// every downstream consumer — Dependency-Track, GUAC, a procurement
// portal — had to rediscover vulnerabilities AIcap had already found,
// or more likely never learned about them at all. The data was in hand;
// only the serialisation was missing.
//
// An empty register produces no `vulnerabilities` key rather than an
// empty array, so "we did not look" and "we looked and found nothing"
// stay distinguishable to a reader.
func GenerateCycloneDXBOMWithRegister(bom types.AIBOM, register types.RiskRegister) types.CycloneDXBOM {
	components := []types.CycloneDXComponent{}
	// refsByComponent maps a lower-cased component name to its bom-ref
	// so advisories can point at the component they affect.
	refsByComponent := map[string]string{}

	for _, dep := range bom.Dependencies {
		ref := componentRef(dep)
		refsByComponent[strings.ToLower(dep.Name)] = ref
		comp := types.CycloneDXComponent{
			Type:    ClassifyComponentType(dep),
			BOMRef:  ref,
			Name:    dep.Name,
			Version: dep.Version,
			PURL:    GeneratePURL(dep),
			Properties: []types.CycloneDXProperty{
				{Name: "aicap:riskLevel", Value: dep.RiskLevel},
				{Name: "aicap:ecosystem", Value: dep.Ecosystem},
				{Name: "aicap:description", Value: dep.Description},
			},
		}

		if dep.Location != "" {
			comp.Properties = append(comp.Properties, types.CycloneDXProperty{
				Name: "aicap:location", Value: dep.Location,
			})
		}

		if dep.License != "" {
			lic := types.CycloneDXLicense{}
			lic.License.Name = dep.License
			comp.Licenses = []types.CycloneDXLicense{lic}
		}

		components = append(components, comp)
	}

	return types.CycloneDXBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		SerialNumber: "urn:uuid:" + fmt.Sprintf("%x", sha256.Sum256([]byte(bom.ProjectName+bom.CommitSha)))[:36],
		Version:      1,
		Metadata: types.CycloneDXMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Component: types.CycloneDXComponent{
				Type:    "application",
				Name:    bom.ProjectName,
				Version: bom.CommitSha,
			},
		},
		Components:      components,
		Vulnerabilities: cycloneDXVulnerabilities(register, refsByComponent),
	}
}

// componentRef builds a stable bom-ref for a component. The purl is used
// where one exists, since it is already a canonical identifier; findings
// with no package identity (hardcoded models, exposed secrets, weight
// files) fall back to a name+version form.
func componentRef(dep types.AIDependency) string {
	if purl := GeneratePURL(dep); purl != "" {
		return purl
	}
	ref := "aicap:" + strings.ToLower(strings.ReplaceAll(dep.Name, " ", "-"))
	if dep.Version != "" {
		ref += "@" + dep.Version
	}
	return ref
}

// cycloneDXVulnerabilities projects the risk register's live advisories
// into the CycloneDX 1.5 shape.
//
// Only advisories with a real identifier are emitted. Catalog findings
// without live vulnerability data are risk-management entries, not
// vulnerabilities: putting an OWASP category into a `vulnerabilities`
// array would make a consumer's dependency scanner report a CVE that
// does not exist. Those stay in the Annex IV risk register, where they
// belong.
func cycloneDXVulnerabilities(register types.RiskRegister, refs map[string]string) []types.CycloneDXVulnerability {
	var out []types.CycloneDXVulnerability
	for _, f := range register.Findings {
		ref := refs[strings.ToLower(f.Component)]
		for _, v := range f.LiveVulns {
			if v.ID == "" {
				continue
			}
			entry := types.CycloneDXVulnerability{
				ID:          v.ID,
				Source:      &types.CycloneDXVulnSource{Name: "OSV", URL: "https://osv.dev/vulnerability/" + v.ID},
				Description: v.Summary,
				Advisories:  []types.CycloneDXAdvisoryRef{{URL: "https://osv.dev/vulnerability/" + v.ID}},
			}
			if ref != "" {
				entry.Affects = []types.CycloneDXAffects{{Ref: ref}}
			}
			if v.Severity != "" || v.CVSSVector != "" {
				rating := types.CycloneDXRating{
					Source:   &types.CycloneDXVulnSource{Name: "OSV"},
					Severity: strings.ToLower(v.Severity),
					Vector:   v.CVSSVector,
				}
				// `method` describes how the rating was produced. It is
				// only set when a CVSS vector is actually present —
				// claiming CVSSv31 for a bare "HIGH" label would
				// misrepresent where the number came from.
				if v.CVSSVector != "" {
					rating.Method = cvssMethod(v.CVSSVector)
				}
				entry.Ratings = []types.CycloneDXRating{rating}
			}
			if v.FixedVersion != "" {
				entry.Recommendation = "Upgrade to " + v.FixedVersion + " or later."
			}
			out = append(out, entry)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// cvssMethod maps a CVSS vector prefix to the CycloneDX method enum.
func cvssMethod(vector string) string {
	switch {
	case strings.HasPrefix(vector, "CVSS:4"):
		return "CVSSv4"
	case strings.HasPrefix(vector, "CVSS:3.1"):
		return "CVSSv31"
	case strings.HasPrefix(vector, "CVSS:3"):
		return "CVSSv3"
	case strings.HasPrefix(vector, "AV:"):
		return "CVSSv2"
	default:
		return "other"
	}
}

// componentIdentity is the key that decides whether two detections are
// the same component. Used by the § 1 count, the § 2(a) grouping, and
// the § 2(b) licensing summary, so those three cannot disagree.
//
// Ecosystem is part of the identity because § 2(a) groups within an
// ecosystem heading: the same package pinned in both requirements.txt
// and pyproject.toml renders as two entries, under "Python (pip)" and
// "Python (Poetry/PEP)". A count that collapsed them would be three
// short of what the reader can count in the section below it, which is
// the mismatch this identity exists to prevent.
func componentIdentity(dep types.AIDependency) string {
	return dep.Ecosystem + "|e|" + dep.Name + "|v|" + dep.Version + "|l|" + dep.License
}

// countDistinctComponents counts components after collapsing repeated
// detections of the same one.
func countDistinctComponents(deps []types.AIDependency) int {
	seen := map[string]bool{}
	for _, dep := range deps {
		seen[componentIdentity(dep)] = true
	}
	return len(seen)
}

// depGroup is one distinct component and every place it was detected.
type depGroup struct {
	dep       types.AIDependency
	locations []string
}

// maxRenderedLocations caps how many detection sites are listed inline.
// A model identifier used in forty files should say so and name a few,
// not consume a page of the document.
const maxRenderedLocations = 5

// groupDependencies collapses repeated detections of the same component
// into one entry carrying all of its locations.
//
// Identity is (name, version, licence): two hardcoded models differ by
// the identifier they carry, which lives in Version, and two packages
// differ by version. Locations are deduplicated too — the same file can
// legitimately be walked twice when a directory scan and an image scan
// both cover it.
func groupDependencies(deps []types.AIDependency) []depGroup {
	order := []string{}
	byKey := map[string]*depGroup{}
	seenLoc := map[string]bool{}

	for _, dep := range deps {
		key := dep.Name + "\x00" + dep.Version + "\x00" + dep.License
		g, ok := byKey[key]
		if !ok {
			g = &depGroup{dep: dep}
			byKey[key] = g
			order = append(order, key)
		}
		if dep.Location != "" && !seenLoc[key+"\x00"+dep.Location] {
			seenLoc[key+"\x00"+dep.Location] = true
			g.locations = append(g.locations, dep.Location)
		}
	}

	out := make([]depGroup, 0, len(order))
	for _, key := range order {
		g := byKey[key]
		sort.Strings(g.locations)
		out = append(out, *g)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].dep.Name != out[j].dep.Name {
			return out[i].dep.Name < out[j].dep.Name
		}
		return out[i].dep.Version < out[j].dep.Version
	})
	return out
}

// formatLocations renders the "found at" suffix for a grouped entry.
func formatLocations(locations []string) string {
	if len(locations) == 0 {
		return ""
	}
	shown := locations
	suffix := ""
	if len(shown) > maxRenderedLocations {
		shown = shown[:maxRenderedLocations]
		suffix = fmt.Sprintf(" and %d more", len(locations)-maxRenderedLocations)
	}
	label := "found at"
	if len(locations) > 1 {
		label = fmt.Sprintf("%d occurrences, at", len(locations))
	}
	return fmt.Sprintf("_%s `%s`%s_", label, strings.Join(shown, "`, `"), suffix)
}

// DisplayVersion formats a version for human-facing output.
//
// The "v" prefix is only correct for something that is actually a
// version. The Version field carries other things: the model identifier
// for a "Hardcoded Model" finding, a constraint like ">=2.0" from a
// manifest, and scanner placeholders like "imported" or
// "docker-install". Prefixing those produced "vgpt-5",
// "vmodels/llama-3-8b.gguf", "v>=2.0" and "vdocker-install" in a
// document handed to auditors — small, but the kind of sloppiness that
// makes a reader wonder how carefully the rest was produced.
func DisplayVersion(v string) string {
	if v == "" {
		return "unspecified"
	}
	if v[0] >= '0' && v[0] <= '9' {
		return "v" + v
	}
	return v
}

// ClassifyComponentType maps AIcap dependency types to CycloneDX component types
func ClassifyComponentType(dep types.AIDependency) string {
	if strings.HasPrefix(dep.Ecosystem, "Model Weight") || strings.HasPrefix(dep.Ecosystem, "Container Image") {
		return "machine-learning-model"
	}
	if dep.Name == "Exposed Secret" {
		return "data"
	}
	return "library"
}

// GeneratePURL creates a Package URL for the dependency
func GeneratePURL(dep types.AIDependency) string {
	switch {
	case strings.Contains(dep.Ecosystem, "pip") || strings.Contains(dep.Ecosystem, "Poetry"):
		return fmt.Sprintf("pkg:pypi/%s@%s", dep.Name, dep.Version)
	case strings.Contains(dep.Ecosystem, "npm"):
		return fmt.Sprintf("pkg:npm/%s@%s", dep.Name, dep.Version)
	case strings.Contains(dep.Ecosystem, "Go"):
		return fmt.Sprintf("pkg:golang/%s@%s", dep.Name, dep.Version)
	case strings.Contains(dep.Ecosystem, "Dockerfile"):
		return fmt.Sprintf("pkg:docker/%s", dep.Name)
	default:
		return ""
	}
}

// parseTerraformFile analyzes .tf files for GPU instance types and cost optimization opportunities
var owaspMLRisks = map[string][]string{
	"openai":       {"ML06:2023 AI Supply Chain Attacks - External LLM API dependency creates supply chain risk"},
	"anthropic":    {"ML06:2023 AI Supply Chain Attacks - External LLM API dependency creates supply chain risk"},
	"langchain":    {"ML01:2023 Input Manipulation - LLM orchestration framework susceptible to prompt injection", "ML06:2023 AI Supply Chain Attacks - Third-party orchestration framework creates supply chain risk"},
	"torch":        {"ML04:2023 Model Theft - Local model weights may be extractable", "ML08:2023 Model Skewing - Training pipeline integrity must be verified"},
	"tensorflow":   {"ML04:2023 Model Theft - Local model weights may be extractable", "ML08:2023 Model Skewing - Training pipeline integrity must be verified"},
	"transformers": {"ML06:2023 AI Supply Chain Attacks - Pre-trained model supply chain risk", "ML02:2023 Data Poisoning - Pre-trained models may contain poisoned weights"},
	"scikit-learn": {"ML08:2023 Model Skewing - Ensure training data distributions are monitored"},
	"ollama":       {"ML04:2023 Model Theft - Local model hosting increases model exfiltration surface"},
	"chromadb":     {"ML09:2023 Output Integrity - Vector DB poisoning can corrupt RAG retrieval results"},
	"pinecone":     {"ML09:2023 Output Integrity - Vector DB poisoning can corrupt RAG retrieval results"},
}

// enrichWithOWASPRisks adds OWASP ML Top 10 risk annotations to the types.AIBOM
func EnrichWithOWASPRisks(bom *types.AIBOM) {
	for i, dep := range bom.Dependencies {
		depNameLower := strings.ToLower(dep.Name)
		if risks, ok := owaspMLRisks[depNameLower]; ok {
			// Append OWASP risks to the description
			owaspNote := " | OWASP ML: " + strings.Join(risks, "; ")
			// Only add if not already annotated
			if !strings.Contains(bom.Dependencies[i].Description, "OWASP") {
				bom.Dependencies[i].Description += owaspNote
			}
		}
	}
}
