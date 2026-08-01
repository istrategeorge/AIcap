package compliance

import (
	"context"
	"strings"
	"sync"
	"testing"

	"aicap/pkg/types"
)

// Wave 16 tests: advisory depth, query scope, and determinism.
//
// The two behaviours under test are the ones that decide whether the
// risk register is useful to the person reading it: whether a
// vulnerability can be reported at all when the static catalog has never
// heard of the component, and whether the report says what to upgrade to.

// --- Advisory depth ------------------------------------------------------

func TestOSVVuln_ToLiveVuln_CarriesFixAndSeverity(t *testing.T) {
	v := osvVuln{
		ID:               "GHSA-abcd",
		Aliases:          []string{"CVE-2025-1111"},
		Summary:          "Arbitrary code execution during model load",
		DatabaseSpecific: osvDBSpecific{Severity: "HIGH"},
		Severity:         []osvSeverity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
		Affected: []osvAffected{{
			Package: osvPackage{Name: "transformers", Ecosystem: "PyPI"},
			Ranges: []osvRange{{Type: "ECOSYSTEM", Events: []osvEvent{
				{Introduced: "0"}, {Fixed: "4.48.1"},
			}}},
		}},
	}

	got := v.toLiveVuln("transformers")

	if got.FixedVersion != "4.48.1" {
		t.Errorf("FixedVersion = %q, want 4.48.1 — the most actionable field OSV returns", got.FixedVersion)
	}
	if got.Severity != "HIGH" {
		t.Errorf("Severity = %q, want HIGH", got.Severity)
	}
	if !strings.HasPrefix(got.CVSSVector, "CVSS:3.1/") {
		t.Errorf("CVSSVector = %q, want the vector quoted verbatim, not recomputed", got.CVSSVector)
	}
	if got.Summary == "" || len(got.Aliases) != 1 {
		t.Errorf("summary/aliases dropped: %+v", got)
	}
}

func TestOSVVuln_EarliestFixFor_IgnoresSiblingPackages(t *testing.T) {
	// An advisory can list several affected packages. Reporting a
	// sibling's fix version as this component's remediation would be
	// actively wrong advice.
	v := osvVuln{
		ID: "GHSA-multi",
		Affected: []osvAffected{
			{
				Package: osvPackage{Name: "other-package", Ecosystem: "PyPI"},
				Ranges:  []osvRange{{Events: []osvEvent{{Fixed: "9.9.9"}}}},
			},
			{
				Package: osvPackage{Name: "torch", Ecosystem: "PyPI"},
				Ranges:  []osvRange{{Events: []osvEvent{{Fixed: "2.6.0"}}}},
			},
		},
	}
	if got := v.earliestFixFor("torch"); got != "2.6.0" {
		t.Errorf("earliestFixFor(torch) = %q, want 2.6.0", got)
	}
}

func TestOSVVuln_NoPublishedFix_ReportsEmpty(t *testing.T) {
	v := osvVuln{
		ID: "GHSA-nofix",
		Affected: []osvAffected{{
			Package: osvPackage{Name: "torch", Ecosystem: "PyPI"},
			Ranges:  []osvRange{{Events: []osvEvent{{Introduced: "0"}}}},
		}},
	}
	if got := v.toLiveVuln("torch").FixedVersion; got != "" {
		t.Errorf("FixedVersion = %q, want empty when no fix is published", got)
	}
}

// --- Query scope ---------------------------------------------------------

func TestIsQueryableVersion(t *testing.T) {
	// Placeholders must never reach OSV: /v1/query without a parseable
	// version returns every advisory ever filed against the package,
	// including ones fixed long before the version in use. Attributing
	// those to the project would be a fabricated compliance finding.
	for _, v := range []string{"", "unknown", "imported", "local", "docker-install",
		"docker-image", "docker-layer", "HIDDEN", "latest", "*"} {
		if isQueryableVersion(v) {
			t.Errorf("isQueryableVersion(%q) = true, want false", v)
		}
	}
	for _, v := range []string{"1.0", "2.4.0", "4.44.0", "1.40.0rc1", "0.32.0"} {
		if !isQueryableVersion(v) {
			t.Errorf("isQueryableVersion(%q) = false, want true", v)
		}
	}
}

func TestEnrichWithOSV_SkipsPlaceholderVersions(t *testing.T) {
	queried := make(chan string, 8)
	server := newMockOSV(t, func(q osvQuery) []osvVuln {
		queried <- q.Version
		return []osvVuln{{ID: "CVE-SHOULD-NOT-APPEAR"}}
	})
	t.Cleanup(server.Close)
	withOSVURL(t, server.URL)

	bom := types.AIBOM{Dependencies: []types.AIDependency{
		// Detected via `import torch` — the version is unknown.
		{Name: "torch", Version: "imported", Ecosystem: "Python (pip)"},
	}}
	register := ComputeRiskRegister(bom)
	EnrichWithOSV(context.Background(), &register, bom, NewOSVClient())

	close(queried)
	if v, ok := <-queried; ok {
		t.Errorf("OSV was queried with version %q; placeholder versions must be skipped", v)
	}
	if len(register.Findings) != 1 {
		t.Fatalf("findings = %d, want the catalog finding preserved", len(register.Findings))
	}
	if len(register.Findings[0].LiveVulns) != 0 {
		t.Error("advisories attached to a dependency whose version is unknown")
	}
}

func TestEnrichWithOSV_QueriesDepsOutsideTheCatalog(t *testing.T) {
	// The scope fix. Before Wave 16 only catalog-matched names were sent
	// to OSV, so a vulnerable dependency the 10-entry catalog had never
	// heard of was never even looked up.
	var mu sync.Mutex
	seen := map[string]bool{}
	server := newMockOSV(t, func(q osvQuery) []osvVuln {
		mu.Lock()
		seen[q.Package.Name] = true
		mu.Unlock()
		return nil
	})
	t.Cleanup(server.Close)
	withOSVURL(t, server.URL)

	bom := types.AIBOM{Dependencies: []types.AIDependency{
		{Name: "torch", Version: "2.4.0", Ecosystem: "Python (pip)"},
		{Name: "pillow", Version: "10.0.0", Ecosystem: "Python (pip)"},
		{Name: "express", Version: "4.19.0", Ecosystem: "Node.js (npm)"},
	}}
	register := ComputeRiskRegister(bom)
	EnrichWithOSV(context.Background(), &register, bom, NewOSVClient())

	mu.Lock()
	defer mu.Unlock()
	for _, want := range []string{"torch", "pillow", "express"} {
		if !seen[want] {
			t.Errorf("%q was never queried against OSV", want)
		}
	}
}

func TestEnrichWithOSV_DeduplicatesRepeatedDeps(t *testing.T) {
	// The same dependency is routinely detected in both a manifest and a
	// lockfile. That must be one OSV call, not two.
	var mu sync.Mutex
	calls := 0
	server := newMockOSV(t, func(q osvQuery) []osvVuln {
		mu.Lock()
		calls++
		mu.Unlock()
		return nil
	})
	t.Cleanup(server.Close)
	withOSVURL(t, server.URL)

	bom := types.AIBOM{Dependencies: []types.AIDependency{
		{Name: "torch", Version: "2.4.0", Ecosystem: "Python (pip)"},
		{Name: "torch", Version: "2.4.0", Ecosystem: "Python (Poetry lock)"},
	}}
	register := ComputeRiskRegister(bom)
	EnrichWithOSV(context.Background(), &register, bom, NewOSVClient())

	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Errorf("OSV called %d times for one distinct dep+version, want 1", calls)
	}
}

func TestEnrichWithOSV_OrderingIsDeterministic(t *testing.T) {
	// Workers finish in arbitrary order. An auditable document that
	// reshuffles its rows between identical runs invites exactly the
	// questions this product exists to prevent.
	server := newMockOSV(t, func(q osvQuery) []osvVuln {
		return []osvVuln{{ID: "CVE-" + q.Package.Name}}
	})
	t.Cleanup(server.Close)
	withOSVURL(t, server.URL)

	bom := types.AIBOM{Dependencies: []types.AIDependency{
		{Name: "zeta-pkg", Version: "1.0", Ecosystem: "Python (pip)"},
		{Name: "alpha-pkg", Version: "1.0", Ecosystem: "Python (pip)"},
		{Name: "mid-pkg", Version: "1.0", Ecosystem: "Python (pip)"},
	}}

	var first []string
	for run := 0; run < 5; run++ {
		register := ComputeRiskRegister(bom)
		EnrichWithOSV(context.Background(), &register, bom, NewOSVClient())
		order := []string{}
		for _, f := range register.Findings {
			order = append(order, f.Component)
		}
		if run == 0 {
			first = order
			continue
		}
		if strings.Join(order, ",") != strings.Join(first, ",") {
			t.Fatalf("finding order varied between runs: %v vs %v", first, order)
		}
	}
	if len(first) != 3 || first[0] != "alpha-pkg" {
		t.Errorf("order = %v, want alphabetical by component", first)
	}
}

// --- Severity and remediation --------------------------------------------

func TestSeverityFromVulns(t *testing.T) {
	cases := []struct {
		labels []string
		want   string
	}{
		{[]string{"HIGH"}, "High"},
		{[]string{"CRITICAL"}, "High"},
		{[]string{"MODERATE"}, "Medium"},
		{[]string{"LOW"}, "Low"},
		{[]string{"LOW", "HIGH"}, "High"},
		// Unrated advisories land on Medium: "Low" would understate an
		// unknown, "High" would inflate the summary counts an auditor
		// reads before anything else.
		{[]string{""}, "Medium"},
		{nil, "Medium"},
	}
	for _, c := range cases {
		vulns := make([]types.LiveVuln, 0, len(c.labels))
		for _, l := range c.labels {
			vulns = append(vulns, types.LiveVuln{Severity: l})
		}
		if got := severityFromVulns(vulns); got != c.want {
			t.Errorf("severityFromVulns(%v) = %q, want %q", c.labels, got, c.want)
		}
	}
}

func TestRemediationAdvice_NamesFixOrSaysThereIsNone(t *testing.T) {
	withFix := remediationAdvice([]types.LiveVuln{{FixedVersion: "4.48.1"}, {FixedVersion: "4.48.1"}})
	if !strings.Contains(withFix, "4.48.1") {
		t.Errorf("advice = %q, want the fixed version named", withFix)
	}
	if strings.Count(withFix, "4.48.1") != 1 {
		t.Errorf("advice = %q, want the duplicate fix version deduplicated", withFix)
	}

	noFix := remediationAdvice([]types.LiveVuln{{ID: "GHSA-x"}})
	if !strings.Contains(strings.ToLower(noFix), "no fixed version") {
		t.Errorf("advice = %q, want it to state plainly that no fix is published", noFix)
	}
}

// --- Rendering -----------------------------------------------------------

func TestRenderLiveAdvisoriesMarkdown_ShowsFixAndDetail(t *testing.T) {
	reg := types.RiskRegister{Findings: []types.RiskFinding{{
		Component: "transformers",
		Version:   "4.44.0",
		Source:    "catalog",
		LiveVulns: []types.LiveVuln{{
			ID:           "GHSA-abcd",
			Severity:     "HIGH",
			Summary:      "Arbitrary code execution",
			FixedVersion: "4.48.1",
			CVSSVector:   "CVSS:3.1/AV:N",
		}},
	}}}

	md := RenderLiveAdvisoriesMarkdown(reg)
	for _, want := range []string{"GHSA-abcd", "HIGH", "Arbitrary code execution", "fixed in 4.48.1", "CVSS:3.1/AV:N"} {
		if !strings.Contains(md, want) {
			t.Errorf("advisory block missing %q:\n%s", want, md)
		}
	}
}

func TestRenderLiveAdvisoriesMarkdown_StatesWhenNoFixExists(t *testing.T) {
	reg := types.RiskRegister{Findings: []types.RiskFinding{{
		Component: "torch",
		LiveVulns: []types.LiveVuln{{ID: "GHSA-nofix", Severity: "MODERATE"}},
	}}}
	md := RenderLiveAdvisoriesMarkdown(reg)
	if !strings.Contains(md, "no fixed version published") {
		t.Errorf("an unfixed advisory must say so — it is a different remediation decision:\n%s", md)
	}
}

func TestRenderLiveAdvisoriesMarkdown_EmptyWhenNoLiveData(t *testing.T) {
	reg := types.RiskRegister{Findings: []types.RiskFinding{{Component: "torch"}}}
	if got := RenderLiveAdvisoriesMarkdown(reg); got != "" {
		t.Errorf("got %q, want empty so the caller can omit the heading entirely", got)
	}
}

func TestRenderRiskRegisterMarkdown_ShowsFindingSource(t *testing.T) {
	reg := types.RiskRegister{Findings: []types.RiskFinding{
		{Component: "torch", Severity: "High", Status: "open", Source: "catalog"},
		{Component: "pillow", Severity: "High", Status: "open", Source: "osv"},
	}}
	md := RenderRiskRegisterMarkdown(reg)
	if !strings.Contains(md, "| Source |") {
		t.Errorf("table missing Source column:\n%s", md)
	}
	if !strings.Contains(md, "live advisory") || !strings.Contains(md, "catalog") {
		t.Errorf("table must distinguish curated from live-advisory findings:\n%s", md)
	}
}

func TestAnnexIV_IncludesLiveAdvisoryBlock(t *testing.T) {
	bom := types.AIBOM{
		ProjectName: "demo",
		Dependencies: []types.AIDependency{
			{Name: "transformers", Version: "4.44.0", Ecosystem: "Python (pip)", RiskLevel: "High"},
		},
	}
	register := ComputeRiskRegister(bom)
	register.Findings[0].LiveVulns = []types.LiveVuln{{
		ID: "GHSA-abcd", Severity: "HIGH", FixedVersion: "4.48.1",
	}}
	register.Findings[0].LiveVulnIDs = []string{"GHSA-abcd"}

	md := GenerateAnnexIVMarkdownWithRegister(bom, register)

	if !strings.Contains(md, "Live advisories") {
		t.Error("Annex IV omits the live advisory section")
	}
	if !strings.Contains(md, "fixed in 4.48.1") {
		t.Error("Annex IV omits the fixed version — the one field the reader can act on")
	}
	if !strings.Contains(md, "does not recompute") {
		t.Error("Annex IV should state that severities are quoted as published, not recomputed")
	}
}

func TestEnrichWithOSV_CatalogFindingKeepsCuratedMitigationAndGainsFix(t *testing.T) {
	// The curated mitigation is a considered assessment of the
	// component's risk class; the live fix is the immediate action.
	// A reader scanning the mitigation list should get both.
	server := newMockOSV(t, func(q osvQuery) []osvVuln {
		return []osvVuln{{
			ID:               "GHSA-tf",
			DatabaseSpecific: osvDBSpecific{Severity: "HIGH"},
			Affected: []osvAffected{{
				Package: osvPackage{Name: "tensorflow", Ecosystem: "PyPI"},
				Ranges:  []osvRange{{Events: []osvEvent{{Introduced: "0"}, {Fixed: "2.18.1"}}}},
			}},
		}}
	})
	t.Cleanup(server.Close)
	withOSVURL(t, server.URL)

	bom := types.AIBOM{Dependencies: []types.AIDependency{
		{Name: "tensorflow", Version: "2.15.0", Ecosystem: "Python (pip)"},
	}}
	register := ComputeRiskRegister(bom)
	curated := register.Findings[0].Mitigation
	if curated == "" {
		t.Fatal("setup: catalog entry has no mitigation")
	}

	EnrichWithOSV(context.Background(), &register, bom, NewOSVClient())

	got := register.Findings[0].Mitigation
	if !strings.Contains(got, strings.TrimRight(curated, " .")) {
		t.Errorf("curated mitigation was discarded:\n got: %s\nwant it to retain: %s", got, curated)
	}
	if !strings.Contains(got, "2.18.1") {
		t.Errorf("mitigation = %q, want the available fix version appended", got)
	}
	if register.Findings[0].Source != "catalog" {
		t.Errorf("source = %q, want catalog (the finding originated there)", register.Findings[0].Source)
	}
	// Enriching a catalog finding must not create a second row for it.
	if len(register.Findings) != 1 {
		t.Errorf("findings = %d, want 1", len(register.Findings))
	}
}

// --- Attestation ---------------------------------------------------------

func TestAnnexIV_LocalRender_DoesNotClaimAnImmutableAuditTrail(t *testing.T) {
	// The reason it is safe to emit Annex IV from the free CLI at all.
	// If this regresses, the tool ships a document asserting an audit
	// trail that does not exist — the exact overstatement the product
	// exists to prevent.
	bom := types.AIBOM{ProjectName: "demo", CommitSha: "abc123"}
	md := GenerateAnnexIVMarkdownWithAttestation(bom, ComputeRiskRegister(bom),
		types.Attestation{Anchored: false})

	if strings.Contains(md, "immutable audit trail") {
		t.Error("a locally generated document must not claim an immutable audit trail")
	}
	for _, want := range []string{
		"Unattested",
		"not anchored to an audit ledger",
		"It cannot be independently verified",
		"AICAP_API_KEY",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("unattested provenance section missing %q", want)
		}
	}
}

func TestAnnexIV_AnchoredRender_KeepsLedgerLanguage(t *testing.T) {
	bom := types.AIBOM{ProjectName: "demo", CommitSha: "abc123"}
	md := GenerateAnnexIVMarkdownWithAttestation(bom, ComputeRiskRegister(bom),
		types.Attestation{Anchored: true, LedgerHash: "deadbeef"})

	if !strings.Contains(md, "immutable audit trail") {
		t.Error("anchored render lost its ledger language")
	}
	if !strings.Contains(md, "deadbeef") {
		t.Error("anchored render omits the ledger hash it was given")
	}
	if strings.Contains(md, "Unattested") {
		t.Error("anchored render must not carry the unattested warning")
	}
}

func TestGenerateAnnexIVMarkdownWithRegister_DefaultsToAnchored(t *testing.T) {
	// /api/save-proof relies on this: its renders are persisted into the
	// ledger, so the anchored wording is correct there and must not
	// change as a side effect of the CLI work.
	bom := types.AIBOM{ProjectName: "demo"}
	md := GenerateAnnexIVMarkdownWithRegister(bom, ComputeRiskRegister(bom))
	if !strings.Contains(md, "Immutable Compliance Proof") {
		t.Error("save-proof render lost its anchored § 5")
	}
}

// --- Remediation advice quality (found against live OSV data) ------------

func TestRemediationAdvice_IgnoresGitShas(t *testing.T) {
	// OSV records a `fixed` event per affected range, and projects that
	// publish source-range advisories put a git commit SHA there. Running
	// against real data for vllm produced a mitigation listing twenty-odd
	// "versions", several of them 40-character SHAs.
	advice := remediationAdvice([]types.LiveVuln{
		{ID: "a", FixedVersion: "432117cd1f59c76d97da2eaff55a7d758301dbc7"},
		{ID: "b", FixedVersion: "0.11.0"},
	})
	if strings.Contains(advice, "432117cd") {
		t.Errorf("advice names a git SHA as an upgrade target: %q", advice)
	}
	if !strings.Contains(advice, "0.11.0") {
		t.Errorf("advice dropped the real version: %q", advice)
	}
}

func TestRemediationAdvice_NamesOneTargetNotEveryBranch(t *testing.T) {
	// A long-lived package gets advisories fixed on several release
	// branches. Enumerating all of them buries the actionable answer;
	// the highest version clears every one.
	advice := remediationAdvice([]types.LiveVuln{
		{ID: "a", FixedVersion: "0.7.0"},
		{ID: "b", FixedVersion: "0.24.0"},
		{ID: "c", FixedVersion: "0.10.1.1"},
		{ID: "d", FixedVersion: "0.9.0"},
	})
	if !strings.Contains(advice, "0.24.0") {
		t.Errorf("advice = %q, want the highest fixed version", advice)
	}
	if strings.Contains(advice, "0.7.0") || strings.Contains(advice, "0.9.0") {
		t.Errorf("advice enumerates superseded branches: %q", advice)
	}
}

func TestHighestVersion_ComparesNumerically(t *testing.T) {
	// String sort would put 0.9.0 above 0.24.0 — the classic failure.
	cases := []struct {
		in   []string
		want string
	}{
		{[]string{"0.9.0", "0.24.0"}, "0.24.0"},
		{[]string{"0.10.1.1", "0.10.1"}, "0.10.1.1"},
		{[]string{"1.2.3", "1.10.0", "1.9.9"}, "1.10.0"},
		{[]string{"2.0.0"}, "2.0.0"},
		{[]string{"4.44.0", "4.48.1"}, "4.48.1"},
	}
	for _, c := range cases {
		if got := highestVersion(c.in); got != c.want {
			t.Errorf("highestVersion(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestLooksLikeVersion(t *testing.T) {
	for _, v := range []string{"1.0", "0.24.0", "4.48.1", "2.6.0", "1.40.0rc1"} {
		if !looksLikeVersion(v) {
			t.Errorf("looksLikeVersion(%q) = false, want true", v)
		}
	}
	for _, v := range []string{
		"", "432117cd1f59c76d97da2eaff55a7d758301dbc7", "d3d6bb13fb62da3234addf65",
		"master", "v-next",
	} {
		if looksLikeVersion(v) {
			t.Errorf("looksLikeVersion(%q) = true, want false", v)
		}
	}
}

// --- CycloneDX vulnerabilities array (Wave 19) ---------------------------

func TestCycloneDX_EmitsVulnerabilitiesFromRegister(t *testing.T) {
	// AIcap held live advisories and emitted an SBOM without them, so
	// Dependency-Track and friends had to rediscover vulnerabilities it
	// had already found — or never learned about them at all.
	bom := types.AIBOM{
		ProjectName: "demo",
		Dependencies: []types.AIDependency{
			{Name: "transformers", Version: "4.44.0", Ecosystem: "Python (pip)", RiskLevel: "High"},
		},
	}
	reg := types.RiskRegister{Findings: []types.RiskFinding{{
		Component: "transformers",
		Version:   "4.44.0",
		LiveVulns: []types.LiveVuln{{
			ID:           "GHSA-abcd",
			Summary:      "Arbitrary code execution",
			Severity:     "HIGH",
			CVSSVector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			FixedVersion: "4.48.1",
		}},
	}}}

	cdx := GenerateCycloneDXBOMWithRegister(bom, reg)

	if len(cdx.Vulnerabilities) != 1 {
		t.Fatalf("Vulnerabilities = %d, want 1", len(cdx.Vulnerabilities))
	}
	v := cdx.Vulnerabilities[0]
	if v.ID != "GHSA-abcd" {
		t.Errorf("id = %q", v.ID)
	}
	if v.Recommendation == "" || !strings.Contains(v.Recommendation, "4.48.1") {
		t.Errorf("recommendation = %q, want the fixed version", v.Recommendation)
	}
	if len(v.Ratings) != 1 || v.Ratings[0].Severity != "high" {
		t.Errorf("ratings = %+v, want the published severity", v.Ratings)
	}
	if v.Ratings[0].Method != "CVSSv31" {
		t.Errorf("method = %q, want CVSSv31 from the vector prefix", v.Ratings[0].Method)
	}

	// The advisory must point at the component it affects, by the same
	// bom-ref the component carries — otherwise a consumer cannot link
	// them and the array is decoration.
	if len(v.Affects) != 1 {
		t.Fatalf("affects = %+v, want one reference", v.Affects)
	}
	var componentRef string
	for _, c := range cdx.Components {
		if c.Name == "transformers" {
			componentRef = c.BOMRef
		}
	}
	if componentRef == "" {
		t.Fatal("component has no bom-ref, so nothing can reference it")
	}
	if v.Affects[0].Ref != componentRef {
		t.Errorf("affects ref = %q, component bom-ref = %q — they must match", v.Affects[0].Ref, componentRef)
	}
}

func TestCycloneDX_NoVulnerabilitiesKeyWhenNoneFound(t *testing.T) {
	// Absent rather than empty: "we did not look" and "we looked and
	// found nothing" must stay distinguishable.
	cdx := GenerateCycloneDXBOM(types.AIBOM{ProjectName: "demo"})
	if cdx.Vulnerabilities != nil {
		t.Errorf("Vulnerabilities = %+v, want nil so the key is omitted", cdx.Vulnerabilities)
	}
}

func TestCycloneDX_CatalogFindingsAreNotEmittedAsVulnerabilities(t *testing.T) {
	// A curated OWASP mapping is a risk-management entry, not a CVE.
	// Emitting it into the vulnerabilities array would make a consumer's
	// scanner report a vulnerability that does not exist.
	bom := types.AIBOM{Dependencies: []types.AIDependency{
		{Name: "torch", Version: "2.4.0", Ecosystem: "Python (pip)", RiskLevel: "High"},
	}}
	reg := types.RiskRegister{Findings: []types.RiskFinding{{
		Component:     "torch",
		OwaspCategory: "ML04:2023 Model Theft",
		Severity:      "High",
		// No LiveVulns.
	}}}

	cdx := GenerateCycloneDXBOMWithRegister(bom, reg)
	if len(cdx.Vulnerabilities) != 0 {
		t.Errorf("catalog-only finding leaked into the vulnerabilities array: %+v", cdx.Vulnerabilities)
	}
}

func TestCycloneDX_RatingOmitsMethodWithoutAVector(t *testing.T) {
	// Claiming CVSSv31 for a bare "HIGH" label would misrepresent where
	// the rating came from.
	bom := types.AIBOM{Dependencies: []types.AIDependency{
		{Name: "torch", Version: "2.4.0", Ecosystem: "Python (pip)"},
	}}
	reg := types.RiskRegister{Findings: []types.RiskFinding{{
		Component: "torch",
		LiveVulns: []types.LiveVuln{{ID: "GHSA-x", Severity: "MODERATE"}},
	}}}

	cdx := GenerateCycloneDXBOMWithRegister(bom, reg)
	if len(cdx.Vulnerabilities) != 1 {
		t.Fatalf("want one vulnerability, got %d", len(cdx.Vulnerabilities))
	}
	if m := cdx.Vulnerabilities[0].Ratings[0].Method; m != "" {
		t.Errorf("method = %q, want empty when no CVSS vector was published", m)
	}
}

func TestCycloneDX_VulnerabilityOrderIsStable(t *testing.T) {
	bom := types.AIBOM{Dependencies: []types.AIDependency{
		{Name: "torch", Version: "2.4.0", Ecosystem: "Python (pip)"},
	}}
	reg := types.RiskRegister{Findings: []types.RiskFinding{{
		Component: "torch",
		LiveVulns: []types.LiveVuln{
			{ID: "GHSA-zzz"}, {ID: "CVE-2025-1"}, {ID: "GHSA-aaa"},
		},
	}}}

	first := GenerateCycloneDXBOMWithRegister(bom, reg)
	for i := 0; i < 5; i++ {
		got := GenerateCycloneDXBOMWithRegister(bom, reg)
		for j := range got.Vulnerabilities {
			if got.Vulnerabilities[j].ID != first.Vulnerabilities[j].ID {
				t.Fatal("vulnerability order varied between runs")
			}
		}
	}
	if first.Vulnerabilities[0].ID != "CVE-2025-1" {
		t.Errorf("order = %s…, want sorted by id", first.Vulnerabilities[0].ID)
	}
}

// --- Report-quality fixes found by reading an actual generated PDF ------

func TestDisplayVersion_OnlyPrefixesRealVersions(t *testing.T) {
	// The Version field carries more than versions: model identifiers for
	// "Hardcoded Model" findings, manifest constraints, and scanner
	// placeholders. A blanket "v" prefix produced "vgpt-5",
	// "vmodels/llama-3-8b.gguf", "v>=2.0" and "vdocker-install" in a
	// document handed to auditors.
	cases := map[string]string{
		"1.12.0":                 "v1.12.0",
		"0.24.2":                 "v0.24.2",
		"gpt-5":                  "gpt-5",
		"claude-opus-4-5":        "claude-opus-4-5",
		"models/llama-3-8b.gguf": "models/llama-3-8b.gguf",
		">=2.0":                  ">=2.0",
		"docker-install":         "docker-install",
		"imported":               "imported",
		"":                       "unspecified",
	}
	for in, want := range cases {
		if got := DisplayVersion(in); got != want {
			t.Errorf("DisplayVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestComputeRiskRegister_DeduplicatesSameComponentAndVersion(t *testing.T) {
	// The same package detected in a manifest and a lockfile is one entry
	// in the register, not two. A real report listed `openai v1.12.0`
	// twice with identical content.
	bom := types.AIBOM{Dependencies: []types.AIDependency{
		{Name: "openai", Version: "1.12.0", Ecosystem: "Python (pip)"},
		{Name: "openai", Version: "1.12.0", Ecosystem: "Python (Poetry lock)"},
		{Name: "openai", Version: "1.12.0", Ecosystem: "Source Code (.py import)"},
	}}

	reg := ComputeRiskRegister(bom)
	if len(reg.Findings) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(reg.Findings), reg.Findings)
	}
	// The summary counts must not double-count either — that header is
	// the first thing an auditor reads.
	if reg.Summary.Total != 1 {
		t.Errorf("summary total = %d, want 1", reg.Summary.Total)
	}
}

func TestComputeRiskRegister_KeepsDistinctVersionsSeparate(t *testing.T) {
	// Two versions of the same package in different manifests are
	// genuinely two things to assess, and must not be collapsed.
	bom := types.AIBOM{Dependencies: []types.AIDependency{
		{Name: "scikit-learn", Version: "0.24.2", Ecosystem: "Python (pip)"},
		{Name: "scikit-learn", Version: "1.4.0", Ecosystem: "Python (Poetry lock)"},
	}}

	reg := ComputeRiskRegister(bom)
	if len(reg.Findings) != 2 {
		t.Fatalf("findings = %d, want 2 (distinct versions): %+v", len(reg.Findings), reg.Findings)
	}
}

func TestEnrichWithOSV_AdvisoriesLandOnTheRightVersion(t *testing.T) {
	// The bug this pins: enrichment indexed findings by component name
	// alone, so with two versions present every advisory piled onto
	// whichever row was indexed — attributing a vulnerability to a
	// version that does not have it, inside a compliance document.
	server := newMockOSV(t, func(q osvQuery) []osvVuln {
		if q.Version == "0.24.2" {
			return []osvVuln{{ID: "GHSA-old-only"}}
		}
		return nil // 1.4.0 is clean
	})
	t.Cleanup(server.Close)
	withOSVURL(t, server.URL)

	bom := types.AIBOM{Dependencies: []types.AIDependency{
		{Name: "scikit-learn", Version: "0.24.2", Ecosystem: "Python (pip)"},
		{Name: "scikit-learn", Version: "1.4.0", Ecosystem: "Python (Poetry lock)"},
	}}
	reg := ComputeRiskRegister(bom)
	EnrichWithOSV(context.Background(), &reg, bom, NewOSVClient())

	byVersion := map[string][]string{}
	for _, f := range reg.Findings {
		byVersion[f.Version] = f.LiveVulnIDs
	}
	if len(byVersion["0.24.2"]) != 1 || byVersion["0.24.2"][0] != "GHSA-old-only" {
		t.Errorf("0.24.2 advisories = %v, want [GHSA-old-only]", byVersion["0.24.2"])
	}
	if len(byVersion["1.4.0"]) != 0 {
		t.Errorf("1.4.0 has advisories %v, but the advisory was reported against 0.24.2 only",
			byVersion["1.4.0"])
	}
}

func TestRenderRiskRegisterMarkdown_NoStrayVPrefix(t *testing.T) {
	reg := types.RiskRegister{Findings: []types.RiskFinding{
		{Component: "torch", Version: ">=2.0", Severity: "High", Status: "open"},
		{Component: "transformers", Version: "docker-install", Severity: "High", Status: "open"},
		{Component: "openai", Version: "1.12.0", Severity: "Medium", Status: "open"},
	}}
	md := RenderRiskRegisterMarkdown(reg)

	for _, bad := range []string{"v>=2.0", "vdocker-install"} {
		if strings.Contains(md, bad) {
			t.Errorf("register table contains %q", bad)
		}
	}
	if !strings.Contains(md, "v1.12.0") {
		t.Error("a real version lost its v prefix")
	}
}

func TestComputeRiskRegister_DropsPlaceholderRowWhenAVersionIsKnown(t *testing.T) {
	// `import openai` plus `openai==1.12.0` in requirements is one
	// component. The import-only row carries no version, so it can never
	// be checked against OSV — leaving it in put an empty advisory
	// column next to a row listing ten CVEs for the same library.
	bom := types.AIBOM{Dependencies: []types.AIDependency{
		{Name: "openai", Version: "imported", Ecosystem: "Source Code (.py import)"},
		{Name: "openai", Version: "1.12.0", Ecosystem: "Python (pip)"},
	}}

	reg := ComputeRiskRegister(bom)
	if len(reg.Findings) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(reg.Findings), reg.Findings)
	}
	if reg.Findings[0].Version != "1.12.0" {
		t.Errorf("kept version %q, want the concrete one", reg.Findings[0].Version)
	}
}

func TestComputeRiskRegister_KeepsPlaceholderWhenItIsAllWeHave(t *testing.T) {
	// A bare import with no manifest pin is still worth reporting — the
	// component is present, we just cannot say which version.
	bom := types.AIBOM{Dependencies: []types.AIDependency{
		{Name: "openai", Version: "imported", Ecosystem: "Source Code (.py import)"},
	}}

	reg := ComputeRiskRegister(bom)
	if len(reg.Findings) != 1 {
		t.Fatalf("findings = %d, want the import-only finding retained", len(reg.Findings))
	}
}

func TestAnnexIV_Section2a_GroupsAndLocatesDetections(t *testing.T) {
	// The question a reader asks of a repeated finding is "where?", and
	// § 2(a) used to answer by printing the same sentence N times with
	// the location omitted.
	bom := types.AIBOM{
		ProjectName: "demo",
		Dependencies: []types.AIDependency{
			{Name: "Hardcoded Model", Version: "gpt-5", Ecosystem: "Source Code (.go)",
				RiskLevel: "High", Description: "Hardcoded AI model identifier", Location: "b.go:2"},
			{Name: "Hardcoded Model", Version: "gpt-5", Ecosystem: "Source Code (.go)",
				RiskLevel: "High", Description: "Hardcoded AI model identifier", Location: "a.go:1"},
			{Name: "Hardcoded Model", Version: "gpt-5", Ecosystem: "Source Code (.go)",
				RiskLevel: "High", Description: "Hardcoded AI model identifier", Location: "a.go:1"},
		},
	}
	md := GenerateAnnexIVMarkdown(bom)

	if got := strings.Count(md, "**Hardcoded Model**"); got != 1 {
		t.Errorf("component rendered %d times, want 1 grouped entry", got)
	}
	if !strings.Contains(md, "2 occurrences") {
		t.Error("occurrence count missing — duplicate locations should collapse to two distinct sites")
	}
	for _, loc := range []string{"a.go:1", "b.go:2"} {
		if !strings.Contains(md, loc) {
			t.Errorf("location %q not rendered; without it duplicate findings are indistinguishable", loc)
		}
	}
	if strings.Contains(md, "(vgpt-5)") {
		t.Error("model identifier rendered with a stray v prefix")
	}
}

func TestAnnexIV_IsDeterministicAcrossRuns(t *testing.T) {
	// § 2(a) grouped by ranging a map and § 2(b) listed licences the
	// same way, so two scans of an unchanged repo produced documents
	// that differed only by section order.
	bom := types.AIBOM{
		ProjectName: "demo",
		Dependencies: []types.AIDependency{
			{Name: "openai", Version: "1.0", Ecosystem: "Python (pip)", RiskLevel: "High", License: "MIT"},
			{Name: "torch", Version: "2.0", Ecosystem: "Python (Poetry lock)", RiskLevel: "High", License: "apache-2.0"},
			{Name: "ai", Version: "4.0", Ecosystem: "Node.js (npm)", RiskLevel: "High", License: "MIT"},
			{Name: "Hardcoded Model", Version: "gpt-5", Ecosystem: "Source Code (.go)", RiskLevel: "High"},
		},
	}

	// Strip the generation timestamp, which legitimately differs.
	normalise := func(s string) string {
		out := []string{}
		for _, line := range strings.Split(s, "\n") {
			if strings.HasPrefix(line, "*Generated:") || strings.Contains(line, "Scan Timestamp") {
				continue
			}
			out = append(out, line)
		}
		return strings.Join(out, "\n")
	}

	first := normalise(GenerateAnnexIVMarkdown(bom))
	for i := 0; i < 15; i++ {
		if got := normalise(GenerateAnnexIVMarkdown(bom)); got != first {
			t.Fatal("Annex IV markdown varies between identical runs")
		}
	}
}

func TestAnnexIV_Section3b_NoPolicyIsNotAPass(t *testing.T) {
	// "No violations detected" and "there was no policy to violate" are
	// different facts. The section used to render both as one ticked
	// box, so a project with no governance policy at all read as having
	// passed one — in the document an auditor uses to judge exactly
	// that.
	noPolicy := GenerateAnnexIVMarkdown(types.AIBOM{ProjectName: "demo"})
	if strings.Contains(noPolicy, "- [x] No policy violations") {
		t.Error("a project with no .aicap.yml renders as a passed policy check")
	}
	if !strings.Contains(noPolicy, "no policy was evaluated") {
		t.Error("the absence of a policy file must be stated plainly")
	}
	if !strings.Contains(noPolicy, "not a pass") {
		t.Error("the section must say that an unevaluated policy is not a pass")
	}

	withPolicy := GenerateAnnexIVMarkdown(types.AIBOM{
		ProjectName: "demo",
		Policy:      &types.PolicyConfig{Purpose: "test"},
	})
	if !strings.Contains(withPolicy, "- [x] Policy evaluated") {
		t.Error("a policy that was evaluated cleanly should tick the box")
	}
}
