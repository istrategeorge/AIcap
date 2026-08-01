package finops

import (
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"aicap/pkg/types"
)

// nearlyEqual is the float-safe comparator the cost tests use because
// 32.77 * 730 in Go isn't bit-identical to what `32.77 * 730.0` reads
// as on the call site (last-bit rounding). 0.01 tolerance is way
// inside what auditors would care about ($0.01 noise on a $24k figure).
func nearlyEqual(a, b float64) bool { return math.Abs(a-b) < 0.01 }

// LookupGPUCost contract: returns a populated FinOpsCost when the
// content contains a known instance-family prefix; nil otherwise.
// Hourly→monthly conversion uses AssumedHoursPerMonth (730 by default).

func TestLookupGPUCost_AWS_p4d(t *testing.T) {
	got := LookupGPUCost(`resource "aws_instance" "trainer" { instance_type = "p4d.24xlarge" }`)
	if got == nil {
		t.Fatal("LookupGPUCost = nil, want non-nil match for p4d")
	}
	if got.Cloud != "AWS" {
		t.Errorf("Cloud = %q, want AWS", got.Cloud)
	}
	if got.InstanceFamily != "p4d." {
		t.Errorf("InstanceFamily = %q, want p4d.", got.InstanceFamily)
	}
	// Catalog point estimate for p4d.24xlarge is $32.77/hr — the
	// monthly figure should be 32.77 * 730 = 23,922.10.
	wantMonthly := 32.77 * 730.0
	if !nearlyEqual(got.MonthlyUSDLow, wantMonthly) {
		t.Errorf("MonthlyUSDLow = %.2f, want %.2f", got.MonthlyUSDLow, wantMonthly)
	}
	if !nearlyEqual(got.MonthlyUSDHigh, wantMonthly) {
		t.Errorf("MonthlyUSDHigh = %.2f, want %.2f", got.MonthlyUSDHigh, wantMonthly)
	}
}

func TestLookupGPUCost_AWS_g5_Range(t *testing.T) {
	// g5 covers g5.xlarge ($1.01) through g5.48xlarge ($16.29) — must
	// surface as a range, not a point estimate.
	got := LookupGPUCost(`instance_type = "g5.2xlarge"`)
	if got == nil {
		t.Fatal("nil for g5")
	}
	if got.HourlyUSDLow == got.HourlyUSDHigh {
		t.Errorf("g5 should be a range, got point %v", got.HourlyUSDLow)
	}
}

func TestLookupGPUCost_GCP_a3_highgpu(t *testing.T) {
	got := LookupGPUCost("machine_type = a3-highgpu-8g")
	if got == nil {
		t.Fatal("nil for a3-highgpu")
	}
	if got.Cloud != "GCP" {
		t.Errorf("Cloud = %q, want GCP", got.Cloud)
	}
}

func TestLookupGPUCost_Azure_StandardND(t *testing.T) {
	// Azure prefixes are lower-cased in the catalog; case-insensitive
	// match must still fire on a real Terraform `Standard_ND96asr_v4`.
	got := LookupGPUCost(strings.ToLower(`vm_size = "Standard_ND96asr_v4"`))
	if got == nil {
		t.Fatal("nil for Standard_ND")
	}
	if got.Cloud != "Azure" {
		t.Errorf("Cloud = %q, want Azure", got.Cloud)
	}
}

func TestLookupGPUCost_NoMatch(t *testing.T) {
	if got := LookupGPUCost("instance_type = t3.micro"); got != nil {
		t.Errorf("non-nil for unrelated instance type: %#v", got)
	}
}

func TestAssumedHoursPerMonth_DefaultsTo730(t *testing.T) {
	if AssumedHoursPerMonth() != 730 {
		t.Errorf("AssumedHoursPerMonth = %d, want 730", AssumedHoursPerMonth())
	}
}

// EstimateBOMCost contract: aggregates monthly low/high across costed
// findings; counts uncosted findings separately so auditors know the
// headline figure is missing detections.

func TestEstimateBOMCost_AggregatesMonthly(t *testing.T) {
	bom := types.AIBOM{FinOps: []types.FinOpsFinding{
		{Resource: "tf1", EstimatedCost: &types.FinOpsCost{MonthlyUSDLow: 100, MonthlyUSDHigh: 200}},
		{Resource: "tf2", EstimatedCost: &types.FinOpsCost{MonthlyUSDLow: 50, MonthlyUSDHigh: 50}},
		{Resource: "k8s-no-instance"}, // EstimatedCost == nil
	}}
	est := EstimateBOMCost(bom)
	if est == nil {
		t.Fatal("EstimateBOMCost = nil")
	}
	if est.TotalMonthlyUSDLow != 150 {
		t.Errorf("Low = %v, want 150", est.TotalMonthlyUSDLow)
	}
	if est.TotalMonthlyUSDHigh != 250 {
		t.Errorf("High = %v, want 250", est.TotalMonthlyUSDHigh)
	}
	if est.CostedFindings != 2 || est.UncostedFindings != 1 {
		t.Errorf("Costed/Uncosted = %d/%d, want 2/1", est.CostedFindings, est.UncostedFindings)
	}
	if est.Currency != "USD" {
		t.Errorf("Currency = %q, want USD", est.Currency)
	}
}

// Wave 11: LookupGPUCost populates spot fields when the catalog has a
// multiplier for the matched cloud. Multiplier = 0.30 means the spot
// figure is 30% of on-demand (i.e. 70% savings).
func TestLookupGPUCost_PopulatesSpotFields(t *testing.T) {
	got := LookupGPUCost(`instance_type = "p4d.24xlarge"`)
	if got == nil {
		t.Fatal("nil for p4d")
	}
	if got.SpotMultiplier <= 0 || got.SpotMultiplier >= 1 {
		t.Errorf("SpotMultiplier = %v, want (0,1)", got.SpotMultiplier)
	}
	wantSpot := got.MonthlyUSDLow * got.SpotMultiplier
	if !nearlyEqual(got.SpotMonthlyUSDLow, wantSpot) {
		t.Errorf("SpotMonthlyUSDLow = %.2f, want %.2f", got.SpotMonthlyUSDLow, wantSpot)
	}
	if got.SpotMonthlyUSDLow >= got.MonthlyUSDLow {
		t.Errorf("spot (%v) should be cheaper than on-demand (%v)", got.SpotMonthlyUSDLow, got.MonthlyUSDLow)
	}
}

// Wave 11: EstimateBOMCost aggregates per-finding spot fields into
// TotalSpotMonthlyUSD* and derives SpotSavingsMonthlyUSD* from the
// difference. When no finding carries spot data the summary leaves the
// spot fields at zero so the Annex IV renderer skips the spot line.
func TestEstimateBOMCost_AggregatesSpot(t *testing.T) {
	bom := types.AIBOM{FinOps: []types.FinOpsFinding{
		{Resource: "tf1", EstimatedCost: &types.FinOpsCost{
			MonthlyUSDLow: 100, MonthlyUSDHigh: 200,
			SpotMultiplier: 0.30, SpotMonthlyUSDLow: 30, SpotMonthlyUSDHigh: 60,
		}},
		{Resource: "tf2", EstimatedCost: &types.FinOpsCost{
			MonthlyUSDLow: 50, MonthlyUSDHigh: 50,
			SpotMultiplier: 0.30, SpotMonthlyUSDLow: 15, SpotMonthlyUSDHigh: 15,
		}},
	}}
	est := EstimateBOMCost(bom)
	if est.TotalSpotMonthlyUSDLow != 45 || est.TotalSpotMonthlyUSDHigh != 75 {
		t.Errorf("spot totals = %v/%v, want 45/75", est.TotalSpotMonthlyUSDLow, est.TotalSpotMonthlyUSDHigh)
	}
	if est.SpotSavingsMonthlyUSDLow != 105 || est.SpotSavingsMonthlyUSDHigh != 175 {
		t.Errorf("savings = %v/%v, want 105/175",
			est.SpotSavingsMonthlyUSDLow, est.SpotSavingsMonthlyUSDHigh)
	}
	if est.SpotDisclaimer == "" {
		t.Error("SpotDisclaimer should be populated when spot data is present")
	}
}

func TestEstimateBOMCost_NoSpotData_SkipsSpotFields(t *testing.T) {
	bom := types.AIBOM{FinOps: []types.FinOpsFinding{
		{Resource: "tf", EstimatedCost: &types.FinOpsCost{
			MonthlyUSDLow: 100, MonthlyUSDHigh: 200,
		}},
	}}
	est := EstimateBOMCost(bom)
	if est.TotalSpotMonthlyUSDLow != 0 || est.TotalSpotMonthlyUSDHigh != 0 {
		t.Errorf("spot totals should be 0 when no finding has spot data, got %v/%v",
			est.TotalSpotMonthlyUSDLow, est.TotalSpotMonthlyUSDHigh)
	}
	if est.SpotDisclaimer != "" {
		t.Errorf("SpotDisclaimer should be empty when no spot data, got %q", est.SpotDisclaimer)
	}
}

func TestEstimateBOMCost_NoFindingsReturnsNil(t *testing.T) {
	if got := EstimateBOMCost(types.AIBOM{}); got != nil {
		t.Errorf("expected nil for BOM with no FinOps findings, got %#v", got)
	}
}

func TestEstimateBOMCost_AllUncosted_StillReturnsSummary(t *testing.T) {
	// When every finding lacks a cost (typical for k8s-only projects)
	// we still return a populated summary — it just has zero monthly
	// cost and a positive UncostedFindings count. That way the
	// disclaimer block always renders and auditors see the assumptions.
	bom := types.AIBOM{FinOps: []types.FinOpsFinding{{Resource: "deploy.yaml"}}}
	est := EstimateBOMCost(bom)
	if est == nil {
		t.Fatal("nil for all-uncosted BOM")
	}
	if est.CostedFindings != 0 {
		t.Errorf("CostedFindings = %d, want 0", est.CostedFindings)
	}
	if est.UncostedFindings != 1 {
		t.Errorf("UncostedFindings = %d, want 1", est.UncostedFindings)
	}
	if est.Disclaimer == "" {
		t.Error("Disclaimer is empty even on uncosted summary")
	}
}

// LoadCatalogFromURL tests use httptest.NewServer so no real network is needed.

func TestLoadCatalogFromURL_Empty(t *testing.T) {
	if err := LoadCatalogFromURL(""); err != nil {
		t.Errorf("empty url: expected nil error, got %v", err)
	}
	// Embedded catalog must still work.
	if got := LookupGPUCost(`instance_type = "p4d.24xlarge"`); got == nil {
		t.Error("embedded catalog broken after no-op LoadCatalogFromURL")
	}
}

func TestLoadCatalogFromURL_RemoteCatalog(t *testing.T) {
	// Restore embedded catalog when the test finishes so later tests are unaffected.
	t.Cleanup(func() { _ = parseCatalog(costsJSON) })

	const remotePrefix = "remote_test_gpu."
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Minimal catalog with a single recognisable prefix.
		w.Write([]byte(`{
			"_meta": {"assumed_hours_per_month": 730, "disclaimer": "remote test"},
			"aws": {
				"` + remotePrefix + `": {
					"hourly_usd_low": 5.00,
					"hourly_usd_high": 10.00,
					"description": "Remote test GPU"
				}
			}
		}`))
	}))
	defer srv.Close()

	if err := LoadCatalogFromURL(srv.URL); err != nil {
		t.Fatalf("LoadCatalogFromURL: %v", err)
	}

	// The remote catalog's prefix should now match.
	got := LookupGPUCost("vm_size = \"" + remotePrefix + "8xlarge\"")
	if got == nil {
		t.Fatal("LookupGPUCost returned nil after loading remote catalog")
	}
	if got.Cloud != "AWS" {
		t.Errorf("Cloud = %q, want AWS", got.Cloud)
	}
	if got.HourlyUSDLow != 5.00 {
		t.Errorf("HourlyUSDLow = %v, want 5.00", got.HourlyUSDLow)
	}

	// Embedded prefixes (e.g. p4d.) should no longer be in the catalog since
	// the remote payload replaced it entirely.
	if got2 := LookupGPUCost(`instance_type = "p4d.24xlarge"`); got2 != nil {
		t.Error("old embedded prefix still matches after remote catalog replaced it")
	}
}

func TestLoadCatalogFromURL_Unreachable(t *testing.T) {
	t.Cleanup(func() { _ = parseCatalog(costsJSON) })

	err := LoadCatalogFromURL("http://127.0.0.1:1") // nothing listening on port 1
	if err == nil {
		t.Fatal("expected error for unreachable URL, got nil")
	}

	// Embedded catalog must still work after the failed fetch.
	if got := LookupGPUCost(`instance_type = "p4d.24xlarge"`); got == nil {
		t.Error("embedded catalog broken after failed LoadCatalogFromURL")
	}
}

// TestLookupGPUCost_IsDeterministic pins that a file mentioning several
// GPU families always resolves to the same one.
//
// The lookup used to range the catalog maps directly, and Go randomises
// map iteration — so a Terraform config with both a p4d and a g5
// reported whichever the runtime happened to reach first, along with
// its cost figures. That made the generated Annex IV differ between
// runs, and since the ledger hashes the BOM, it made two scans of an
// unchanged tree produce different chain hashes.
func TestLookupGPUCost_IsDeterministic(t *testing.T) {
	content := `resource "aws_instance" "a" { instance_type = "p4d.24xlarge" }
resource "aws_instance" "b" { instance_type = "g5.xlarge" }
resource "aws_instance" "c" { instance_type = "g4dn.xlarge" }`

	first := LookupGPUCost(content)
	if first == nil {
		t.Fatal("no cost matched a content block naming three known families")
	}
	for i := 0; i < 25; i++ {
		got := LookupGPUCost(content)
		if got == nil || got.InstanceFamily != first.InstanceFamily || got.Cloud != first.Cloud {
			t.Fatalf("lookup varied between calls: %+v vs %+v", first, got)
		}
	}
}

func TestLookupGPUCost_LongestPrefixWins(t *testing.T) {
	// The catalog holds overlapping keys (p4d/p4de, g5/g5g). The more
	// specific match is the better answer, and picking by length is
	// stable where map order is not.
	if got := LookupGPUCost(`instance_type = "p4de.24xlarge"`); got == nil {
		t.Fatal("no match for p4de")
	} else if got.InstanceFamily != "p4de." && got.InstanceFamily != "p4de" {
		t.Errorf("InstanceFamily = %q, want the more specific p4de entry", got.InstanceFamily)
	}
}
