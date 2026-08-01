// Package finops attaches cost estimates to GPU-bearing FinOps
// findings. Wave 7b lifted the per-instance-family hourly-rate
// strings out of pkg/scanner's inline maps and into a structured,
// embedded catalog (gpu_costs.json) so:
//
//   - The same catalog can be reused across multiple detection sites
//     (Terraform, Helm values, k8s manifests with node-affinity hints).
//   - Tests can assert on specific instance families without piggybacking
//     on regex internals in scanner.go.
//   - A future wave can swap the catalog source for a live cloud-pricing
//     API without touching either the scanner or the Annex IV renderer.
//
// The contract is intentionally narrow: LookupGPUCost takes the lower-cased
// content of an IaC file and returns the first cloud / family it
// recognises. If multiple families appear in one file we just take the
// first one detected — costing each one separately would require a real
// HCL/YAML parse, which is out of scope for the curated MVP.

package finops

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"aicap/pkg/types"
)

//go:embed gpu_costs.json
var costsJSON []byte

// catalogEntry mirrors one entry in gpu_costs.json. Private so callers
// always go through LookupGPUCost / EstimateBOMCost and get a public
// types.FinOpsCost back.
type catalogEntry struct {
	HourlyUSDLow  float64 `json:"hourly_usd_low"`
	HourlyUSDHigh float64 `json:"hourly_usd_high"`
	Description   string  `json:"description"`
}

// catalogMeta is the curated assumptions block at the top of the catalog.
// Surfaced into the FinOpsCostSummary disclaimer so auditors see exactly
// what we baked in.
type catalogMeta struct {
	AssumedHoursPerMonth int                `json:"assumed_hours_per_month"`
	Disclaimer           string             `json:"disclaimer"`
	SpotMultipliers      map[string]float64 `json:"spot_multipliers"`
	SpotDisclaimer       string             `json:"spot_disclaimer"`
}

// catalog is loaded once at process start.
//
//	catalog[cloud][prefix] -> entry
//
// Cloud key is lower-case ("aws", "azure", "gcp") for case-insensitive
// matching against IaC content (which we also lower-case before lookup).
var (
	catalog = map[string]map[string]catalogEntry{}
	meta    catalogMeta
)

func init() {
	// Fail-soft: leave catalog empty on parse error so LookupGPUCost
	// returns nil rather than crashing the server at boot.
	_ = parseCatalog(costsJSON)
}

// parseCatalog replaces the package-level catalog and meta from raw JSON.
// Shared by init (embedded file) and LoadCatalogFromURL (remote fetch).
func parseCatalog(data []byte) error {
	raw := map[string]json.RawMessage{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("parse gpu costs catalog: %w", err)
	}
	newMeta := catalogMeta{}
	if metaRaw, ok := raw["_meta"]; ok {
		_ = json.Unmarshal(metaRaw, &newMeta)
	}
	newCatalog := map[string]map[string]catalogEntry{}
	for cloud, body := range raw {
		if strings.HasPrefix(cloud, "_") {
			continue
		}
		entries := map[string]catalogEntry{}
		if err := json.Unmarshal(body, &entries); err != nil {
			continue
		}
		newCatalog[strings.ToLower(cloud)] = entries
	}
	catalog = newCatalog
	meta = newMeta
	return nil
}

// LoadCatalogFromURL fetches a gpu_costs.json-format catalog from url and
// replaces the embedded catalog on success. On any failure (unreachable host,
// non-200, parse error) it returns an error and leaves the embedded catalog
// intact so FinOps cost estimates degrade gracefully rather than disappear.
// A blank url is a no-op. Intended to be called once at server startup.
func LoadCatalogFromURL(url string) error {
	if url == "" {
		return nil
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url) //nolint:noctx
	if err != nil {
		return fmt.Errorf("fetch gpu costs catalog: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch gpu costs catalog: status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read gpu costs catalog: %w", err)
	}
	return parseCatalog(data)
}

// AssumedHoursPerMonth returns the constant we multiply hourly rates
// by when computing monthly figures. Exported so the Annex IV builder
// can render the assumption inline.
func AssumedHoursPerMonth() int {
	if meta.AssumedHoursPerMonth == 0 {
		return 730
	}
	return meta.AssumedHoursPerMonth
}

// Disclaimer returns the catalog's curated assumption-disclaimer text,
// rendered verbatim into Annex IV § 2(c).
func Disclaimer() string {
	if meta.Disclaimer == "" {
		return "Estimates assume 730 hours/month at on-demand list pricing — actual cost depends on instance size, region, spot/savings-plan discounts, and runtime hours."
	}
	return meta.Disclaimer
}

// SpotDisclaimer returns the catalog's curated spot/preemptible
// disclaimer, rendered alongside the spot-savings line in Annex IV.
func SpotDisclaimer() string {
	if meta.SpotDisclaimer == "" {
		return "Spot savings assume the workload tolerates preemption."
	}
	return meta.SpotDisclaimer
}

// SpotMultiplier returns the catalog's spot/preemptible multiplier for
// `cloud` (lower-case "aws"|"azure"|"gcp"). A return of 0 means the
// catalog has no entry, in which case LookupGPUCost will leave the
// spot fields unset (zero) and the Annex IV renderer omits the spot
// line entirely.
func SpotMultiplier(cloud string) float64 {
	if meta.SpotMultipliers == nil {
		return 0
	}
	return meta.SpotMultipliers[strings.ToLower(cloud)]
}

// LookupGPUCost scans `content` for known GPU-instance-family prefixes
// and returns the cost shape for the first one it finds. `content` is
// expected to be lower-cased by the caller (Terraform / Helm parsers
// already do this).
//
// Returns nil if no family matches — that's the legitimate "we detected
// a GPU but don't know the instance type" case (typical for k8s
// nvidia.com/gpu requests with no node-affinity to an instance class).
func LookupGPUCost(content string) *types.FinOpsCost {
	// Iterated in sorted order, and the longest matching prefix wins.
	//
	// Ranging the catalog maps directly meant a file mentioning two GPU
	// families got a randomly chosen one — so the same Terraform config
	// reported a p4d on one run and a g5 on the next, with the cost
	// figures to match. Nondeterminism anywhere in the scan also
	// propagates into the ledger hash, which is computed over the BOM.
	//
	// Longest-prefix wins because the catalog contains overlapping keys
	// ("g5" and "g5g", "p4d" and "p4de"); the more specific one is the
	// better answer, and picking it by length is stable.
	clouds := make([]string, 0, len(catalog))
	for cloud := range catalog {
		clouds = append(clouds, cloud)
	}
	sort.Strings(clouds)

	bestCloud, bestPrefix := "", ""
	var bestEntry catalogEntry
	for _, cloud := range clouds {
		entries := catalog[cloud]
		prefixes := make([]string, 0, len(entries))
		for p := range entries {
			prefixes = append(prefixes, p)
		}
		sort.Strings(prefixes)
		for _, prefix := range prefixes {
			if !strings.Contains(content, prefix) {
				continue
			}
			if len(prefix) > len(bestPrefix) {
				bestCloud, bestPrefix, bestEntry = cloud, prefix, entries[prefix]
			}
		}
	}
	if bestPrefix == "" {
		return nil
	}

	cloud, prefix, entry := bestCloud, bestPrefix, bestEntry
	hours := float64(AssumedHoursPerMonth())
	out := &types.FinOpsCost{
		InstanceFamily: prefix,
		Cloud:          cloudDisplay(cloud),
		HourlyUSDLow:   entry.HourlyUSDLow,
		HourlyUSDHigh:  entry.HourlyUSDHigh,
		MonthlyUSDLow:  entry.HourlyUSDLow * hours,
		MonthlyUSDHigh: entry.HourlyUSDHigh * hours,
		Description:    entry.Description,
	}
	if mult := SpotMultiplier(cloud); mult > 0 {
		out.SpotMultiplier = mult
		out.SpotHourlyUSDLow = entry.HourlyUSDLow * mult
		out.SpotHourlyUSDHigh = entry.HourlyUSDHigh * mult
		out.SpotMonthlyUSDLow = out.MonthlyUSDLow * mult
		out.SpotMonthlyUSDHigh = out.MonthlyUSDHigh * mult
	}
	return out
}

// cloudDisplay turns the lower-case catalog key ("aws", "azure", "gcp")
// into the canonical capitalisation used in the existing FinOps
// description strings. Keeps Annex IV consistent with what auditors
// have already seen in older proof drills.
func cloudDisplay(cloud string) string {
	switch cloud {
	case "aws":
		return "AWS"
	case "azure":
		return "Azure"
	case "gcp":
		return "GCP"
	default:
		return strings.ToUpper(cloud)
	}
}
