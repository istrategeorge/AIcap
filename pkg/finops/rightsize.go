package finops

// Wave 11: rightsizing recommendations.
//
// When a BOM shows no training signals — i.e. the workload looks
// inference-only — but the scanner detected a training-class GPU
// (p4d, p5, a3-highgpu, standard_nd, …), we surface a suggestion to
// swap to the matching inference-optimized family in the same cloud
// (inf2, g6, g2-standard, …). Conservative by design: we only emit
// when both sides of the recommendation are in our catalog so the
// savings figure has the same provenance as the on-demand estimate.

import (
	"fmt"
	"strings"

	"aicap/pkg/types"
)

// inferenceAlternative maps a training-class instance family (catalog
// prefix, lower-case) to the recommended inference family in the same
// cloud plus a one-line rationale that names the accelerator the
// recommendation is built around. Mappings are intentionally
// conservative — we only list cases where there's a clear inference
// silicon equivalent. Cases like Azure ND (H100/A100 training) have no
// dedicated Azure inference SKU yet so we don't suggest one; auditors
// will see no recommendation rather than a misleading one.
var inferenceAlternative = map[string]struct {
	Cloud       string // catalog cloud key (lower-case)
	Family      string // recommended catalog prefix
	Accelerator string // human-readable accelerator name
	Note        string // short rationale fragment
}{
	"p3.":        {"aws", "g5.", "NVIDIA A10G", "successor inference family with newer GPU at a fraction of the cost"},
	"p4d.":       {"aws", "inf2.", "AWS Inferentia2", "purpose-built inference silicon; A100-class throughput at a fraction of the cost"},
	"p4de.":      {"aws", "inf2.", "AWS Inferentia2", "purpose-built inference silicon; A100 80GB workloads typically fit on inf2.xlarge–inf2.24xlarge"},
	"p5.":        {"aws", "inf2.", "AWS Inferentia2", "H100 is over-provisioned for inference; Inferentia2 covers most LLM serving workloads"},
	"trn1.":      {"aws", "inf2.", "AWS Inferentia2", "Trainium is training-only silicon; pair it with Inferentia2 for serving"},
	"a3-highgpu": {"gcp", "g2-standard", "NVIDIA L4", "L4 is GCP's inference-optimized GPU; H100 is over-provisioned for serving"},
	"a2-highgpu": {"gcp", "g2-standard", "NVIDIA L4", "L4 is GCP's inference-optimized GPU; A100 is training-class"},
	"a2-megagpu": {"gcp", "g2-standard", "NVIDIA L4", "L4 is GCP's inference-optimized GPU; A100 80GB is training-class"},
}

// HasTrainingSignals returns true when the BOM carries any evidence
// that the workload trains models (vs serving them). We treat any
// governance training-data signal as positive evidence; the catalog of
// detectors lives in pkg/scanner/governance.go and covers DVC,
// Terraform training buckets, and HuggingFace dataset imports.
func HasTrainingSignals(bom types.AIBOM) bool {
	if len(bom.Governance.TrainingData) > 0 {
		return true
	}
	// Also treat explicit training-loop libraries as a training signal —
	// these aren't governance evidence per se but they're load-bearing
	// proof that the codebase trains, not just serves.
	for _, dep := range bom.Dependencies {
		switch strings.ToLower(dep.Name) {
		case "pytorch-lightning", "pytorch_lightning", "accelerate", "deepspeed", "mlflow", "wandb":
			return true
		}
	}
	return false
}

// BuildRightsizingRecommendations walks the BOM's FinOps findings and
// returns a recommendation for each training-class GPU finding when
// HasTrainingSignals(bom) is false. Returns nil for the noisy case
// where the workload trains — we don't recommend swapping a training
// GPU for an inference SKU there.
func BuildRightsizingRecommendations(bom types.AIBOM) []types.FinOpsRightsizing {
	if HasTrainingSignals(bom) {
		return nil
	}
	var out []types.FinOpsRightsizing
	for _, f := range bom.FinOps {
		c := f.EstimatedCost
		if c == nil {
			continue
		}
		alt, ok := inferenceAlternative[c.InstanceFamily]
		if !ok {
			continue
		}
		// Cross-cloud recommendations aren't useful — auditors expect us
		// to stay on AWS/Azure/GCP. Skip if catalog cloud doesn't match
		// the finding's cloud (catalog stores cloud in lower-case; the
		// finding uses display casing).
		if !strings.EqualFold(alt.Cloud, c.Cloud) {
			continue
		}
		entries, ok := catalog[alt.Cloud]
		if !ok {
			continue
		}
		altEntry, ok := entries[alt.Family]
		if !ok {
			continue
		}
		hours := float64(AssumedHoursPerMonth())
		altLow := altEntry.HourlyUSDLow * hours
		altHigh := altEntry.HourlyUSDHigh * hours
		// Savings = current monthly - recommended monthly. Use a like-
		// for-like pairing (low vs low, high vs high) so the range
		// reflects the spread within each family rather than the
		// worst-case difference between extremes.
		savingsLow := c.MonthlyUSDLow - altLow
		savingsHigh := c.MonthlyUSDHigh - altHigh
		// The pairing can invert when the recommended family's price
		// spread is wider than the current one's (inf2 spans xlarge to
		// 48xlarge; p4d has a single size). A range must satisfy
		// low <= high, so order the two scenario values.
		if savingsLow > savingsHigh {
			savingsLow, savingsHigh = savingsHigh, savingsLow
		}
		if savingsLow <= 0 && savingsHigh <= 0 {
			// Refuse to recommend a family that's the same price or more.
			continue
		}
		out = append(out, types.FinOpsRightsizing{
			Resource:               f.Resource,
			Location:               f.Location,
			CurrentFamily:          c.InstanceFamily,
			CurrentCloud:           c.Cloud,
			RecommendedFamily:      alt.Family,
			RecommendedAccelerator: alt.Accelerator,
			Rationale: fmt.Sprintf(
				"No training signals detected in this BOM — workload looks inference-only. %s.",
				alt.Note,
			),
			EstimatedSavingsLow:  savingsLow,
			EstimatedSavingsHigh: savingsHigh,
		})
	}
	return out
}
