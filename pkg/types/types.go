package types

// AIDependency represents an identified AI library/model in the codebase
type AIDependency struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Ecosystem   string `json:"ecosystem"`
	RiskLevel   string `json:"riskLevel"`
	Description string `json:"description"`
	Location    string `json:"location,omitempty"`
	License     string `json:"license,omitempty"`
}

// FinOpsFinding represents a cloud cost optimization warning
type FinOpsFinding struct {
	Resource    string `json:"resource"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Location    string `json:"location,omitempty"`
}

// AIBOM represents the final Software Bill of Materials for AI
type AIBOM struct {
	ProjectName      string            `json:"projectName"`
	CommitSha        string            `json:"commitSha,omitempty"`
	ScannedFiles     int               `json:"scannedFiles"`
	Dependencies     []AIDependency    `json:"dependencies"`
	FinOps           []FinOpsFinding   `json:"finOps"`
	PolicyViolations []PolicyViolation `json:"policyViolations,omitempty"`
	Compliance       string            `json:"complianceStatus"`
}

// PolicyViolation represents a policy-as-code rule violation
type PolicyViolation struct {
	Rule        string `json:"rule"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Location    string `json:"location,omitempty"`
}

// PolicyConfig represents the .aicap.yml policy-as-code configuration
type PolicyConfig struct {
	AllowedModels   []string `json:"allowedModels"`
	BlockedModels   []string `json:"blockedModels"`
	MaxRiskLevel    string   `json:"maxRiskLevel"`
	BlockOnHighRisk bool     `json:"blockOnHighRisk"`
	RequireLicenses bool     `json:"requireLicenses"`
	AllowedLicenses []string `json:"allowedLicenses"`
}

// Map of known AI libraries and their assumed regulatory risk (MVP level)
type LibraryMeta struct {
	Risk string `json:"risk"`
	Desc string `json:"desc"`
}

// ProofRecord represents a historical compliance scan
type ProofRecord struct {
	ProjectName string `json:"projectName"`
	CommitSha   string `json:"commitSha"`
	CryptoHash  string `json:"cryptoHash"`
	Timestamp   string `json:"timestamp"`
}

// LicenseMapping links a local/hardcoded model to its registry or proprietary license
type LicenseMapping struct {
	HFID    string `json:"hf_id,omitempty"`
	License string `json:"license,omitempty"`
}

// CycloneDX SBOM structures — minimal CycloneDX 1.5 compatible output
type CycloneDXBOM struct {
	BOMFormat    string               `json:"bomFormat"`
	SpecVersion  string               `json:"specVersion"`
	SerialNumber string               `json:"serialNumber"`
	Version      int                  `json:"version"`
	Metadata     CycloneDXMetadata    `json:"metadata"`
	Components   []CycloneDXComponent `json:"components"`
}

type CycloneDXMetadata struct {
	Timestamp string             `json:"timestamp"`
	Component CycloneDXComponent `json:"component"`
}

type CycloneDXComponent struct {
	Type       string              `json:"type"`
	BOMRef     string              `json:"bom-ref"`
	Name       string              `json:"name"`
	Version    string              `json:"version,omitempty"`
	PURL       string              `json:"purl,omitempty"`
	Licenses   []CycloneDXLicense  `json:"licenses,omitempty"`
	Properties []CycloneDXProperty `json:"properties,omitempty"`
}

type CycloneDXLicense struct {
	License struct {
		ID   string `json:"id,omitempty"`
		Name string `json:"name,omitempty"`
	} `json:"license"`
}

type CycloneDXProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// HFModelResponse structure for HuggingFace Hub API
type HFModelResponse struct {
	Id         string `json:"_id"`
	ModelId    string `json:"modelId"`
	Tags       []string `json:"tags"`
	PipelineTag string `json:"pipeline_tag"`
}
