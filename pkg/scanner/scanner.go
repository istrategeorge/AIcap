package scanner

import (
	"bufio"
	"embed"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"aicap/pkg/compliance"
	"aicap/pkg/finops"
	"aicap/pkg/types"
)

var targetAILibraries map[string]types.LibraryMeta

var targetModels []string

var modelLicenseMap map[string]types.LicenseMapping

// modelFamily is a compiled entry from model_families.json. Families
// exist because a flat list of literal model names (models.json) goes
// stale the instant a vendor ships a new generation — and a stale model
// list in a compliance scanner is not a cosmetic problem: the codebase
// scans clean, reports no AI components, and that verdict gets written
// into the audit ledger. Patterns keep matching across releases.
type modelFamily struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
	Vendor  string `json:"vendor"`
	License string `json:"license"`

	re *regexp.Regexp
}

var modelFamilies []modelFamily

//go:embed libraries.json models.json licenses.json model_families.json
var embeddedFiles embed.FS

func init() {
	libFile, err := embeddedFiles.ReadFile("libraries.json")
	if err != nil {
		log.Println("Could not load libraries.json, using default libraries.")
		targetAILibraries = map[string]types.LibraryMeta{
			"openai":       {"High", "External LLM API Call (OpenAI)"},
			"anthropic":    {"High", "External LLM API Call (Anthropic)"},
			"langchain":    {"Medium", "LLM Orchestration Framework"},
			"torch":        {"High", "PyTorch Machine Learning Framework"},
			"tensorflow":   {"High", "TensorFlow Machine Learning Framework"},
			"scikit-learn": {"Low", "Traditional Machine Learning Library"},
			"transformers": {"High", "Hugging Face Transformers"},
		}
	} else {
		if err := json.Unmarshal(libFile, &targetAILibraries); err != nil {
			log.Printf("Error parsing libraries.json: %v. Using defaults.", err)
		}
	}

	file, err := embeddedFiles.ReadFile("models.json")
	if err != nil {
		log.Println("Could not load models.json, using default models.")
		targetModels = []string{"gpt-4", "claude-3", "llama-3"}
		return
	}
	if err := json.Unmarshal(file, &targetModels); err != nil {
		log.Printf("Error parsing models.json: %v. Using defaults.", err)
		targetModels = []string{"gpt-4", "claude-3", "llama-3"}
	}

	licFile, err := embeddedFiles.ReadFile("licenses.json")
	if err != nil {
		log.Println("Could not load licenses.json, using default license mappings.")
		modelLicenseMap = map[string]types.LicenseMapping{
			"llama-3":  {HFID: "meta-llama/Meta-Llama-3-8B"},
			"mixtral":  {HFID: "mistralai/Mixtral-8x7B-v0.1"},
			"gpt-4":    {License: "Proprietary (OpenAI)"},
			"o1-":      {License: "Proprietary (OpenAI)"},
			"claude-3": {License: "Proprietary (Anthropic)"},
			"gemini":   {License: "Proprietary (Google)"},
		}
	} else {
		if err := json.Unmarshal(licFile, &modelLicenseMap); err != nil {
			log.Printf("Error parsing licenses.json: %v. Using defaults.", err)
		}
	}

	famFile, err := embeddedFiles.ReadFile("model_families.json")
	if err != nil {
		log.Println("Could not load model_families.json; falling back to literal model matching only.")
		return
	}
	if err := loadModelFamilies(famFile); err != nil {
		log.Printf("Error parsing model_families.json: %v. Falling back to literal model matching only.", err)
	}
}

// loadModelFamilies parses and compiles a model-family catalog, replacing
// whatever is currently loaded. Split out from init so it can be driven
// by a test or a remote catalog refresh.
//
// A family whose pattern fails to compile is skipped with a log line
// rather than aborting the whole catalog — one bad regex should cost us
// one family, not every family.
func loadModelFamilies(data []byte) error {
	var doc struct {
		Families []modelFamily `json:"families"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return err
	}

	compiled := make([]modelFamily, 0, len(doc.Families))
	for _, fam := range doc.Families {
		// (?i) — model identifiers are written in every casing:
		// "GPT-4o", "Claude-Sonnet-4-5", "meta-llama/Llama-3.1-8B".
		re, err := regexp.Compile("(?i)" + fam.Pattern)
		if err != nil {
			log.Printf("Skipping model family %q: bad pattern: %v", fam.Name, err)
			continue
		}
		fam.re = re
		compiled = append(compiled, fam)
	}
	modelFamilies = compiled
	return nil
}

// matchModelFamily returns the first family whose pattern matches the
// literal, if any. Callers must already have ruled the literal out as
// prose (see isTargetModelLiteral).
func matchModelFamily(val string) (modelFamily, bool) {
	for _, fam := range modelFamilies {
		if fam.re != nil && fam.re.MatchString(val) {
			return fam, true
		}
	}
	return modelFamily{}, false
}

// sortedKeys returns a map's keys in a stable order. Any loop that
// emits a finding while ranging a map must use this: Go randomises map
// iteration, and that randomness propagates into the BOM, the ledger
// hash computed over it, and the rendered document.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// sortedLibraryNames returns the AI-library catalog keys in a stable
// order. Callers that emit a finding per catalog match must use this
// rather than ranging the map: Go randomises map iteration, and any
// randomness in the order findings are appended propagates into the
// BOM, into the ledger hash computed over it, and into the rendered
// document.
func sortedLibraryNames() []string {
	names := make([]string, 0, len(targetAILibraries))
	for name := range targetAILibraries {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// LookupLibrary returns the catalog metadata for a known AI library
// keyed by its lowercased package name (PyPI name, npm name, etc.).
// The returned bool is false when the library is not in the catalog.
// Exported so out-of-package scanners (e.g. pkg/imagescan, which walks
// container-image layers) can cross-reference findings against the same
// curated set of AI dependencies the directory scanner uses.
func LookupLibrary(name string) (types.LibraryMeta, bool) {
	meta, ok := targetAILibraries[strings.ToLower(name)]
	return meta, ok
}

func PerformScan(scanDir string) types.AIBOM {
	bom := types.AIBOM{
		ProjectName:  filepath.Base(scanDir),
		Dependencies: []types.AIDependency{},
		FinOps:       []types.FinOpsFinding{},
		Compliance:   "Pending",
	}

	// Walk the directory looking for manifest files
	err := filepath.Walk(scanDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip hidden directories like .git
		if info.IsDir() && strings.HasPrefix(info.Name(), ".") && info.Name() != "." && info.Name() != ".." {
			return filepath.SkipDir
		}

		if !info.IsDir() {
			bom.ScannedFiles++
			// Wave 16: match the whole requirements-file family, not
			// just the exact name — requirements-dev.txt and
			// requirements/base.txt are as common as requirements.txt
			// and were previously skipped entirely.
			if isRequirementsFile(path) {
				deps := parseRequirementsTxt(path)
				bom.Dependencies = append(bom.Dependencies, deps...)
				bias, defenses := detectGovernanceFromManifest(path)
				bom.Governance.BiasMonitoring = append(bom.Governance.BiasMonitoring, bias...)
				bom.Governance.PromptInjectionDefenses = append(bom.Governance.PromptInjectionDefenses, defenses...)
			}
			if info.Name() == "package.json" {
				deps := parsePackageJson(path)
				bom.Dependencies = append(bom.Dependencies, deps...)
			}
			if info.Name() == "go.mod" {
				deps := parseGoMod(path)
				bom.Dependencies = append(bom.Dependencies, deps...)
			}
			if info.Name() == "pyproject.toml" {
				deps := parsePyProjectToml(path)
				bom.Dependencies = append(bom.Dependencies, deps...)
				bias, defenses := detectGovernanceFromManifest(path)
				bom.Governance.BiasMonitoring = append(bom.Governance.BiasMonitoring, bias...)
				bom.Governance.PromptInjectionDefenses = append(bom.Governance.PromptInjectionDefenses, defenses...)
			}
			// Wave 7c — additional Python dep manifests.
			// poetry.lock and Pipfile.lock are the resolved trees that
			// Poetry / Pipenv emit; they're authoritative for the actual
			// versions a deploy will install, more so than pyproject.toml
			// or Pipfile (which carry version ranges).
			if info.Name() == "poetry.lock" {
				deps := parsePoetryLock(path)
				bom.Dependencies = append(bom.Dependencies, deps...)
			}
			if info.Name() == "Pipfile.lock" {
				deps := parsePipfileLock(path)
				bom.Dependencies = append(bom.Dependencies, deps...)
			}
			// Wave 7c — pnpm + yarn lockfiles. Same role for the JS
			// ecosystem as the Python lockfiles above. package.json
			// alone shows version *ranges*; the lockfiles tell us the
			// resolved version that actually got installed.
			if info.Name() == "pnpm-lock.yaml" {
				deps := parsePnpmLock(path)
				bom.Dependencies = append(bom.Dependencies, deps...)
			}
			if info.Name() == "yarn.lock" {
				deps := parseYarnLock(path)
				bom.Dependencies = append(bom.Dependencies, deps...)
			}
			// Wave 7c — Conda environment.yml. Common in ML research
			// codebases; we only catch the explicit version-pinned
			// entries (numpy=1.26.0) and the pip sub-list — looser
			// constraints aren't useful for an SBOM.
			if info.Name() == "environment.yml" || info.Name() == "environment.yaml" {
				deps := parseCondaEnv(path)
				bom.Dependencies = append(bom.Dependencies, deps...)
			}
			if info.Name() == "Dockerfile" || strings.HasPrefix(info.Name(), "Dockerfile.") {
				deps := parseDockerfile(path)
				bom.Dependencies = append(bom.Dependencies, deps...)
			}
			if strings.HasSuffix(info.Name(), ".go") {
				deps := parseGoAST(path)
				bom.Dependencies = append(bom.Dependencies, deps...)
			}
			if strings.HasSuffix(info.Name(), ".py") {
				deps := parsePythonSource(path)
				bom.Dependencies = append(bom.Dependencies, deps...)
				training, bias, defenses := detectGovernanceFromPython(path)
				bom.Governance.TrainingData = append(bom.Governance.TrainingData, training...)
				bom.Governance.BiasMonitoring = append(bom.Governance.BiasMonitoring, bias...)
				bom.Governance.PromptInjectionDefenses = append(bom.Governance.PromptInjectionDefenses, defenses...)
			}

			// Wave 16: Jupyter notebooks. Previously unscanned despite
			// being where most ML code — and most pasted API keys —
			// actually live.
			if strings.HasSuffix(strings.ToLower(info.Name()), ".ipynb") {
				deps := parseJupyterNotebook(path)
				bom.Dependencies = append(bom.Dependencies, deps...)
			}

			// Scan .env files for leaked secrets
			if info.Name() == ".env" || strings.HasSuffix(info.Name(), ".env") {
				deps := parseEnvFile(path)
				bom.Dependencies = append(bom.Dependencies, deps...)
			}

			ext := strings.ToLower(filepath.Ext(info.Name()))
			isModelWeight := false
			switch ext {
			case ".safetensors", ".onnx", ".pt", ".h5", ".gguf", ".bin", ".tflite", ".pb", ".mlmodel", ".ckpt":
				isModelWeight = true
			}

			// Some models are directories containing .bin or .safetensors. We just flag the file.
			if info.Name() == "pytorch_model.bin" || info.Name() == "model.safetensors" {
				isModelWeight = true
			}

			if isModelWeight {
				deps := parseLocalModelWeight(path)
				bom.Dependencies = append(bom.Dependencies, deps...)
			}

			if ext == ".yaml" || ext == ".yml" {
				// Wave 7b renamed the local var (was `finops`) so it
				// doesn't shadow the new pkg/finops import.
				k8sFinOps := parseKubernetesManifest(path)
				bom.FinOps = append(bom.FinOps, k8sFinOps...)
				// Also check for Helm values with GPU resources
				if info.Name() == "values.yaml" || info.Name() == "values.yml" {
					helmFinOps := parseHelmValues(path)
					bom.FinOps = append(bom.FinOps, helmFinOps...)
				}
				// Wave 7a: HITL signals from k8s + Argo + GitHub Actions.
				// detectGovernanceFromYAML covers k8s/Argo (regex-based,
				// path-agnostic). detectGovernanceFromGitHubActions only
				// fires for files under .github/workflows so we don't
				// double-count environment: lines from unrelated YAML.
				bom.Governance.HITL = append(bom.Governance.HITL, detectGovernanceFromYAML(path)...)
				bom.Governance.HITL = append(bom.Governance.HITL, detectGovernanceFromGitHubActions(path)...)
			}

			// Terraform FinOps: parse .tf files for GPU instance types.
			// Wave 7a: also pull training-data bucket signals from the
			// same file so we don't open it twice.
			if ext == ".tf" {
				tfFinOps := parseTerraformFile(path)
				bom.FinOps = append(bom.FinOps, tfFinOps...)
				bom.Governance.TrainingData = append(bom.Governance.TrainingData, detectGovernanceFromTerraform(path)...)
			}

			// Wave 7a: DVC files are training-data versioning evidence.
			bom.Governance.TrainingData = append(bom.Governance.TrainingData, detectGovernanceFromDVC(path)...)
		}
		return nil
	})

	if err != nil {
		log.Printf("Error scanning directory: %v", err)
	}

	// Wave 7b: aggregate per-finding cost attributions into a BOM-level
	// summary. EstimateBOMCost returns nil when there are no FinOps
	// findings at all, in which case the field stays unset and the
	// `omitempty` on the JSON tag drops it from output.
	bom.FinOpsCostEstimate = finops.EstimateBOMCost(bom)

	// Wave 11: build rightsizing recommendations for inference-only
	// workloads running on training-class GPUs. Pure derivation from
	// the BOM we just assembled — returns nil when training signals
	// were detected or no candidate finding matched.
	bom.FinOpsRecommendations = finops.BuildRightsizingRecommendations(bom)

	// Determine overall compliance posture based on findings
	bom.Compliance = "Passed"
	for i, dep := range bom.Dependencies {
		if dep.RiskLevel == "High" {
			bom.Compliance = "Action Required (Annex IV Documentation Missing)"
		}

		// Phase 2, Layer 3: Enrich models with License data via Hugging Face API
		if dep.Name == "Hardcoded Model" || strings.HasPrefix(dep.Ecosystem, "Model Weight") {
			hfID := ""
			val := strings.ToLower(dep.Version)
			if dep.Version == "local" {
				val = strings.ToLower(dep.Name)
			}

			// Heuristic mapping to Hugging Face registries or proprietary licenses
			for key, mapping := range modelLicenseMap {
				if strings.Contains(val, key) {
					if mapping.License != "" {
						bom.Dependencies[i].License = mapping.License
					} else if mapping.HFID != "" {
						hfID = mapping.HFID
					}
					break
				}
			}

			// Fall back to the family's licence when licenses.json has
			// no entry — that map is keyed by specific model names and
			// so goes stale for exactly the same reason the flat model
			// list did. Open-weight families carry an empty licence
			// here on purpose: the real licence varies per checkpoint,
			// so leaving it blank keeps the Hugging Face lookup (and
			// the visible gap in the report) rather than asserting
			// something we can't stand behind.
			if bom.Dependencies[i].License == "" && hfID == "" {
				if fam, ok := matchModelFamily(val); ok && fam.License != "" {
					bom.Dependencies[i].License = fam.License
				}
			}

			if hfID != "" {
				license := fetchHuggingFaceMetadata(hfID)
				if license != "" {
					bom.Dependencies[i].License = license
				}
			}
		}
	}
	// Phase: OWASP ML Top 10 Risk Enrichment
	// Cross-reference detected dependencies with known ML attack vectors
	compliance.EnrichWithOWASPRisks(&bom)

	// Phase: EU AI Act Article 5 indicators (Wave 20). Article 5 has
	// applied since 2 Feb 2025 — earlier than the high-risk rules the
	// rest of this scanner serves — and carries the Act's heaviest
	// penalties. These are indicators requiring human assessment, never
	// determinations: whether a prohibition applies turns on deployment
	// context a static scan cannot observe.
	bom.ProhibitedPractices = compliance.DetectProhibitedPractices(bom)

	// Phase: EU AI Act Article 50 transparency duties (Wave 21). Applies
	// from 2 Aug 2026, same date as the high-risk regime. Unlike Article
	// 5 these forbid nothing — they require disclosure — so the output is
	// a duty list with the evidence found for each, not a verdict.
	bom.TransparencyObligations = compliance.DetectTransparencyObligations(bom)

	// Phase: Policy-as-Code Evaluation
	// Load .aicap.yml policy if it exists in the scanned directory
	policy := compliance.LoadPolicyConfig(scanDir)
	if policy != nil {
		bom.Policy = policy
		bom.PolicyViolations = compliance.EvaluatePolicy(policy, bom)
		if len(bom.PolicyViolations) > 0 {
			for _, v := range bom.PolicyViolations {
				if v.Severity == "Blocker" {
					bom.Compliance = "Blocked by Policy"
					break
				}
			}
		}
	}

	return bom
}

// requirementSpecRe matches the leading `name[extras]` and the first
// version constraint of a PEP 508 requirement string. Extras
// (`transformers[torch]`) and environment markers (`; python_version <
// "3.11"`) are tolerated because both are common in real manifests and
// neither changes which package is being installed.
var requirementSpecRe = regexp.MustCompile(`^([a-zA-Z0-9][a-zA-Z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?:([>=<~!]=?|===)\s*([a-zA-Z0-9_\-.*+!]+))?`)

// parseRequirementSpec pulls the package name and pinned version out of a
// single PEP 508 requirement string ("openai>=1.40.0",
// "transformers[torch]==4.44.0", `langchain ; python_version > "3.9"`).
// Returns ok=false for anything that isn't a plain named requirement —
// pip flags (`-r base.txt`, `--index-url ...`), VCS/URL installs
// (`git+https://…`), and local paths (`.`, `./pkg`) all fall out here
// rather than being recorded as a package named `-r` or `git+https`.
//
// The returned name is lower-cased; version is "unknown" when the spec
// carries no constraint we can pin (a bare name, or a range like `>=1.0`
// where the resolved version lives in a lockfile we may not have).
func parseRequirementSpec(spec string) (name, version string, ok bool) {
	spec = strings.TrimSpace(spec)
	// Strip an inline comment before parsing — "openai==1.2.0  # pinned".
	if idx := strings.Index(spec, " #"); idx >= 0 {
		spec = strings.TrimSpace(spec[:idx])
	}
	// Environment markers never affect identity; drop them.
	if idx := strings.Index(spec, ";"); idx >= 0 {
		spec = strings.TrimSpace(spec[:idx])
	}
	if spec == "" || strings.HasPrefix(spec, "-") || strings.HasPrefix(spec, ".") {
		return "", "", false
	}
	// URL / VCS installs carry no reliable package name in the spec.
	if strings.Contains(spec, "://") || strings.HasPrefix(spec, "git+") {
		return "", "", false
	}

	m := requirementSpecRe.FindStringSubmatch(spec)
	if len(m) < 2 || m[1] == "" {
		return "", "", false
	}
	version = "unknown"
	if len(m) > 3 && m[3] != "" {
		// Note: for a range (`>=1.40.0`) this records the lower bound,
		// not the version that will actually resolve at install time.
		// That matches the pre-Wave-16 behaviour and keeps a version to
		// hand to the OSV lookup; a lockfile, where one exists, is
		// always the more authoritative source and is parsed separately.
		version = m[3]
	}
	return strings.ToLower(m[1]), version, true
}

// isRequirementsFile reports whether a path is a pip requirements file.
//
// Matching only the exact name `requirements.txt` (as this scanner did
// until Wave 16) misses the two layouts most real projects use: the
// suffixed form (`requirements-dev.txt`, `requirements.prod.txt`) and the
// directory form (`requirements/base.txt`). Both were scanned as generic
// files and produced no findings at all, so a project could come back
// "Passed" with its entire AI stack declared in `requirements/base.txt`.
func isRequirementsFile(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	if !strings.HasSuffix(base, ".txt") {
		return false
	}
	if base == "requirements.txt" ||
		strings.HasPrefix(base, "requirements-") ||
		strings.HasPrefix(base, "requirements_") ||
		strings.HasPrefix(base, "requirements.") {
		return true
	}
	// requirements/base.txt, requirements/dev.txt, …
	return strings.ToLower(filepath.Base(filepath.Dir(path))) == "requirements"
}

// loadPolicyConfig reads a .aicap.yml policy configuration file
func parseRequirementsTxt(filePath string) []types.AIDependency {
	var found []types.AIDependency
	file, err := os.Open(filePath)
	if err != nil {
		return found
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		pkgName, version, ok := parseRequirementSpec(line)
		if !ok {
			continue
		}

		if meta, exists := targetAILibraries[pkgName]; exists {
			found = append(found, types.AIDependency{
				Name:        pkgName,
				Version:     version,
				Ecosystem:   "Python (pip)",
				RiskLevel:   meta.Risk,
				Description: meta.Desc,
				Location:    filePath,
			})
		}
	}
	return found
}

// fetchHuggingFaceMetadata makes a live API call to retrieve model licenses
func fetchHuggingFaceMetadata(modelID string) string {
	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("https://huggingface.co/api/models/" + modelID)
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	defer resp.Body.Close()

	var hfResp types.HFModelResponse
	if err := json.NewDecoder(resp.Body).Decode(&hfResp); err != nil {
		return ""
	}
	for _, tag := range hfResp.Tags {
		if strings.HasPrefix(tag, "license:") {
			return strings.TrimPrefix(tag, "license:")
		}
	}
	return ""
}

// parseLocalModelWeight handles local ML serialization formats
func parseLocalModelWeight(filePath string) []types.AIDependency {
	return []types.AIDependency{
		{
			Name:        filepath.Base(filePath),
			Version:     "local",
			Ecosystem:   "Model Weight (" + filepath.Ext(filePath) + ")",
			RiskLevel:   "High",
			Description: "Locally hosted model weight file detected",
			Location:    filePath,
		},
	}
}

// parsePackageJson parses Node.js dependencies
func parsePackageJson(filePath string) []types.AIDependency {
	var found []types.AIDependency
	file, err := os.ReadFile(filePath)
	if err != nil {
		return found
	}

	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}

	if err := json.Unmarshal(file, &pkg); err != nil {
		return found
	}

	checkDeps := func(deps map[string]string) {
		for name, version := range deps {
			cleanName := strings.ToLower(name)
			if meta, exists := targetAILibraries[cleanName]; exists {
				found = append(found, types.AIDependency{
					Name:        name,
					Version:     strings.TrimPrefix(strings.TrimPrefix(version, "^"), "~"),
					Ecosystem:   "Node.js (npm)",
					RiskLevel:   meta.Risk,
					Description: meta.Desc,
					Location:    filePath,
				})
			}
		}
	}

	checkDeps(pkg.Dependencies)
	checkDeps(pkg.DevDependencies)

	return found
}

// isTargetModelLiteral reports whether a string literal is a hardcoded
// model identifier. Substring matching alone flags prose — test
// assertion messages, log lines, format strings ("expected 2 deps
// (openai + llama-3 weight), got %d") — because model names appear in
// sentences about models. Real identifiers (gpt-4,
// claude-3-opus-20240229, meta-llama/Meta-Llama-3-8B) never contain
// whitespace, so any literal with whitespace is treated as prose.
//
// Two matchers run: the literal list from models.json (exact, curated)
// and the family patterns from model_families.json (generational). The
// family pass is what keeps this working when a vendor ships a new model
// generation — without it, the scanner reports a codebase using a
// current model as having no AI components at all.
func isTargetModelLiteral(val string) bool {
	if strings.ContainsAny(val, " \t\r\n") {
		return false
	}
	for _, model := range targetModels {
		if strings.Contains(val, model) {
			return true
		}
	}
	_, ok := matchModelFamily(val)
	return ok
}

// pythonScanContext parameterises the Python line scanner so the same
// detection logic serves both `.py` files and `.ipynb` notebook code
// cells, which differ only in how a finding's origin is described.
type pythonScanContext struct {
	importEcosystem  string
	literalEcosystem string
	sourceLabel      string // used in finding descriptions: "Python source code" / "notebook cell"
	// locate renders the human-readable location for a 1-based line
	// number within the scanned unit.
	locate func(lineNum int) string
}

// pythonLiteralRe matches string literals inside single or double quotes.
var pythonLiteralRe = regexp.MustCompile(`"([^"]*)"|'([^']*)'`)

// pythonImportRe matches "import X" or "from X import Y" patterns.
var pythonImportRe = regexp.MustCompile(`^\s*(?:import\s+([a-zA-Z0-9_]+)|from\s+([a-zA-Z0-9_]+)(?:\.[a-zA-Z0-9_.]+)?\s+import)`)

// scanPythonLines runs import / hardcoded-model / exposed-secret
// detection over a slice of Python source lines. Extracted from
// parsePythonSource in Wave 16 so notebooks reuse it verbatim rather
// than growing a second, drifting copy of the same heuristics.
//
// `detectedImports` is supplied by the caller so a notebook can
// deduplicate an import across all of its cells (the same `import
// torch` appearing in three cells is one dependency, not three).
func scanPythonLines(lines []string, ctx pythonScanContext, detectedImports map[string]bool) []types.AIDependency {
	var found []types.AIDependency

	for i, line := range lines {
		lineNum := i + 1

		// Detect Python import statements for AI libraries
		importMatches := pythonImportRe.FindStringSubmatch(line)
		if len(importMatches) > 0 {
			modName := importMatches[1]
			if modName == "" {
				modName = importMatches[2]
			}
			modName = strings.ToLower(modName)
			if meta, exists := targetAILibraries[modName]; exists && !detectedImports[modName] {
				detectedImports[modName] = true
				found = append(found, types.AIDependency{
					Name:        modName,
					Version:     "imported",
					Ecosystem:   ctx.importEcosystem,
					RiskLevel:   meta.Risk,
					Description: meta.Desc + " (detected via import statement)",
					Location:    ctx.locate(lineNum),
				})
			}
		}

		// Detect hardcoded model strings and secrets
		matches := pythonLiteralRe.FindAllStringSubmatch(line, -1)
		for _, match := range matches {
			if len(match) > 2 {
				val := match[1]
				if val == "" {
					val = match[2]
				}

				if isTargetModelLiteral(val) {
					found = append(found, types.AIDependency{
						Name:        "Hardcoded Model",
						Version:     val,
						Ecosystem:   ctx.literalEcosystem,
						RiskLevel:   "High",
						Description: "Hardcoded AI model identifier found in " + ctx.sourceLabel,
						Location:    ctx.locate(lineNum),
					})
				}

				if strings.HasPrefix(val, "sk-") && len(val) > 20 {
					found = append(found, types.AIDependency{
						Name:        "Exposed Secret",
						Version:     "HIDDEN",
						Ecosystem:   ctx.literalEcosystem,
						RiskLevel:   "High",
						Description: "Potential hardcoded API key found in " + ctx.sourceLabel,
						Location:    ctx.locate(lineNum),
					})
				}
			}
		}
	}
	return found
}

// parsePythonSource uses heuristic regex matching to find string literals AND import statements in Python files
func parsePythonSource(filePath string) []types.AIDependency {
	file, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	return scanPythonLines(lines, pythonScanContext{
		importEcosystem:  "Source Code (.py import)",
		literalEcosystem: "Source Code (.py)",
		sourceLabel:      "Python source code",
		locate: func(lineNum int) string {
			return fmt.Sprintf("%s:%d", filePath, lineNum)
		},
	}, map[string]bool{})
}

// parseKubernetesManifest checks IaC files for expensive GPU requests without optimization
func parseKubernetesManifest(filePath string) []types.FinOpsFinding {
	var found []types.FinOpsFinding
	file, err := os.Open(filePath)
	if err != nil {
		return found
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	hasGPURequest := false
	hasOptimization := false

	for scanner.Scan() {
		line := strings.ToLower(scanner.Text())
		// Look for common GPU resource requests
		if strings.Contains(line, "nvidia.com/gpu") || strings.Contains(line, "amd.com/gpu") {
			hasGPURequest = true
		}
		// Look for indicators of Multi-Instance GPU (MIG) or time-slicing
		if strings.Contains(line, "mig.config") || strings.Contains(line, "time-slicing") {
			hasOptimization = true
		}
	}

	if hasGPURequest && !hasOptimization {
		found = append(found, types.FinOpsFinding{
			Resource:    filepath.Base(filePath),
			Severity:    "Warning",
			Description: "Expensive GPU requested without MIG or time-slicing configuration. Potential cost inefficiency.",
			Location:    filePath,
		})
	}

	return found
}

// parseGoAST utilizes Go's Abstract Syntax Tree to find hardcoded models and secrets
func parseGoAST(filePath string) []types.AIDependency {
	var found []types.AIDependency
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, filePath, nil, 0)
	if err != nil {
		return found
	}

	ast.Inspect(node, func(n ast.Node) bool {
		// Look specifically for literal values (e.g., strings) to avoid matching comments or variable names
		lit, ok := n.(*ast.BasicLit)
		if ok && lit.Kind == token.STRING {
			// Unquote rather than trim so escape sequences resolve —
			// a source literal "a\nllama-3" contains real whitespace
			// and must be treated as prose by the model detector.
			val, err := strconv.Unquote(lit.Value)
			if err != nil {
				val = strings.Trim(lit.Value, "\"`")
			}

			// Detect hardcoded model identifiers
			if isTargetModelLiteral(val) {
				pos := fset.Position(lit.Pos())
				found = append(found, types.AIDependency{
					Name:        "Hardcoded Model",
					Version:     val,
					Ecosystem:   "Source Code (.go)",
					RiskLevel:   "High",
					Description: "Hardcoded AI model identifier found in source code",
					Location:    pos.String(),
				})
			}

			// Detect exposed API Keys (Basic heuristic for OpenAI/Anthropic keys)
			if strings.HasPrefix(val, "sk-") && len(val) > 20 {
				pos := fset.Position(lit.Pos())
				found = append(found, types.AIDependency{
					Name:        "Exposed Secret",
					Version:     "HIDDEN",
					Ecosystem:   "Source Code (.go)",
					RiskLevel:   "High",
					Description: "Potential hardcoded API key found in source code",
					Location:    pos.String(),
				})
			}
		}
		return true
	})

	return found
}

// parseGoMod extracts AI dependencies from Go module files
func parseGoMod(filePath string) []types.AIDependency {
	var found []types.AIDependency
	file, err := os.Open(filePath)
	if err != nil {
		return found
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	inRequireBlock := false
	// Match lines like: github.com/sashabaranov/go-openai v1.20.0
	requireLineRe := regexp.MustCompile(`^\s*([^\s]+)\s+v?([^\s]+)`)

	// Known AI-related Go packages mapped to our library metadata
	goAIModules := map[string]string{
		"go-openai":        "openai",
		"anthropic-sdk-go": "anthropic",
		"generative-ai-go": "google-generativeai",
		"langchaingo":      "langchain",
		"ollama":           "ollama",
		"go-cohere":        "cohere",
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "require (" {
			inRequireBlock = true
			continue
		}
		if line == ")" && inRequireBlock {
			inRequireBlock = false
			continue
		}

		// Handle single-line require: require github.com/foo/bar v1.0.0
		if strings.HasPrefix(line, "require ") && !strings.Contains(line, "(") {
			line = strings.TrimPrefix(line, "require ")
			inRequireBlock = false // it's a one-liner
		} else if !inRequireBlock {
			continue
		}

		matches := requireLineRe.FindStringSubmatch(line)
		if len(matches) < 3 {
			continue
		}

		modulePath := strings.ToLower(matches[1])
		version := matches[2]

		// Check if any known AI Go module name appears in the module path
		for goModKey, libKey := range goAIModules {
			if strings.Contains(modulePath, goModKey) {
				meta, exists := targetAILibraries[libKey]
				if !exists {
					meta = types.LibraryMeta{Risk: "Medium", Desc: "AI-related Go module"}
				}
				found = append(found, types.AIDependency{
					Name:        modulePath,
					Version:     version,
					Ecosystem:   "Go (module)",
					RiskLevel:   meta.Risk,
					Description: meta.Desc,
					Location:    filePath,
				})
				break
			}
		}
	}
	return found
}

// parsePyProjectToml extracts AI dependencies from pyproject.toml.
//
// Two distinct shapes live in this file and both must be handled:
//
//	[tool.poetry.dependencies]      key = value table (Poetry)
//	openai = "^1.12.0"
//
//	[project]                       PEP 621 array-of-strings — the
//	dependencies = [                standard form, and what uv, hatch,
//	  "openai>=1.40.0",             flit, and modern setuptools emit
//	]
//
// Until Wave 16 only the table form was parsed; a `[project]` array —
// by now the more common of the two — produced zero findings, so a
// project declaring its whole AI stack the standard way scanned clean.
// `[project.optional-dependencies]` groups are covered too, since extras
// are where GPU/ML stacks are usually declared.
func parsePyProjectToml(filePath string) []types.AIDependency {
	var found []types.AIDependency
	data, err := os.ReadFile(filePath)
	if err != nil {
		return found
	}

	content := string(data)
	lines := strings.Split(content, "\n")
	inDepsSection := false

	// Match lines like: openai = "^1.12.0" or torch = {version = ">=2.0"}
	depLineRe := regexp.MustCompile(`^\s*([a-zA-Z0-9_-]+)\s*=\s*(.+)`)

	// PEP 621 array state. `inDepArray` is set while we're inside the
	// brackets of a dependency array so continuation lines are read as
	// requirement strings rather than as TOML keys.
	inDepArray := false
	inOptionalDeps := false
	arrayEntryRe := regexp.MustCompile(`["']([^"']+)["']`)

	emitSpec := func(spec, ecosystem string) {
		pkgName, version, ok := parseRequirementSpec(spec)
		if !ok {
			return
		}
		if meta, exists := targetAILibraries[pkgName]; exists {
			found = append(found, types.AIDependency{
				Name:        pkgName,
				Version:     version,
				Ecosystem:   ecosystem,
				RiskLevel:   meta.Risk,
				Description: meta.Desc,
				Location:    filePath,
			})
		}
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// --- PEP 621 array handling (runs before section bookkeeping so
		// a `]` terminator inside an array is never mistaken for a
		// section header). ---
		if inDepArray {
			for _, m := range arrayEntryRe.FindAllStringSubmatch(trimmed, -1) {
				emitSpec(m[1], "Python (PEP 621)")
			}
			if strings.Contains(trimmed, "]") {
				inDepArray = false
			}
			continue
		}

		// Detect dependency sections. Poetry's grouped form
		// (`[tool.poetry.group.dev.dependencies]`) is the same key =
		// value table as the ungrouped one.
		if trimmed == "[tool.poetry.dependencies]" || trimmed == "[project.dependencies]" ||
			(strings.HasPrefix(trimmed, "[tool.poetry.group.") && strings.HasSuffix(trimmed, ".dependencies]")) {
			inDepsSection = true
			inOptionalDeps = false
			continue
		}

		// Exit when we hit a new section
		if strings.HasPrefix(trimmed, "[") {
			inDepsSection = false
			// `[project.optional-dependencies]` holds one array per
			// extra (dev = [...], gpu = [...]), so every array inside
			// it is a dependency array.
			inOptionalDeps = trimmed == "[project.optional-dependencies]"
			continue
		}

		// `dependencies = [...]` under [project], or any `name = [...]`
		// under [project.optional-dependencies].
		if strings.HasPrefix(trimmed, "dependencies") || inOptionalDeps {
			if idx := strings.Index(trimmed, "["); idx >= 0 && strings.Contains(trimmed, "=") &&
				strings.Index(trimmed, "=") < idx {
				rest := trimmed[idx:]
				for _, m := range arrayEntryRe.FindAllStringSubmatch(rest, -1) {
					emitSpec(m[1], "Python (PEP 621)")
				}
				// Single-line arrays close on the same line.
				if !strings.Contains(rest, "]") {
					inDepArray = true
				}
				continue
			}
		}

		if !inDepsSection {
			continue
		}

		matches := depLineRe.FindStringSubmatch(trimmed)
		if len(matches) < 3 {
			continue
		}

		pkgName := strings.ToLower(matches[1])
		versionSpec := matches[2]

		// Skip non-dependency keys like "python"
		if pkgName == "python" {
			continue
		}

		// Extract version string — handles "^1.0", {version = ">=2.0"}, etc.
		version := "unknown"
		versionSpec = strings.Trim(versionSpec, " \"'")
		if strings.HasPrefix(versionSpec, "{") {
			// Complex version specifier: extract version value
			vRe := regexp.MustCompile(`version\s*=\s*"([^"]+)"`)
			vMatch := vRe.FindStringSubmatch(versionSpec)
			if len(vMatch) > 1 {
				version = vMatch[1]
			}
		} else {
			version = strings.TrimLeft(versionSpec, "^~>=<!")
		}

		if meta, exists := targetAILibraries[pkgName]; exists {
			found = append(found, types.AIDependency{
				Name:        pkgName,
				Version:     version,
				Ecosystem:   "Python (Poetry/PEP)",
				RiskLevel:   meta.Risk,
				Description: meta.Desc,
				Location:    filePath,
			})
		}
	}
	return found
}

// parseDockerfile analyzes Dockerfiles to detect AI framework base images and model weight copies
func parseDockerfile(filePath string) []types.AIDependency {
	var found []types.AIDependency
	file, err := os.Open(filePath)
	if err != nil {
		return found
	}
	defer file.Close()

	// Known AI-related Docker base images
	aiBaseImages := map[string]string{
		"pytorch":      "PyTorch Container Image",
		"tensorflow":   "TensorFlow Container Image",
		"nvidia/cuda":  "NVIDIA CUDA Base Image",
		"huggingface":  "Hugging Face Container Image",
		"nvcr.io":      "NVIDIA Container Registry Image",
		"ollama":       "Ollama Container Image",
		"vllm":         "vLLM Inference Engine Image",
		"tritonserver": "NVIDIA Triton Inference Server",
	}

	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		lineLower := strings.ToLower(line)

		// Detect FROM instructions with AI base images
		if strings.HasPrefix(lineLower, "from ") {
			imageParts := strings.Fields(line)
			if len(imageParts) >= 2 {
				imageName := strings.ToLower(imageParts[1])
				// Sorted, and first match wins — so an image matching
				// several keys (nvcr.io/nvidia/pytorch matches both
				// "nvcr.io" and "pytorch") always gets the same
				// description. Ranging the map made the label flip
				// between runs, which meant the same Dockerfile produced
				// a different document and a different ledger hash.
				for _, aiKey := range sortedKeys(aiBaseImages) {
					aiDesc := aiBaseImages[aiKey]
					if strings.Contains(imageName, aiKey) {
						found = append(found, types.AIDependency{
							Name:        imageParts[1],
							Version:     "docker-image",
							Ecosystem:   "Container Image (Dockerfile)",
							RiskLevel:   "High",
							Description: aiDesc + " detected as base image",
							Location:    fmt.Sprintf("%s:%d", filePath, lineNum),
						})
						break
					}
				}
			}
		}

		// Detect COPY/ADD of model weight files
		if strings.HasPrefix(lineLower, "copy ") || strings.HasPrefix(lineLower, "add ") {
			modelExtensions := []string{".safetensors", ".onnx", ".pt", ".h5", ".gguf", ".bin", ".tflite", ".pb", ".ckpt"}
			for _, ext := range modelExtensions {
				if strings.Contains(lineLower, ext) {
					found = append(found, types.AIDependency{
						Name:        "Containerized Model Weight",
						Version:     "docker-layer",
						Ecosystem:   "Container Image (Dockerfile)",
						RiskLevel:   "High",
						Description: fmt.Sprintf("Model weight file (%s) being copied into container image", ext),
						Location:    fmt.Sprintf("%s:%d", filePath, lineNum),
					})
					break
				}
			}
		}

		// Detect pip install of AI libraries within Dockerfile RUN commands.
		//
		// Iterated in sorted order, not map order. Go randomises map
		// iteration, so ranging the catalog directly emitted these
		// findings in a different sequence on every run — which made the
		// BOM's dependency order vary, and the BOM is what the ledger
		// hashes. Two scans of an identical tree produced different
		// crypto_hashes, so a chain could not distinguish "the code
		// changed" from "the map iterated differently", and the
		// generated document reshuffled itself between runs.
		if strings.HasPrefix(lineLower, "run ") && strings.Contains(lineLower, "pip install") {
			for _, libName := range sortedLibraryNames() {
				meta := targetAILibraries[libName]
				if strings.Contains(lineLower, libName) {
					found = append(found, types.AIDependency{
						Name:        libName,
						Version:     "docker-install",
						Ecosystem:   "Container Image (pip in Dockerfile)",
						RiskLevel:   meta.Risk,
						Description: meta.Desc + " (installed in Dockerfile)",
						Location:    fmt.Sprintf("%s:%d", filePath, lineNum),
					})
				}
			}
		}
	}
	return found
}

// generateCycloneDXBOM converts AIcap's types.AIBOM to CycloneDX 1.5 JSON format
func parseTerraformFile(filePath string) []types.FinOpsFinding {
	var found []types.FinOpsFinding
	data, err := os.ReadFile(filePath)
	if err != nil {
		return found
	}

	content := strings.ToLower(string(data))

	// Wave 7b: cost data lives in pkg/finops/gpu_costs.json. LookupGPUCost
	// returns the first matching family — finding cost ranges, hourly +
	// monthly, plus a human-readable family description that we splice
	// into the existing Severity / Description shape so the dashboard
	// table doesn't need any field-level changes.
	cost := finops.LookupGPUCost(content)
	if cost == nil {
		// No GPU instance family matched — nothing to report from this
		// file. Earlier versions of this function would emit an
		// uncostable warning, but the K8s parser already covers the
		// "GPU detected with no instance type" case and we'd just be
		// double-reporting.
		return found
	}

	// Spot / preemptible detection stays heuristic — Terraform can express
	// it many ways (capacity_type = "spot", spot_price = ..., scheduling
	// blocks, tags). We treat "any of the keywords appearing in the file"
	// as evidence; false positives are tolerable because the message is
	// always advisory.
	hasSpot := strings.Contains(content, "spot") ||
		strings.Contains(content, "preemptible") ||
		(strings.Contains(content, "capacity_type") && strings.Contains(content, "spot"))

	severity := "Warning"
	description := fmt.Sprintf("%s instance detected in Terraform config: %s.", cost.Cloud, cost.Description)
	if !hasSpot {
		description += " Consider using spot/preemptible instances for 60-90% cost savings on non-critical workloads."
	} else {
		severity = "Info"
		description += " Spot/preemptible pricing detected — good cost optimization."
	}

	found = append(found, types.FinOpsFinding{
		Resource:      filepath.Base(filePath),
		Severity:      severity,
		Description:   description,
		Location:      filePath,
		EstimatedCost: cost,
	})

	return found
}

// parseEnvFile scans .env files for exposed AI platform API keys and secrets
func parseEnvFile(filePath string) []types.AIDependency {
	var found []types.AIDependency
	file, err := os.Open(filePath)
	if err != nil {
		return found
	}
	defer file.Close()

	// Sensitive key patterns for AI/ML platforms
	sensitivePatterns := map[string]string{
		"sk-":     "OpenAI API Key",
		"sk-ant-": "Anthropic API Key",
		"hf_":     "Hugging Face API Token",
		"AIza":    "Google AI API Key",
		"AKIA":    "AWS Access Key (potential SageMaker/Bedrock)",
		"r8_":     "Replicate API Token",
		"xai-":    "xAI (Grok) API Key",
	}

	// Also check key names that hint at AI services
	sensitiveKeyNames := map[string]string{
		"OPENAI_API_KEY":        "OpenAI",
		"ANTHROPIC_API_KEY":     "Anthropic",
		"HUGGINGFACE_TOKEN":     "Hugging Face",
		"HF_TOKEN":              "Hugging Face",
		"GOOGLE_AI_API_KEY":     "Google AI",
		"COHERE_API_KEY":        "Cohere",
		"REPLICATE_API_TOKEN":   "Replicate",
		"AZURE_OPENAI_API_KEY":  "Azure OpenAI",
		"AWS_SECRET_ACCESS_KEY": "AWS (SageMaker/Bedrock)",
		"WANDB_API_KEY":         "Weights & Biases",
		"LANGCHAIN_API_KEY":     "LangChain/LangSmith",
		"PINECONE_API_KEY":      "Pinecone Vector DB",
		"TOGETHER_API_KEY":      "Together AI",
	}

	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		keyName := strings.TrimSpace(parts[0])
		keyValue := strings.TrimSpace(parts[1])
		keyValue = strings.Trim(keyValue, "\"'")

		// Check if the variable name suggests an AI API key
		if platform, isAIKey := sensitiveKeyNames[strings.ToUpper(keyName)]; isAIKey {
			if keyValue != "" && keyValue != "your-key-here" && !strings.HasPrefix(keyValue, "${") && !strings.HasPrefix(keyValue, "<") {
				found = append(found, types.AIDependency{
					Name:        "Exposed Secret",
					Version:     "HIDDEN",
					Ecosystem:   "Environment File (.env)",
					RiskLevel:   "High",
					Description: fmt.Sprintf("%s API key found in .env file — should be in a secret manager, not committed to VCS", platform),
					Location:    fmt.Sprintf("%s:%d", filePath, lineNum),
				})
			}
		}

		// Check if the value matches a known secret pattern
		for prefix, platform := range sensitivePatterns {
			if strings.HasPrefix(keyValue, prefix) && len(keyValue) > 20 {
				found = append(found, types.AIDependency{
					Name:        "Exposed Secret",
					Version:     "HIDDEN",
					Ecosystem:   "Environment File (.env)",
					RiskLevel:   "High",
					Description: fmt.Sprintf("%s detected in .env file — rotate this key immediately", platform),
					Location:    fmt.Sprintf("%s:%d", filePath, lineNum),
				})
				break // avoid double-flagging
			}
		}
	}
	return found
}

// parseHelmValues analyzes Helm values.yaml for GPU resource requests and AI model serving configs
func parseHelmValues(filePath string) []types.FinOpsFinding {
	var found []types.FinOpsFinding
	data, err := os.ReadFile(filePath)
	if err != nil {
		return found
	}

	content := strings.ToLower(string(data))
	lines := strings.Split(content, "\n")

	hasGPU := false
	hasModelServing := false
	hasAutoscaling := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Detect GPU resource requests
		if strings.Contains(trimmed, "nvidia.com/gpu") || strings.Contains(trimmed, "amd.com/gpu") {
			hasGPU = true
		}

		// Detect model serving frameworks
		modelServingPatterns := []string{
			"tritonserver", "tensorflow-serving", "torchserve", "seldon",
			"kserve", "mlflow", "bentoml", "ray-serve", "vllm",
		}
		for _, pattern := range modelServingPatterns {
			if strings.Contains(trimmed, pattern) {
				hasModelServing = true
			}
		}

		// Detect autoscaling configuration
		if strings.Contains(trimmed, "autoscaling") || strings.Contains(trimmed, "hpa") || strings.Contains(trimmed, "minreplicas") {
			hasAutoscaling = true
		}
	}

	if hasGPU {
		severity := "Warning"
		desc := "GPU resource requests detected in Helm values. "
		if !hasAutoscaling {
			desc += "No autoscaling configuration found — fixed GPU allocation may lead to cost waste during low-traffic periods."
		} else {
			severity = "Info"
			desc += "Autoscaling is configured — good cost optimization practice."
		}
		found = append(found, types.FinOpsFinding{
			Resource:    filepath.Base(filePath),
			Severity:    severity,
			Description: desc,
			Location:    filePath,
		})
	}

	if hasModelServing {
		found = append(found, types.FinOpsFinding{
			Resource:    filepath.Base(filePath),
			Severity:    "Info",
			Description: "AI model serving framework configuration detected in Helm values. Consider batching inference requests for GPU utilization optimization.",
			Location:    filePath,
		})
	}

	return found
}

// owaspMLRisks provides a static mapping of detected dependencies to OWASP Machine Learning Top 10 risks
// This enriches the compliance report with known attack vectors
