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
	"strings"
	"time"

	"aicap/pkg/compliance"
	"aicap/pkg/types"
)

var targetAILibraries map[string]types.LibraryMeta

var targetModels []string

var modelLicenseMap map[string]types.LicenseMapping

//go:embed libraries.json models.json licenses.json
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
			if info.Name() == "requirements.txt" {
				deps := parseRequirementsTxt(path)
				bom.Dependencies = append(bom.Dependencies, deps...)
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
				finops := parseKubernetesManifest(path)
				bom.FinOps = append(bom.FinOps, finops...)
				// Also check for Helm values with GPU resources
				if info.Name() == "values.yaml" || info.Name() == "values.yml" {
					helmFinOps := parseHelmValues(path)
					bom.FinOps = append(bom.FinOps, helmFinOps...)
				}
			}

			// Terraform FinOps: parse .tf files for GPU instance types
			if ext == ".tf" {
				finops := parseTerraformFile(path)
				bom.FinOps = append(bom.FinOps, finops...)
			}
		}
		return nil
	})

	if err != nil {
		log.Printf("Error scanning directory: %v", err)
	}

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

	// Phase: Policy-as-Code Evaluation
	// Load .aicap.yml policy if it exists in the scanned directory
	policy := compliance.LoadPolicyConfig(scanDir)
	if policy != nil {
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

// loadPolicyConfig reads a .aicap.yml policy configuration file
func parseRequirementsTxt(filePath string) []types.AIDependency {
	var found []types.AIDependency
	file, err := os.Open(filePath)
	if err != nil {
		return found
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Regex to match "library==version" or just "library"
	re := regexp.MustCompile(`^([a-zA-Z0-9_\-]+)(?:[>=<~]+([a-zA-Z0-9_\-\.]+))?`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		matches := re.FindStringSubmatch(line)
		if len(matches) > 1 {
			pkgName := strings.ToLower(matches[1])
			version := "unknown"
			if len(matches) > 2 && matches[2] != "" {
				version = matches[2]
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

// parsePythonSource uses heuristic regex matching to find string literals AND import statements in Python files
func parsePythonSource(filePath string) []types.AIDependency {
	var found []types.AIDependency
	file, err := os.Open(filePath)
	if err != nil {
		return found
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Regex to match string literals inside single or double quotes
	strRegex := regexp.MustCompile(`"([^"]*)"|'([^']*)'`)
	// Regex to match "import X" or "from X import Y" patterns
	importRegex := regexp.MustCompile(`^\s*(?:import\s+([a-zA-Z0-9_]+)|from\s+([a-zA-Z0-9_]+)(?:\.[a-zA-Z0-9_.]+)?\s+import)`)

	detectedImports := map[string]bool{} // deduplicate
	lineNum := 1
	for scanner.Scan() {
		line := scanner.Text()

		// Detect Python import statements for AI libraries
		importMatches := importRegex.FindStringSubmatch(line)
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
					Ecosystem:   "Source Code (.py import)",
					RiskLevel:   meta.Risk,
					Description: meta.Desc + " (detected via import statement)",
					Location:    fmt.Sprintf("%s:%d", filePath, lineNum),
				})
			}
		}

		// Detect hardcoded model strings and secrets
		matches := strRegex.FindAllStringSubmatch(line, -1)
		for _, match := range matches {
			if len(match) > 2 {
				val := match[1]
				if val == "" {
					val = match[2]
				}

				isTargetModel := false
				for _, model := range targetModels {
					if strings.Contains(val, model) {
						isTargetModel = true
						break
					}
				}

				if isTargetModel {
					found = append(found, types.AIDependency{
						Name:        "Hardcoded Model",
						Version:     val,
						Ecosystem:   "Source Code (.py)",
						RiskLevel:   "High",
						Description: "Hardcoded AI model identifier found in Python source code",
						Location:    fmt.Sprintf("%s:%d", filePath, lineNum),
					})
				}

				if strings.HasPrefix(val, "sk-") && len(val) > 20 {
					found = append(found, types.AIDependency{
						Name:        "Exposed Secret",
						Version:     "HIDDEN",
						Ecosystem:   "Source Code (.py)",
						RiskLevel:   "High",
						Description: "Potential hardcoded API key found in Python source code",
						Location:    fmt.Sprintf("%s:%d", filePath, lineNum),
					})
				}
			}
		}
		lineNum++
	}
	return found
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
			val := strings.Trim(lit.Value, "\"")

			isTargetModel := false
			for _, model := range targetModels {
				if strings.Contains(val, model) {
					isTargetModel = true
					break
				}
			}

			// Detect hardcoded model identifiers
			if isTargetModel {
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

// parsePyProjectToml extracts AI dependencies from Poetry pyproject.toml files
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

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Detect dependency sections
		if trimmed == "[tool.poetry.dependencies]" || trimmed == "[project.dependencies]" {
			inDepsSection = true
			continue
		}

		// Exit when we hit a new section
		if strings.HasPrefix(trimmed, "[") {
			inDepsSection = false
			continue
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
				for aiKey, aiDesc := range aiBaseImages {
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

		// Detect pip install of AI libraries within Dockerfile RUN commands
		if strings.HasPrefix(lineLower, "run ") && strings.Contains(lineLower, "pip install") {
			for libName, meta := range targetAILibraries {
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

	// AWS GPU instance families
	awsGPUInstances := map[string]string{
		"p3.":   "NVIDIA V100 GPU (p3) — $3.06-$24.48/hr",
		"p4d.":  "NVIDIA A100 GPU (p4d) — $32.77/hr",
		"p4de.": "NVIDIA A100 80GB GPU (p4de) — $40.97/hr",
		"p5.":   "NVIDIA H100 GPU (p5) — $98.32/hr",
		"g4dn.": "NVIDIA T4 GPU (g4dn) — $0.53-$7.82/hr",
		"g5.":   "NVIDIA A10G GPU (g5) — $1.01-$16.29/hr",
		"g5g.":  "AWS Graviton GPU (g5g) — $0.42-$2.74/hr",
		"g6.":   "NVIDIA L4 GPU (g6) — $0.80-$13.35/hr",
		"inf1.": "AWS Inferentia (inf1) — $0.23-$4.72/hr",
		"inf2.": "AWS Inferentia2 (inf2) — $0.76-$12.98/hr",
		"trn1.": "AWS Trainium (trn1) — $1.34-$21.50/hr",
	}

	// Azure GPU instance families
	azureGPUInstances := map[string]string{
		"standard_nc": "NVIDIA T4/V100 GPU (NC-series)",
		"standard_nd": "NVIDIA A100/H100 GPU (ND-series)",
		"standard_nv": "NVIDIA GPU for visualization (NV-series)",
	}

	// GCP GPU instance families
	gcpGPUInstances := map[string]string{
		"a2-highgpu":  "NVIDIA A100 GPU (a2-highgpu)",
		"a2-megagpu":  "NVIDIA A100 80GB GPU (a2-megagpu)",
		"g2-standard": "NVIDIA L4 GPU (g2-standard)",
		"a3-highgpu":  "NVIDIA H100 GPU (a3-highgpu)",
	}

	checkInstances := func(instances map[string]string, cloud string) {
		for instanceType, desc := range instances {
			if strings.Contains(content, instanceType) {
				// Check for spot/preemptible configurations
				hasSpot := strings.Contains(content, "spot") ||
					strings.Contains(content, "preemptible") ||
					strings.Contains(content, "capacity_type") && strings.Contains(content, "spot")

				severity := "Warning"
				description := fmt.Sprintf("%s instance detected in Terraform config: %s.", cloud, desc)
				if !hasSpot {
					description += " Consider using spot/preemptible instances for 60-90%% cost savings on non-critical workloads."
				} else {
					severity = "Info"
					description += " Spot/preemptible pricing detected — good cost optimization."
				}

				found = append(found, types.FinOpsFinding{
					Resource:    filepath.Base(filePath),
					Severity:    severity,
					Description: description,
					Location:    filePath,
				})
			}
		}
	}

	checkInstances(awsGPUInstances, "AWS")
	checkInstances(azureGPUInstances, "Azure")
	checkInstances(gcpGPUInstances, "GCP")

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
