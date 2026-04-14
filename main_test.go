package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- Helper Functions ---

func createTempFile(t *testing.T, name string, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	err := os.WriteFile(path, []byte(content), 0644)
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	return path
}

func createTempDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		subDir := filepath.Dir(name)
		if subDir != "." {
			os.MkdirAll(filepath.Join(dir, subDir), 0755)
		}
		err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644)
		if err != nil {
			t.Fatalf("Failed to create temp file %s: %v", name, err)
		}
	}
	return dir
}

// --- parseRequirementsTxt Tests ---

func TestParseRequirementsTxt_DetectsAILibraries(t *testing.T) {
	content := `flask==2.0.1
openai==1.12.0
requests==2.26.0
langchain==0.1.5
scikit-learn==0.24.2
`
	path := createTempFile(t, "requirements.txt", content)
	deps := parseRequirementsTxt(path)

	if len(deps) != 3 {
		t.Fatalf("Expected 3 AI dependencies, got %d: %+v", len(deps), deps)
	}

	names := map[string]bool{}
	for _, d := range deps {
		names[d.Name] = true
		if d.Ecosystem != "Python (pip)" {
			t.Errorf("Expected ecosystem 'Python (pip)', got '%s'", d.Ecosystem)
		}
	}

	if !names["openai"] {
		t.Error("Expected to detect 'openai'")
	}
	if !names["langchain"] {
		t.Error("Expected to detect 'langchain'")
	}
	if !names["scikit-learn"] {
		t.Error("Expected to detect 'scikit-learn'")
	}
}

func TestParseRequirementsTxt_EmptyFile(t *testing.T) {
	path := createTempFile(t, "requirements.txt", "")
	deps := parseRequirementsTxt(path)
	if len(deps) != 0 {
		t.Errorf("Expected 0 dependencies from empty file, got %d", len(deps))
	}
}

func TestParseRequirementsTxt_CommentsAndBlanks(t *testing.T) {
	content := `# This is a comment
openai==1.0.0

# Another comment
flask==2.0
`
	path := createTempFile(t, "requirements.txt", content)
	deps := parseRequirementsTxt(path)
	if len(deps) != 1 {
		t.Fatalf("Expected 1 AI dependency (openai), got %d", len(deps))
	}
	if deps[0].Name != "openai" {
		t.Errorf("Expected 'openai', got '%s'", deps[0].Name)
	}
}

// --- parsePackageJson Tests ---

func TestParsePackageJson_DetectsAILibraries(t *testing.T) {
	content := `{
  "dependencies": {
    "openai": "^4.0.0",
    "express": "^4.18.0"
  },
  "devDependencies": {
    "langchain": "^0.1.0"
  }
}`
	path := createTempFile(t, "package.json", content)
	deps := parsePackageJson(path)

	if len(deps) != 2 {
		t.Fatalf("Expected 2 AI dependencies, got %d: %+v", len(deps), deps)
	}

	names := map[string]bool{}
	for _, d := range deps {
		names[d.Name] = true
	}
	if !names["openai"] {
		t.Error("Expected to detect 'openai'")
	}
	if !names["langchain"] {
		t.Error("Expected to detect 'langchain'")
	}
}

func TestParsePackageJson_InvalidJSON(t *testing.T) {
	path := createTempFile(t, "package.json", "not valid json")
	deps := parsePackageJson(path)
	if len(deps) != 0 {
		t.Errorf("Expected 0 dependencies from invalid JSON, got %d", len(deps))
	}
}

// --- parseGoAST Tests ---

func TestParseGoAST_DetectsHardcodedModels(t *testing.T) {
	content := `package main

func main() {
	model := "gpt-4-turbo"
	_ = model
}
`
	path := createTempFile(t, "test.go", content)
	deps := parseGoAST(path)

	found := false
	for _, d := range deps {
		if d.Name == "Hardcoded Model" && strings.Contains(d.Version, "gpt-4") {
			found = true
		}
	}
	if !found {
		t.Error("Expected to detect hardcoded model 'gpt-4-turbo'")
	}
}

func TestParseGoAST_DetectsExposedSecrets(t *testing.T) {
	content := `package main

var apiKey = "sk-1234567890abcdef1234567890abcdef"
`
	path := createTempFile(t, "secret.go", content)
	deps := parseGoAST(path)

	found := false
	for _, d := range deps {
		if d.Name == "Exposed Secret" {
			found = true
		}
	}
	if !found {
		t.Error("Expected to detect exposed secret starting with 'sk-'")
	}
}

func TestParseGoAST_NoFalsePositives(t *testing.T) {
	content := `package main

func main() {
	name := "hello world"
	port := "8080"
}
`
	path := createTempFile(t, "clean.go", content)
	deps := parseGoAST(path)
	if len(deps) != 0 {
		t.Errorf("Expected 0 dependencies in clean Go file, got %d: %+v", len(deps), deps)
	}
}

// --- parsePythonSource Tests ---

func TestParsePythonSource_DetectsModelsAndSecrets(t *testing.T) {
	content := `import openai

def generate():
    key = "sk-1234567890abcdef1234567890abcdef"
    response = openai.chat(model="gpt-4")
`
	path := createTempFile(t, "test.py", content)
	deps := parsePythonSource(path)

	hasModel := false
	hasSecret := false
	for _, d := range deps {
		if d.Name == "Hardcoded Model" {
			hasModel = true
		}
		if d.Name == "Exposed Secret" {
			hasSecret = true
		}
	}

	if !hasModel {
		t.Error("Expected to detect hardcoded model in Python source")
	}
	if !hasSecret {
		t.Error("Expected to detect exposed secret in Python source")
	}
}

// --- parseGoMod Tests ---

func TestParseGoMod_DetectsAIModules(t *testing.T) {
	content := `module example.com/myapp

go 1.22.0

require (
	github.com/sashabaranov/go-openai v1.20.4
	github.com/tmc/langchaingo v0.1.12
	github.com/gin-gonic/gin v1.9.1
)
`
	path := createTempFile(t, "go.mod", content)
	deps := parseGoMod(path)

	if len(deps) != 2 {
		t.Fatalf("Expected 2 AI Go modules, got %d: %+v", len(deps), deps)
	}

	names := map[string]bool{}
	for _, d := range deps {
		names[d.Name] = true
		if d.Ecosystem != "Go (module)" {
			t.Errorf("Expected ecosystem 'Go (module)', got '%s'", d.Ecosystem)
		}
	}

	if !names["github.com/sashabaranov/go-openai"] {
		t.Error("Expected to detect go-openai")
	}
	if !names["github.com/tmc/langchaingo"] {
		t.Error("Expected to detect langchaingo")
	}
}

func TestParseGoMod_SingleLineRequire(t *testing.T) {
	content := `module example.com/myapp

go 1.22.0

require github.com/sashabaranov/go-openai v1.20.4
`
	path := createTempFile(t, "go.mod", content)
	deps := parseGoMod(path)

	if len(deps) != 1 {
		t.Fatalf("Expected 1 AI Go module from single-line require, got %d", len(deps))
	}
}

func TestParseGoMod_NoAIDeps(t *testing.T) {
	content := `module example.com/myapp

go 1.22.0

require (
	github.com/gin-gonic/gin v1.9.1
	github.com/lib/pq v1.10.9
)
`
	path := createTempFile(t, "go.mod", content)
	deps := parseGoMod(path)
	if len(deps) != 0 {
		t.Errorf("Expected 0 AI dependencies, got %d: %+v", len(deps), deps)
	}
}

// --- parsePyProjectToml Tests ---

func TestParsePyProjectToml_DetectsPoetryDeps(t *testing.T) {
	content := `[tool.poetry]
name = "ml-service"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.11"
openai = "^1.12.0"
langchain = "^0.1.5"
torch = {version = ">=2.0", optional = true}
flask = "^3.0.0"
`
	path := createTempFile(t, "pyproject.toml", content)
	deps := parsePyProjectToml(path)

	if len(deps) != 3 {
		t.Fatalf("Expected 3 AI dependencies (openai, langchain, torch), got %d: %+v", len(deps), deps)
	}

	names := map[string]bool{}
	for _, d := range deps {
		names[d.Name] = true
		if d.Ecosystem != "Python (Poetry/PEP)" {
			t.Errorf("Expected ecosystem 'Python (Poetry/PEP)', got '%s'", d.Ecosystem)
		}
	}

	if !names["openai"] {
		t.Error("Expected to detect 'openai'")
	}
	if !names["langchain"] {
		t.Error("Expected to detect 'langchain'")
	}
	if !names["torch"] {
		t.Error("Expected to detect 'torch'")
	}
}

func TestParsePyProjectToml_SkipsPython(t *testing.T) {
	content := `[tool.poetry.dependencies]
python = "^3.11"
`
	path := createTempFile(t, "pyproject.toml", content)
	deps := parsePyProjectToml(path)
	if len(deps) != 0 {
		t.Errorf("Expected 0 (python should be skipped), got %d", len(deps))
	}
}

func TestParsePyProjectToml_StopsAtNewSection(t *testing.T) {
	content := `[tool.poetry.dependencies]
openai = "^1.0"

[tool.poetry.dev-dependencies]
pytest = "^7.0"
`
	path := createTempFile(t, "pyproject.toml", content)
	deps := parsePyProjectToml(path)
	if len(deps) != 1 {
		t.Fatalf("Expected 1 (openai only), got %d", len(deps))
	}
}

// --- parseDockerfile Tests ---

func TestParseDockerfile_DetectsAIBaseImage(t *testing.T) {
	content := `FROM nvcr.io/nvidia/pytorch:24.01-py3
WORKDIR /app
CMD ["python", "serve.py"]
`
	path := createTempFile(t, "Dockerfile", content)
	deps := parseDockerfile(path)

	if len(deps) != 1 {
		t.Fatalf("Expected 1 AI base image detection, got %d: %+v", len(deps), deps)
	}
	if deps[0].Ecosystem != "Container Image (Dockerfile)" {
		t.Errorf("Expected Dockerfile ecosystem, got '%s'", deps[0].Ecosystem)
	}
}

func TestParseDockerfile_DetectsModelWeightCopy(t *testing.T) {
	content := `FROM python:3.11
COPY model.safetensors /app/weights/
`
	path := createTempFile(t, "Dockerfile", content)
	deps := parseDockerfile(path)

	found := false
	for _, d := range deps {
		if d.Name == "Containerized Model Weight" {
			found = true
		}
	}
	if !found {
		t.Error("Expected to detect COPY of .safetensors model weight")
	}
}

func TestParseDockerfile_DetectsPipInstall(t *testing.T) {
	content := `FROM python:3.11
RUN pip install torch transformers
`
	path := createTempFile(t, "Dockerfile", content)
	deps := parseDockerfile(path)

	names := map[string]bool{}
	for _, d := range deps {
		names[d.Name] = true
	}
	if !names["torch"] {
		t.Error("Expected to detect pip install of torch")
	}
	if !names["transformers"] {
		t.Error("Expected to detect pip install of transformers")
	}
}

func TestParseDockerfile_CleanDockerfile(t *testing.T) {
	content := `FROM golang:1.22
WORKDIR /app
COPY . .
RUN go build -o server .
CMD ["./server"]
`
	path := createTempFile(t, "Dockerfile", content)
	deps := parseDockerfile(path)
	if len(deps) != 0 {
		t.Errorf("Expected 0 AI dependencies in clean Dockerfile, got %d: %+v", len(deps), deps)
	}
}

// --- Policy Engine Tests ---

func TestLoadPolicyConfig_ParsesCorrectly(t *testing.T) {
	content := `# Test policy
blocked_models:
  - gpt-3.5-turbo
  - "claude-2"
block_on_high_risk: true
require_licenses: true
allowed_licenses:
  - MIT
  - Apache-2.0
`
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, ".aicap.yml"), []byte(content), 0644)
	if err != nil {
		t.Fatal(err)
	}

	policy := loadPolicyConfig(dir)
	if policy == nil {
		t.Fatal("Expected policy to be loaded")
	}

	if len(policy.BlockedModels) != 2 {
		t.Errorf("Expected 2 blocked models, got %d", len(policy.BlockedModels))
	}
	if !policy.BlockOnHighRisk {
		t.Error("Expected block_on_high_risk to be true")
	}
	if !policy.RequireLicenses {
		t.Error("Expected require_licenses to be true")
	}
	if len(policy.AllowedLicenses) != 2 {
		t.Errorf("Expected 2 allowed licenses, got %d", len(policy.AllowedLicenses))
	}
}

func TestLoadPolicyConfig_NoPolicyFile(t *testing.T) {
	dir := t.TempDir()
	policy := loadPolicyConfig(dir)
	if policy != nil {
		t.Error("Expected nil policy when no .aicap.yml exists")
	}
}

func TestEvaluatePolicy_BlocksBlockedModels(t *testing.T) {
	policy := &PolicyConfig{
		BlockedModels: []string{"gpt-3.5-turbo"},
	}
	bom := AIBOM{
		Dependencies: []AIDependency{
			{Name: "Hardcoded Model", Version: "gpt-3.5-turbo", Ecosystem: "Source Code (.py)", RiskLevel: "High"},
			{Name: "Hardcoded Model", Version: "gpt-4", Ecosystem: "Source Code (.py)", RiskLevel: "High"},
		},
	}

	violations := evaluatePolicy(policy, bom)
	if len(violations) != 1 {
		t.Fatalf("Expected 1 violation for blocked model, got %d: %+v", len(violations), violations)
	}
	if violations[0].Rule != "blocked_model" {
		t.Errorf("Expected rule 'blocked_model', got '%s'", violations[0].Rule)
	}
	if violations[0].Severity != "Blocker" {
		t.Errorf("Expected severity 'Blocker', got '%s'", violations[0].Severity)
	}
}

func TestEvaluatePolicy_BlocksHighRisk(t *testing.T) {
	policy := &PolicyConfig{
		BlockOnHighRisk: true,
	}
	bom := AIBOM{
		Dependencies: []AIDependency{
			{Name: "openai", Version: "1.0", RiskLevel: "High"},
			{Name: "scikit-learn", Version: "1.0", RiskLevel: "Low"},
		},
	}

	violations := evaluatePolicy(policy, bom)
	if len(violations) != 1 {
		t.Fatalf("Expected 1 violation (high-risk only), got %d", len(violations))
	}
}

func TestEvaluatePolicy_RequiresLicenses(t *testing.T) {
	policy := &PolicyConfig{
		RequireLicenses: true,
	}
	bom := AIBOM{
		Dependencies: []AIDependency{
			{Name: "openai", Version: "1.0", RiskLevel: "High", License: ""},
			{Name: "openai", Version: "1.0", RiskLevel: "High", License: "MIT"},
			{Name: "flask", Version: "1.0", RiskLevel: "Low", License: ""},
		},
	}

	violations := evaluatePolicy(policy, bom)
	if len(violations) != 1 {
		t.Fatalf("Expected 1 violation (high-risk missing license), got %d: %+v", len(violations), violations)
	}
}

// --- Integration Test: performScan ---

func TestPerformScan_Integration(t *testing.T) {
	files := map[string]string{
		"requirements.txt": "openai==1.12.0\nflask==2.0.1\n",
		"test.py":          `model = "gpt-4-turbo"` + "\n",
	}
	dir := createTempDir(t, files)
	bom := performScan(dir)

	if bom.ScannedFiles < 2 {
		t.Errorf("Expected at least 2 scanned files, got %d", bom.ScannedFiles)
	}
	if len(bom.Dependencies) < 2 {
		t.Errorf("Expected at least 2 dependencies (openai from requirements + gpt-4 from source), got %d", len(bom.Dependencies))
	}
	if bom.Compliance == "Passed" {
		t.Error("Expected compliance to NOT be 'Passed' with high-risk deps")
	}
}

func TestPerformScan_WithPolicyViolations(t *testing.T) {
	files := map[string]string{
		"test.py":     `model = "gpt-4-turbo"` + "\n",
		".aicap.yml": "blocked_models:\n  - gpt-4\n",
	}
	dir := createTempDir(t, files)
	bom := performScan(dir)

	if len(bom.PolicyViolations) == 0 {
		t.Error("Expected policy violations for blocked gpt-4 model")
	}
	if bom.Compliance != "Blocked by Policy" {
		t.Errorf("Expected compliance 'Blocked by Policy', got '%s'", bom.Compliance)
	}
}

// --- AIBOM JSON Serialization ---

func TestAIBOM_JSONSerialization(t *testing.T) {
	bom := AIBOM{
		ProjectName:  "test-project",
		ScannedFiles: 42,
		Dependencies: []AIDependency{
			{Name: "openai", Version: "1.0", Ecosystem: "Python (pip)", RiskLevel: "High"},
		},
		FinOps:           []FinOpsFinding{},
		PolicyViolations: []PolicyViolation{{Rule: "test", Severity: "Warning", Description: "test"}},
		Compliance:       "Passed",
	}

	data, err := json.Marshal(bom)
	if err != nil {
		t.Fatalf("Failed to serialize AIBOM: %v", err)
	}

	var decoded AIBOM
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to deserialize AIBOM: %v", err)
	}

	if decoded.ProjectName != "test-project" {
		t.Errorf("Expected project name 'test-project', got '%s'", decoded.ProjectName)
	}
	if len(decoded.Dependencies) != 1 {
		t.Errorf("Expected 1 dependency, got %d", len(decoded.Dependencies))
	}
	if len(decoded.PolicyViolations) != 1 {
		t.Errorf("Expected 1 policy violation, got %d", len(decoded.PolicyViolations))
	}
}
