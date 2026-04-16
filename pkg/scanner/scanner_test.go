package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aicap/pkg/compliance"
	"aicap/pkg/types"
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
	content := `package scanner

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
	content := `package scanner

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
	content := `package scanner

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

func TestComplianceLoadPolicyConfig_ParsesCorrectly(t *testing.T) {
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

	policy := compliance.LoadPolicyConfig(dir)
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

func TestComplianceLoadPolicyConfig_NoPolicyFile(t *testing.T) {
	dir := t.TempDir()
	policy := compliance.LoadPolicyConfig(dir)
	if policy != nil {
		t.Error("Expected nil policy when no .aicap.yml exists")
	}
}

func TestComplianceEvaluatePolicy_BlocksBlockedModels(t *testing.T) {
	policy := &types.PolicyConfig{
		BlockedModels: []string{"gpt-3.5-turbo"},
	}
	bom := types.AIBOM{
		Dependencies: []types.AIDependency{
			{Name: "Hardcoded Model", Version: "gpt-3.5-turbo", Ecosystem: "Source Code (.py)", RiskLevel: "High"},
			{Name: "Hardcoded Model", Version: "gpt-4", Ecosystem: "Source Code (.py)", RiskLevel: "High"},
		},
	}

	violations := compliance.EvaluatePolicy(policy, bom)
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

func TestComplianceEvaluatePolicy_BlocksHighRisk(t *testing.T) {
	policy := &types.PolicyConfig{
		BlockOnHighRisk: true,
	}
	bom := types.AIBOM{
		Dependencies: []types.AIDependency{
			{Name: "openai", Version: "1.0", RiskLevel: "High"},
			{Name: "scikit-learn", Version: "1.0", RiskLevel: "Low"},
		},
	}

	violations := compliance.EvaluatePolicy(policy, bom)
	if len(violations) != 1 {
		t.Fatalf("Expected 1 violation (high-risk only), got %d", len(violations))
	}
}

func TestComplianceEvaluatePolicy_RequiresLicenses(t *testing.T) {
	policy := &types.PolicyConfig{
		RequireLicenses: true,
	}
	bom := types.AIBOM{
		Dependencies: []types.AIDependency{
			{Name: "openai", Version: "1.0", RiskLevel: "High", License: ""},
			{Name: "openai", Version: "1.0", RiskLevel: "High", License: "MIT"},
			{Name: "flask", Version: "1.0", RiskLevel: "Low", License: ""},
		},
	}

	violations := compliance.EvaluatePolicy(policy, bom)
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
	bom := PerformScan(dir)

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
	bom := PerformScan(dir)

	if len(bom.PolicyViolations) == 0 {
		t.Error("Expected policy violations for blocked gpt-4 model")
	}
	if bom.Compliance != "Blocked by Policy" {
		t.Errorf("Expected compliance 'Blocked by Policy', got '%s'", bom.Compliance)
	}
}

// --- types.AIBOM JSON Serialization ---

func TestAIBOM_JSONSerialization(t *testing.T) {
	bom := types.AIBOM{
		ProjectName:  "test-project",
		ScannedFiles: 42,
		Dependencies: []types.AIDependency{
			{Name: "openai", Version: "1.0", Ecosystem: "Python (pip)", RiskLevel: "High"},
		},
		FinOps:           []types.FinOpsFinding{},
		PolicyViolations: []types.PolicyViolation{{Rule: "test", Severity: "Warning", Description: "test"}},
		Compliance:       "Passed",
	}

	data, err := json.Marshal(bom)
	if err != nil {
		t.Fatalf("Failed to serialize types.AIBOM: %v", err)
	}

	var decoded types.AIBOM
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to deserialize types.AIBOM: %v", err)
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

// --- parseTerraformFile Tests ---

func TestParseTerraformFile_DetectsAWSGPUInstances(t *testing.T) {
	content := `resource "aws_instance" "training" {
  ami           = "ami-0abcdef"
  instance_type = "p4d.24xlarge"
}
`
	path := createTempFile(t, "main.tf", content)
	findings := parseTerraformFile(path)

	if len(findings) == 0 {
		t.Fatal("Expected at least 1 FinOps finding for p4d GPU instance")
	}

	found := false
	for _, f := range findings {
		if strings.Contains(f.Description, "AWS") && strings.Contains(f.Description, "A100") {
			found = true
		}
	}
	if !found {
		t.Error("Expected AWS A100 GPU finding for p4d instance")
	}
}

func TestParseTerraformFile_DetectsSpotPricing(t *testing.T) {
	content := `resource "aws_instance" "training" {
  instance_type = "g5.xlarge"
  capacity_type = "spot"
}
`
	path := createTempFile(t, "main.tf", content)
	findings := parseTerraformFile(path)

	for _, f := range findings {
		if strings.Contains(f.Description, "g5") && f.Severity != "Info" {
			t.Errorf("Expected Info severity for spot instance, got '%s'", f.Severity)
		}
	}
}

func TestParseTerraformFile_NoGPU(t *testing.T) {
	content := `resource "aws_instance" "web" {
  ami           = "ami-0abcdef"
  instance_type = "t3.micro"
}
`
	path := createTempFile(t, "main.tf", content)
	findings := parseTerraformFile(path)
	if len(findings) != 0 {
		t.Errorf("Expected 0 findings for non-GPU instance, got %d", len(findings))
	}
}

func TestParseTerraformFile_DetectsAzureGPU(t *testing.T) {
	content := `resource "azurerm_virtual_machine" "gpu" {
  vm_size = "Standard_NC6s_v3"
}
`
	path := createTempFile(t, "azure.tf", content)
	findings := parseTerraformFile(path)
	if len(findings) == 0 {
		t.Fatal("Expected Azure GPU finding for Standard_NC instance")
	}
}

// --- CycloneDX Tests ---

func TestComplianceGenerateCycloneDXBOM_ValidFormat(t *testing.T) {
	bom := types.AIBOM{
		ProjectName: "test-project",
		CommitSha:   "abc123",
		Dependencies: []types.AIDependency{
			{Name: "openai", Version: "1.12.0", Ecosystem: "Python (pip)", RiskLevel: "High", License: "MIT"},
			{Name: "Hardcoded Model", Version: "gpt-4", Ecosystem: "Source Code (.py)", RiskLevel: "High"},
		},
	}

	cdx := compliance.GenerateCycloneDXBOM(bom)

	if cdx.BOMFormat != "CycloneDX" {
		t.Errorf("Expected bomFormat 'CycloneDX', got '%s'", cdx.BOMFormat)
	}
	if cdx.SpecVersion != "1.5" {
		t.Errorf("Expected specVersion '1.5', got '%s'", cdx.SpecVersion)
	}
	if len(cdx.Components) != 2 {
		t.Fatalf("Expected 2 components, got %d", len(cdx.Components))
	}
	if cdx.Metadata.Component.Name != "test-project" {
		t.Errorf("Expected metadata component name 'test-project', got '%s'", cdx.Metadata.Component.Name)
	}
}

func TestComplianceGenerateCycloneDXBOM_HasPURL(t *testing.T) {
	bom := types.AIBOM{
		Dependencies: []types.AIDependency{
			{Name: "openai", Version: "1.12.0", Ecosystem: "Python (pip)"},
			{Name: "langchain", Version: "0.1.5", Ecosystem: "Node.js (npm)"},
			{Name: "go-openai", Version: "1.20.4", Ecosystem: "Go (module)"},
		},
	}

	cdx := compliance.GenerateCycloneDXBOM(bom)

	purls := map[string]string{}
	for _, comp := range cdx.Components {
		purls[comp.Name] = comp.PURL
	}

	if purls["openai"] != "pkg:pypi/openai@1.12.0" {
		t.Errorf("Expected PyPI PURL, got '%s'", purls["openai"])
	}
	if purls["langchain"] != "pkg:npm/langchain@0.1.5" {
		t.Errorf("Expected npm PURL, got '%s'", purls["langchain"])
	}
	if purls["go-openai"] != "pkg:golang/go-openai@1.20.4" {
		t.Errorf("Expected Go PURL, got '%s'", purls["go-openai"])
	}
}

func TestComplianceClassifyComponentType(t *testing.T) {
	tests := []struct {
		dep      types.AIDependency
		expected string
	}{
		{types.AIDependency{Ecosystem: "Model Weight (.safetensors)"}, "machine-learning-model"},
		{types.AIDependency{Ecosystem: "Container Image (Dockerfile)"}, "machine-learning-model"},
		{types.AIDependency{Name: "Exposed Secret", Ecosystem: "Source Code (.py)"}, "data"},
		{types.AIDependency{Name: "openai", Ecosystem: "Python (pip)"}, "library"},
	}

	for _, tt := range tests {
		result := compliance.ClassifyComponentType(tt.dep)
		if result != tt.expected {
			t.Errorf("compliance.ClassifyComponentType(%s) = '%s', want '%s'", tt.dep.Name, result, tt.expected)
		}
	}
}

// --- Enhanced Annex IV Tests ---

func TestComplianceGenerateAnnexIVMarkdown_ContainsAllSections(t *testing.T) {
	bom := types.AIBOM{
		ProjectName:  "test-project",
		CommitSha:    "abc123",
		ScannedFiles: 10,
		Dependencies: []types.AIDependency{
			{Name: "openai", Version: "1.0", Ecosystem: "Python (pip)", RiskLevel: "High", License: "MIT"},
			{Name: "Exposed Secret", Version: "HIDDEN", Ecosystem: "Source Code (.py)", RiskLevel: "High"},
		},
		FinOps: []types.FinOpsFinding{
			{Resource: "main.tf", Severity: "Warning", Description: "GPU detected"},
		},
		PolicyViolations: []types.PolicyViolation{
			{Rule: "test_rule", Severity: "Warning", Description: "test violation", Location: "test.py:1"},
		},
		Compliance: "Action Required",
	}

	md := compliance.GenerateAnnexIVMarkdown(bom)

	requiredSections := []string{
		"Annex IV Technical Documentation",
		"General System Description",
		"System Architecture",
		"Licensing Compliance Summary",
		"Hardware Requirements",
		"Risk Management",
		"Automated Risk Register",
		"Policy-as-Code Compliance",
		"CI/CD Pipeline Controls",
		"Human Oversight",
		"Immutable Compliance Proof",
		"Components with license data",
		"CRITICAL",
	}

	for _, section := range requiredSections {
		if !strings.Contains(md, section) {
			t.Errorf("Annex IV markdown missing required section: '%s'", section)
		}
	}
}

// --- Python Import Detection Tests ---

func TestParsePythonSource_DetectsImportStatements(t *testing.T) {
	content := `import torch
from langchain.llms import OpenAI
import os
`
	path := createTempFile(t, "app.py", content)
	deps := parsePythonSource(path)

	importedLibs := map[string]bool{}
	for _, d := range deps {
		if d.Ecosystem == "Source Code (.py import)" {
			importedLibs[d.Name] = true
		}
	}

	if !importedLibs["torch"] {
		t.Error("Expected to detect 'import torch'")
	}
	if !importedLibs["langchain"] {
		t.Error("Expected to detect 'from langchain import'")
	}
}

func TestParsePythonSource_DeduplicatesImports(t *testing.T) {
	content := `import torch
import torch
from torch import nn
`
	path := createTempFile(t, "dup.py", content)
	deps := parsePythonSource(path)

	importCount := 0
	for _, d := range deps {
		if d.Ecosystem == "Source Code (.py import)" && d.Name == "torch" {
			importCount++
		}
	}
	if importCount > 1 {
		t.Errorf("Expected deduplicated imports, got %d 'torch' import detections", importCount)
	}
}

// --- parseEnvFile Tests ---

func TestParseEnvFile_DetectsOpenAIKey(t *testing.T) {
	content := `# API Keys
DATABASE_URL=postgres://localhost/db
OPENAI_API_KEY=sk-1234567890abcdefghijklmnop
PORT=8080
`
	path := createTempFile(t, ".env", content)
	deps := parseEnvFile(path)

	if len(deps) == 0 {
		t.Fatal("Expected to detect OpenAI API key in .env")
	}

	hasOpenAI := false
	for _, d := range deps {
		if strings.Contains(d.Description, "OpenAI") {
			hasOpenAI = true
		}
	}
	if !hasOpenAI {
		t.Error("Expected OpenAI platform detection in .env")
	}
}

func TestParseEnvFile_SkipsPlaceholders(t *testing.T) {
	content := `OPENAI_API_KEY=your-key-here
HF_TOKEN=${HF_TOKEN}
ANTHROPIC_API_KEY=<replace-with-your-key>
`
	path := createTempFile(t, ".env", content)
	deps := parseEnvFile(path)

	if len(deps) != 0 {
		t.Errorf("Expected 0 findings for placeholder values, got %d: %+v", len(deps), deps)
	}
}

func TestParseEnvFile_DetectsMultiplePlatforms(t *testing.T) {
	content := `OPENAI_API_KEY=sk-abc1234567890abcdefghijk
HF_TOKEN=hf_abc1234567890abcdefghijk
WANDB_API_KEY=wand_1234567890abcdefghijk
`
	path := createTempFile(t, ".env", content)
	deps := parseEnvFile(path)

	if len(deps) < 2 {
		t.Errorf("Expected at least 2 secret findings, got %d", len(deps))
	}
}

func TestParseEnvFile_CleanFile(t *testing.T) {
	content := `PORT=8080
DATABASE_URL=postgres://localhost/db
DEBUG=true
`
	path := createTempFile(t, ".env", content)
	deps := parseEnvFile(path)
	if len(deps) != 0 {
		t.Errorf("Expected 0 findings in clean .env, got %d", len(deps))
	}
}

// --- Helm Values Tests ---

func TestParseHelmValues_DetectsGPUWithoutAutoscaling(t *testing.T) {
	content := `replicaCount: 2

resources:
  limits:
    nvidia.com/gpu: 1
    memory: "16Gi"
`
	path := createTempFile(t, "values.yaml", content)
	findings := parseHelmValues(path)

	if len(findings) == 0 {
		t.Fatal("Expected FinOps finding for GPU without autoscaling")
	}

	found := false
	for _, f := range findings {
		if f.Severity == "Warning" && strings.Contains(f.Description, "GPU") {
			found = true
		}
	}
	if !found {
		t.Error("Expected Warning severity for GPU without autoscaling")
	}
}

func TestParseHelmValues_DetectsGPUWithAutoscaling(t *testing.T) {
	content := `resources:
  limits:
    nvidia.com/gpu: 1

autoscaling:
  enabled: true
  minReplicas: 1
  maxReplicas: 4
`
	path := createTempFile(t, "values.yaml", content)
	findings := parseHelmValues(path)

	for _, f := range findings {
		if strings.Contains(f.Description, "GPU") && f.Severity != "Info" {
			t.Errorf("Expected Info severity when autoscaling is configured, got '%s'", f.Severity)
		}
	}
}

func TestParseHelmValues_DetectsModelServing(t *testing.T) {
	content := `image: nvcr.io/nvidia/tritonserver:23.10-py3
modelRepository: /models
`
	path := createTempFile(t, "values.yaml", content)
	findings := parseHelmValues(path)

	found := false
	for _, f := range findings {
		if strings.Contains(f.Description, "model serving") {
			found = true
		}
	}
	if !found {
		t.Error("Expected model serving detection for tritonserver config")
	}
}

// --- OWASP ML Risk Enrichment Tests ---

func TestComplianceEnrichWithOWASPRisks_AddsAnnotations(t *testing.T) {
	bom := types.AIBOM{
		Dependencies: []types.AIDependency{
			{Name: "openai", Version: "1.0", Description: "External LLM API Call (OpenAI)"},
			{Name: "langchain", Version: "0.1", Description: "LLM Orchestration Framework"},
			{Name: "flask", Version: "3.0", Description: "Web Framework"},
		},
	}

	compliance.EnrichWithOWASPRisks(&bom)

	if !strings.Contains(bom.Dependencies[0].Description, "OWASP") {
		t.Error("Expected OWASP annotation on openai dependency")
	}
	if !strings.Contains(bom.Dependencies[0].Description, "ML06") {
		t.Error("Expected ML06 (Supply Chain Attacks) for openai")
	}
	if !strings.Contains(bom.Dependencies[1].Description, "ML01") {
		t.Error("Expected ML01 (Input Manipulation) for langchain")
	}
	if strings.Contains(bom.Dependencies[2].Description, "OWASP") {
		t.Error("Flask should not have OWASP ML annotations")
	}
}

func TestComplianceEnrichWithOWASPRisks_NoDuplicateAnnotations(t *testing.T) {
	bom := types.AIBOM{
		Dependencies: []types.AIDependency{
			{Name: "openai", Version: "1.0", Description: "Already has OWASP ML annotation"},
		},
	}

	compliance.EnrichWithOWASPRisks(&bom)
	compliance.EnrichWithOWASPRisks(&bom) // call twice

	count := strings.Count(bom.Dependencies[0].Description, "OWASP")
	if count > 1 {
		t.Errorf("Expected no duplicate OWASP annotations, got %d occurrences", count)
	}
}




