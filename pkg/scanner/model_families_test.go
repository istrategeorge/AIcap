package scanner

import (
	"strings"
	"testing"
)

// The catalog these tests guard exists because a flat list of literal
// model names silently stops working when a vendor ships a new
// generation — and "silently" is the problem. A scanner that reports no
// AI components in a codebase full of them writes a false attestation
// into the audit ledger. These cases are the shapes that regression
// would break first.

func TestModelFamilies_AllPatternsCompile(t *testing.T) {
	if len(modelFamilies) == 0 {
		t.Fatal("no model families loaded — the embedded catalog failed to parse")
	}
	for _, fam := range modelFamilies {
		if fam.re == nil {
			t.Errorf("family %q has no compiled pattern", fam.Name)
		}
	}
}

func TestIsTargetModelLiteral_CurrentGenerationModels(t *testing.T) {
	// None of these appear in models.json. Each must still be detected,
	// via its family, or the scanner is blind to current model usage.
	detected := []string{
		"gpt-5",
		"gpt-5-mini",
		"claude-opus-4-5",
		"claude-sonnet-4-5-20250929",
		"anthropic/claude-haiku-4-5",
		"gemini-3-pro",
		"llama-4-scout",
		"meta-llama/Llama-4-Maverick-17B",
		"deepseek-r1",
		"deepseek-v3.1",
		"qwen3-235b",
		"grok-4",
		"mistral-large-2411",
		"command-a-03-2025",
		"phi-4",
		"nova-premier",
		"o3-mini",
	}
	for _, val := range detected {
		if !isTargetModelLiteral(val) {
			t.Errorf("isTargetModelLiteral(%q) = false, want true — a current model went undetected", val)
		}
	}
}

func TestIsTargetModelLiteral_StillRejectsProse(t *testing.T) {
	// Whitespace is the prose signal: real identifiers never contain it.
	// Broadening the matcher to patterns must not broaden it to English.
	prose := []string{
		"expected 2 deps (openai + llama-3 weight), got %d",
		"We migrated from gpt-4 to claude-3 last quarter",
		"failed to load gemini-1.5-pro: %w",
		"",
		"a plain string",
	}
	for _, val := range prose {
		if isTargetModelLiteral(val) {
			t.Errorf("isTargetModelLiteral(%q) = true, want false — prose must not be reported as a hardcoded model", val)
		}
	}
}

func TestIsTargetModelLiteral_NoFalsePositivesOnCommonLiterals(t *testing.T) {
	// Family patterns are broader than a literal list, so this is the
	// guard against the other failure mode: strings that appear
	// constantly in ordinary code being reported as hardcoded models.
	// A compliance report full of noise gets ignored as fast as one full
	// of gaps. Extend this list whenever a family is added.
	benign := []string{
		"application/json", "utf-8", "2024-06-20", "v1.2.3", "localhost:8080",
		"postgres://user:pass@host/db", "text/html;charset=utf-8", "sha256",
		"github.com/lib/pq", "X-Request-ID", "no-cache",
		"alpha-1", "beta-2", "release-3", "worker-1", "node-2", "shard-3",
		"eu-west-1", "fr-par", "us-east-1", "p4d.24xlarge", "g5.xlarge",
		"tab-1", "step-2", "phase-3", "http/1.1", "HTTP/2", "TLSv1.3",
		"--verbose", "/api/v1/users", "id-123", "order-42", "invoice-2024",
	}
	for _, s := range benign {
		if isTargetModelLiteral(s) {
			fam, _ := matchModelFamily(s)
			t.Errorf("false positive: %q matched model family %q", s, fam.Name)
		}
	}
}

func TestMatchModelFamily_AssignsVendorLicense(t *testing.T) {
	cases := map[string]string{
		"gpt-5":             "Proprietary (OpenAI)",
		"claude-opus-4-5":   "Proprietary (Anthropic)",
		"gemini-3-pro":      "Proprietary (Google)",
		"grok-4":            "Proprietary (xAI)",
		"command-a-03-2025": "Proprietary (Cohere)",
	}
	for val, wantLicense := range cases {
		fam, ok := matchModelFamily(val)
		if !ok {
			t.Errorf("matchModelFamily(%q) found no family", val)
			continue
		}
		if fam.License != wantLicense {
			t.Errorf("matchModelFamily(%q).License = %q, want %q", val, fam.License, wantLicense)
		}
	}

	// Open-weight families deliberately carry no licence: the real
	// licence varies per checkpoint, so the report should show a gap (or
	// the live Hugging Face lookup) rather than a guess.
	for _, val := range []string{"llama-4-scout", "qwen3-235b", "deepseek-r1"} {
		fam, ok := matchModelFamily(val)
		if !ok {
			t.Errorf("matchModelFamily(%q) found no family", val)
			continue
		}
		if fam.License != "" {
			t.Errorf("matchModelFamily(%q).License = %q, want empty for an open-weight family", val, fam.License)
		}
	}
}

func TestPerformScan_AssignsFamilyLicenseToHardcodedModel(t *testing.T) {
	dir := createTempDir(t, map[string]string{
		"app.py": "MODEL = \"gpt-5\"\n",
	})

	bom := PerformScan(dir)

	var license string
	for _, d := range bom.Dependencies {
		if d.Name == "Hardcoded Model" && d.Version == "gpt-5" {
			license = d.License
		}
	}
	if license != "Proprietary (OpenAI)" {
		t.Errorf("license for gpt-5 = %q, want Proprietary (OpenAI)", license)
	}
}

func TestLoadModelFamilies_SkipsBadPatternKeepsRest(t *testing.T) {
	original := modelFamilies
	t.Cleanup(func() { modelFamilies = original })

	err := loadModelFamilies([]byte(`{"families":[
	  {"name":"broken","pattern":"([unclosed","vendor":"x","license":""},
	  {"name":"good","pattern":"testmodel-[0-9]+","vendor":"x","license":"Proprietary (X)"}
	]}`))
	if err != nil {
		t.Fatalf("loadModelFamilies returned %v, want nil (one bad pattern must not fail the catalog)", err)
	}
	if len(modelFamilies) != 1 || modelFamilies[0].Name != "good" {
		t.Fatalf("got %#v, want only the compilable family retained", modelFamilies)
	}
	if !isTargetModelLiteral("testmodel-7") {
		t.Error("the surviving family did not take effect")
	}
}

func TestLoadModelFamilies_RejectsMalformedJSON(t *testing.T) {
	original := modelFamilies
	t.Cleanup(func() { modelFamilies = original })

	if err := loadModelFamilies([]byte(`{"families": [`)); err == nil {
		t.Error("loadModelFamilies accepted malformed JSON, want an error")
	}
}

func TestParsePackageJson_DetectsScopedAIPackages(t *testing.T) {
	// The npm ecosystem was entirely absent from the catalog: three JS
	// lockfile parsers existed but every scoped AI package they could
	// find was unknown, so JS/TS projects scanned clean.
	path := createTempFile(t, "package.json", `{
	  "dependencies": {
	    "@anthropic-ai/sdk": "^0.32.0",
	    "ai": "^4.0.0",
	    "@langchain/openai": "^0.3.0",
	    "express": "^4.19.0"
	  }
	}`)

	deps := parsePackageJson(path)

	byName := map[string]bool{}
	for _, d := range deps {
		byName[strings.ToLower(d.Name)] = true
	}
	for _, want := range []string{"@anthropic-ai/sdk", "ai", "@langchain/openai"} {
		if !byName[want] {
			t.Errorf("%q not detected in package.json: %#v", want, deps)
		}
	}
	if byName["express"] {
		t.Error("express should not be reported — it is not an AI library")
	}
}

func TestIsTargetModelLiteral_RejectsPunctuatedFragments(t *testing.T) {
	// A model identifier is a token. Punctuation means the literal is a
	// fragment of code or prose that merely contains a model name.
	//
	// Found in AIcap's own report: the string "(vgpt-5)" — lifted from a
	// test assertion in this repo — was detected as a component and
	// rendered as "Hardcoded Model ((vgpt-5))". The whitespace guard did
	// not catch it because the fragment has none.
	fragments := []string{
		"(vgpt-5)",
		"(gpt-4)",
		"model=gpt-4",
		"gpt-4-%s",
		`"gpt-4"`,
		"gpt-4,claude-3",
		"[gpt-4]",
		"{gpt-4}",
		"<gpt-4>",
		"gpt-4;",
		"gpt-4|claude-3",
	}
	for _, f := range fragments {
		if isTargetModelLiteral(f) {
			t.Errorf("isTargetModelLiteral(%q) = true — punctuated fragments are not identifiers", f)
		}
	}
}

func TestIsTargetModelLiteral_KeepsRealIdentifierShapes(t *testing.T) {
	// The tightening must not cost any legitimate identifier form:
	// vendor prefixes, date suffixes, file paths, tags.
	identifiers := []string{
		"gpt-5",
		"gpt-4o-2024-08-06",
		"claude-3-opus-20240229",
		"anthropic/claude-haiku-4-5",
		"meta-llama/Meta-Llama-3-8B",
		"mistralai/Mixtral-8x7B-v0.1",
		"models/llama-3-8b.gguf",
		"deepseek-v3.1",
		"o3-mini",
	}
	for _, id := range identifiers {
		if !isTargetModelLiteral(id) {
			t.Errorf("isTargetModelLiteral(%q) = false — a real identifier was rejected", id)
		}
	}
}
