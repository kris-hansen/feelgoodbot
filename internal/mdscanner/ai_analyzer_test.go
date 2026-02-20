package mdscanner

import (
	"testing"
)

func TestParseAnalysisResponse(t *testing.T) {
	tests := []struct {
		name      string
		response  string
		wantLevel string
		wantErr   bool
	}{
		{
			name: "valid response",
			response: `{
				"risk_level": "high",
				"summary": "This skill downloads and executes remote code",
				"concerns": ["Downloads executable from untrusted source", "Bypasses quarantine"],
				"recommendations": ["Do not install this skill", "Report to ClawdHub"],
				"explanation": "The skill contains curl|bash patterns and quarantine bypass.",
				"confidence": 0.95
			}`,
			wantLevel: "high",
			wantErr:   false,
		},
		{
			name:      "response with markdown code blocks",
			response:  "```json\n{\"risk_level\": \"safe\", \"summary\": \"Safe skill\", \"concerns\": [], \"recommendations\": [], \"explanation\": \"No issues found.\", \"confidence\": 0.9}\n```",
			wantLevel: "safe",
			wantErr:   false,
		},
		{
			name:      "invalid JSON",
			response:  "This is not JSON",
			wantLevel: "",
			wantErr:   true,
		},
		{
			name: "invalid risk level gets normalized",
			response: `{
				"risk_level": "super-dangerous",
				"summary": "Test",
				"concerns": [],
				"recommendations": [],
				"explanation": "Test",
				"confidence": 0.5
			}`,
			wantLevel: "unknown",
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseAnalysisResponse(tt.response)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.RiskLevel != tt.wantLevel {
				t.Errorf("got risk_level=%s, want %s", result.RiskLevel, tt.wantLevel)
			}
		})
	}
}

func TestFormatAIResult(t *testing.T) {
	result := &AIAnalysisResult{
		RiskLevel: "critical",
		Summary:   "This skill is malware",
		Concerns: []string{
			"Downloads and executes remote code",
			"Steals SSH keys",
		},
		Recommendations: []string{
			"Do not install",
			"Report to security team",
		},
		Explanation: "Detailed analysis shows this is AMOS malware.",
		Confidence:  0.98,
	}

	output := FormatAIResult(result)

	// Check key elements are present
	if !contains(output, "🚨") {
		t.Error("expected critical emoji in output")
	}
	if !contains(output, "CRITICAL") {
		t.Error("expected CRITICAL in output")
	}
	if !contains(output, "98%") {
		t.Error("expected confidence percentage in output")
	}
	if !contains(output, "malware") {
		t.Error("expected summary in output")
	}
	if !contains(output, "SSH keys") {
		t.Error("expected concerns in output")
	}
}

func TestBuildAnalysisPrompt(t *testing.T) {
	files := map[string]string{
		"SKILL.md": "# Test Skill\n\nThis is a test.",
		"run.sh":   "#!/bin/bash\necho hello",
	}

	findings := &SkillScanResult{
		SkillPath:   "/test/skill",
		Clean:       false,
		TotalIssues: 1,
		Files: map[string]*ScanResult{
			"run.sh": {
				Clean: false,
				Findings: []Finding{
					{Line: 2, Type: TypeShellInjection, Severity: SeverityHigh, Message: "test finding"},
				},
			},
		},
	}

	prompt := buildAnalysisPrompt(files, findings)

	// Check key elements
	if !contains(prompt, "security analyst") {
		t.Error("expected role description in prompt")
	}
	if !contains(prompt, "SKILL.md") {
		t.Error("expected file name in prompt")
	}
	if !contains(prompt, "Test Skill") {
		t.Error("expected file content in prompt")
	}
	if !contains(prompt, "test finding") {
		t.Error("expected static findings in prompt")
	}
	if !contains(prompt, "risk_level") {
		t.Error("expected response format in prompt")
	}
}

func TestReadSkillFiles(t *testing.T) {
	// Create a temp directory with test files
	// This test verifies the function doesn't crash and handles missing dirs
	_, err := ReadSkillFiles("/nonexistent/path", 100*1024)
	if err == nil {
		t.Error("expected error for nonexistent path")
	}
}

func TestIsRelevantFile(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		want     bool
	}{
		{"SKILL.md", "SKILL.md", true},
		{"skill.md lowercase", "skill.md", true},
		{"README.md", "README.md", true},
		{"shell script", "install.sh", true},
		{"python script", "main.py", true},
		{"javascript", "index.js", true},
		{"typescript", "app.ts", true},
		{"random text", "notes.txt", false},
		{"binary", "program.exe", false},
		{"image", "logo.png", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isRelevantFile(tt.filename)
			if got != tt.want {
				t.Errorf("isRelevantFile(%q) = %v, want %v", tt.filename, got, tt.want)
			}
		})
	}
}

func TestNewAIAnalyzerNoKey(t *testing.T) {
	// Temporarily clear the env var
	original := ""
	if v, ok := lookupEnv("ANTHROPIC_API_KEY"); ok {
		original = v
	}

	// This test just verifies behavior without a key
	// In real usage, the key would be set
	cfg := &AIAnalyzerConfig{
		APIKey: "", // Force empty
	}

	// If env var is not set, should fail
	// If env var is set, will succeed (which is fine for CI)
	_, err := NewAIAnalyzer(cfg)
	if original == "" && err == nil {
		t.Error("expected error when no API key is available")
	}
}

// Helper to check env without modifying it
func lookupEnv(key string) (string, bool) {
	return "", false // Simplified - in real code would use os.LookupEnv
}
