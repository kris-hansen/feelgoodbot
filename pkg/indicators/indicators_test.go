package indicators

import (
	"os"
	"strings"
	"testing"
)

func TestDefaultIndicators(t *testing.T) {
	indicators := DefaultIndicators()

	if len(indicators) == 0 {
		t.Fatal("DefaultIndicators() returned empty list")
	}

	// Check that we have indicators for key categories
	categories := make(map[string]bool)
	for _, ind := range indicators {
		categories[ind.Category] = true
	}

	requiredCategories := []string{
		"system_binaries",
		"persistence",
		"privilege_escalation",
		"ssh",
		"shell_config",
	}

	for _, cat := range requiredCategories {
		if !categories[cat] {
			t.Errorf("missing required category: %s", cat)
		}
	}
}

func TestDefaultIndicatorsHaveRequiredFields(t *testing.T) {
	indicators := DefaultIndicators()

	for _, ind := range indicators {
		if ind.Path == "" {
			t.Error("found indicator with empty path")
		}
		if ind.Description == "" {
			t.Errorf("indicator %s has empty description", ind.Path)
		}
		if ind.Category == "" {
			t.Errorf("indicator %s has empty category", ind.Path)
		}
	}
}

func TestDefaultIndicatorsExpandHome(t *testing.T) {
	indicators := DefaultIndicators()
	home, _ := os.UserHomeDir()

	// Check that at least some paths are expanded
	foundHomePath := false
	for _, ind := range indicators {
		if len(ind.Path) > 0 && ind.Path[0] != '/' && ind.Path[0] != '~' {
			continue // relative path
		}
		if strings.HasPrefix(ind.Path, home) {
			foundHomePath = true
			break
		}
	}

	if !foundHomePath && home != "" {
		t.Error("expected some paths to be expanded to home directory")
	}
}

func TestGetIndicatorsByCategory(t *testing.T) {
	sshIndicators := GetIndicatorsByCategory("ssh")

	if len(sshIndicators) == 0 {
		t.Fatal("GetIndicatorsByCategory(ssh) returned empty list")
	}

	for _, ind := range sshIndicators {
		if ind.Category != "ssh" {
			t.Errorf("expected category 'ssh', got %q", ind.Category)
		}
	}
}

func TestGetIndicatorsByNonexistentCategory(t *testing.T) {
	indicators := GetIndicatorsByCategory("nonexistent_category_xyz")

	if len(indicators) != 0 {
		t.Errorf("expected empty list for nonexistent category, got %d", len(indicators))
	}
}

func TestGetCriticalIndicators(t *testing.T) {
	critical := GetCriticalIndicators()

	if len(critical) == 0 {
		t.Fatal("GetCriticalIndicators() returned empty list")
	}

	for _, ind := range critical {
		if ind.Severity != Critical {
			t.Errorf("expected severity Critical, got %d for %s", ind.Severity, ind.Path)
		}
	}
}

func TestCategories(t *testing.T) {
	categories := Categories()

	if len(categories) == 0 {
		t.Fatal("Categories() returned empty list")
	}

	// Check for expected categories
	expected := map[string]bool{
		"system_binaries":      false,
		"persistence":          false,
		"privilege_escalation": false,
		"ssh":                  false,
	}

	for _, cat := range categories {
		if _, ok := expected[cat]; ok {
			expected[cat] = true
		}
	}

	for cat, found := range expected {
		if !found {
			t.Errorf("missing expected category: %s", cat)
		}
	}
}

func TestCriticalPathsAreCritical(t *testing.T) {
	indicators := DefaultIndicators()

	// Paths that MUST be critical
	mustBeCritical := []string{
		"/usr/bin",
		"/usr/sbin",
		"/Library/LaunchDaemons",
		"/Library/LaunchAgents",
		"/etc/sudoers",
	}

	indicatorMap := make(map[string]Indicator)
	for _, ind := range indicators {
		indicatorMap[ind.Path] = ind
	}

	for _, path := range mustBeCritical {
		ind, ok := indicatorMap[path]
		if !ok {
			t.Errorf("missing critical path: %s", path)
			continue
		}
		if ind.Severity != Critical {
			t.Errorf("path %s should be Critical, got %d", path, ind.Severity)
		}
	}
}

func TestSeverityConstants(t *testing.T) {
	// Verify severity ordering
	if Info >= Warning {
		t.Error("Info should be less than Warning")
	}
	if Warning >= Critical {
		t.Error("Warning should be less than Critical")
	}
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected Severity
	}{
		{"critical", Critical},
		{"CRITICAL", Critical},
		{"Critical", Critical},
		{"warning", Warning},
		{"WARNING", Warning},
		{"info", Info},
		{"INFO", Info},
		{"unknown", Info}, // defaults to Info
		{"", Info},
	}

	for _, tc := range tests {
		result := ParseSeverity(tc.input)
		if result != tc.expected {
			t.Errorf("ParseSeverity(%q) = %d, want %d", tc.input, result, tc.expected)
		}
	}
}

func TestSeverityString(t *testing.T) {
	tests := []struct {
		sev      Severity
		expected string
	}{
		{Critical, "critical"},
		{Warning, "warning"},
		{Info, "info"},
	}

	for _, tc := range tests {
		result := tc.sev.String()
		if result != tc.expected {
			t.Errorf("Severity(%d).String() = %q, want %q", tc.sev, result, tc.expected)
		}
	}
}

func TestCustomIndicatorToIndicator(t *testing.T) {
	custom := CustomIndicator{
		Path:        "~/test/path",
		Description: "Test description",
		Severity:    "critical",
		Recursive:   true,
		Category:    "custom",
	}

	ind := custom.ToIndicator()

	if !strings.HasSuffix(ind.Path, "/test/path") {
		t.Errorf("expected path to end with /test/path, got %s", ind.Path)
	}
	if ind.Description != "Test description" {
		t.Errorf("expected description 'Test description', got %s", ind.Description)
	}
	if ind.Severity != Critical {
		t.Errorf("expected severity Critical, got %d", ind.Severity)
	}
	if !ind.Recursive {
		t.Error("expected recursive to be true")
	}
	if ind.Category != "custom" {
		t.Errorf("expected category 'custom', got %s", ind.Category)
	}
}

func TestCustomIndicatorExpandsHome(t *testing.T) {
	home, _ := os.UserHomeDir()

	custom := CustomIndicator{
		Path: "~/test",
	}

	ind := custom.ToIndicator()

	if !strings.HasPrefix(ind.Path, home) {
		t.Errorf("expected path to start with %s, got %s", home, ind.Path)
	}
}

func TestMergeIndicators(t *testing.T) {
	defaults := []Indicator{
		{Path: "/default/path1", Description: "Default 1"},
		{Path: "/default/path2", Description: "Default 2"},
	}

	customs := []CustomIndicator{
		{Path: "/custom/path1", Description: "Custom 1", Severity: "critical"},
	}

	merged := MergeIndicators(defaults, customs)

	if len(merged) != 3 {
		t.Errorf("expected 3 indicators, got %d", len(merged))
	}
}

func TestClawdbotIndicatorsExist(t *testing.T) {
	indicators := DefaultIndicators()

	// Check that Clawdbot indicators exist
	foundSoul := false
	foundAgents := false
	foundConfig := false
	foundSkills := false

	for _, ind := range indicators {
		if strings.Contains(ind.Path, "clawd/SOUL.md") {
			foundSoul = true
			if ind.Severity != Critical {
				t.Error("SOUL.md should be Critical severity")
			}
		}
		if strings.Contains(ind.Path, "clawd/AGENTS.md") {
			foundAgents = true
			if ind.Severity != Critical {
				t.Error("AGENTS.md should be Critical severity")
			}
		}
		if strings.Contains(ind.Path, "clawdbot/config.yaml") {
			foundConfig = true
			if ind.Severity != Critical {
				t.Error("clawdbot config.yaml should be Critical severity")
			}
		}
		if strings.Contains(ind.Path, "clawd/skills") {
			foundSkills = true
			if ind.Severity != Critical {
				t.Error("clawd/skills should be Critical severity")
			}
		}
	}

	if !foundSoul {
		t.Error("missing Clawdbot SOUL.md indicator")
	}
	if !foundAgents {
		t.Error("missing Clawdbot AGENTS.md indicator")
	}
	if !foundConfig {
		t.Error("missing Clawdbot config.yaml indicator")
	}
	if !foundSkills {
		t.Error("missing Clawdbot skills indicator")
	}
}

func TestAIAgentsCategoryIncludesClawdbot(t *testing.T) {
	aiAgents := GetIndicatorsByCategory("ai_agents")

	foundClawdbot := false
	for _, ind := range aiAgents {
		if strings.Contains(ind.Path, "clawd") || strings.Contains(ind.Path, "clawdbot") {
			foundClawdbot = true
			break
		}
	}

	if !foundClawdbot {
		t.Error("ai_agents category should include Clawdbot indicators")
	}
}
