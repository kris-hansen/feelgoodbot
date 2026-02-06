package indicators

import (
	"os"
	"path/filepath"
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
		if filepath.HasPrefix(ind.Path, home) {
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
