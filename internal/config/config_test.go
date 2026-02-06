package config

import (
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg == nil {
		t.Fatal("DefaultConfig() returned nil")
	}

	// Check defaults are sensible
	if cfg.ScanInterval != 5*time.Minute {
		t.Errorf("ScanInterval = %v, want 5m", cfg.ScanInterval)
	}

	// Indicators should be enabled by default
	if !cfg.Indicators.SystemBinaries {
		t.Error("SystemBinaries should be enabled by default")
	}
	if !cfg.Indicators.LaunchAgents {
		t.Error("LaunchAgents should be enabled by default")
	}
	if !cfg.Indicators.LaunchDaemons {
		t.Error("LaunchDaemons should be enabled by default")
	}
	if !cfg.Indicators.SSHKeys {
		t.Error("SSHKeys should be enabled by default")
	}

	// Local notification should be enabled
	if !cfg.Alerts.LocalNotification {
		t.Error("LocalNotification should be enabled by default")
	}

	// Response actions should include alert
	if len(cfg.Response.OnCritical) == 0 {
		t.Error("OnCritical should have default actions")
	}
	if len(cfg.Response.OnWarning) == 0 {
		t.Error("OnWarning should have default actions")
	}
}

func TestConfigPath(t *testing.T) {
	path := ConfigPath()

	if path == "" {
		t.Error("ConfigPath() returned empty string")
	}

	// Should end with config.yaml
	if len(path) < 11 || path[len(path)-11:] != "config.yaml" {
		t.Errorf("ConfigPath() should end with config.yaml, got %s", path)
	}
}

func TestIndicatorConfigDefaults(t *testing.T) {
	cfg := DefaultConfig()

	// All major indicator types should be enabled by default
	indicators := cfg.Indicators

	if !indicators.SystemBinaries {
		t.Error("SystemBinaries should default to true")
	}
	if !indicators.LaunchAgents {
		t.Error("LaunchAgents should default to true")
	}
	if !indicators.LaunchDaemons {
		t.Error("LaunchDaemons should default to true")
	}
	if !indicators.BrowserExtensions {
		t.Error("BrowserExtensions should default to true")
	}
	if !indicators.SSHKeys {
		t.Error("SSHKeys should default to true")
	}
	if !indicators.EtcFiles {
		t.Error("EtcFiles should default to true")
	}

	// Custom paths should be empty by default
	if len(indicators.CustomPaths) != 0 {
		t.Error("CustomPaths should be empty by default")
	}
}

func TestAlertConfigDefaults(t *testing.T) {
	cfg := DefaultConfig()
	alerts := cfg.Alerts

	// Clawdbot should be disabled by default (requires configuration)
	if alerts.Clawdbot.Enabled {
		t.Error("Clawdbot should be disabled by default")
	}

	// Slack should be disabled by default
	if alerts.Slack.Enabled {
		t.Error("Slack should be disabled by default")
	}

	// Local notification should be enabled
	if !alerts.LocalNotification {
		t.Error("LocalNotification should be enabled by default")
	}
}

func TestResponseConfigDefaults(t *testing.T) {
	cfg := DefaultConfig()
	response := cfg.Response

	// Critical should have alert action
	hasAlert := false
	for _, action := range response.OnCritical {
		if action == "alert" {
			hasAlert = true
			break
		}
	}
	if !hasAlert {
		t.Error("OnCritical should include 'alert' action")
	}

	// Warning should have alert action
	hasAlert = false
	for _, action := range response.OnWarning {
		if action == "alert" {
			hasAlert = true
			break
		}
	}
	if !hasAlert {
		t.Error("OnWarning should include 'alert' action")
	}

	// Info should have log action
	hasLog := false
	for _, action := range response.OnInfo {
		if action == "log" {
			hasLog = true
			break
		}
	}
	if !hasLog {
		t.Error("OnInfo should include 'log' action")
	}
}
