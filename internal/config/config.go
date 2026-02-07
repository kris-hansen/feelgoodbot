// Package config manages feelgoodbot configuration
package config

import (
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/viper"
)

// Config represents the application configuration
type Config struct {
	Indicators   IndicatorConfig `mapstructure:"indicators"`
	ScanInterval time.Duration   `mapstructure:"scan_interval"`
	Alerts       AlertConfig     `mapstructure:"alerts"`
	Response     ResponseConfig  `mapstructure:"response"`
}

// IndicatorConfig configures what to monitor
type IndicatorConfig struct {
	SystemBinaries    bool     `mapstructure:"system_binaries"`
	LaunchAgents      bool     `mapstructure:"launch_agents"`
	LaunchDaemons     bool     `mapstructure:"launch_daemons"`
	BrowserExtensions bool     `mapstructure:"browser_extensions"`
	SSHKeys           bool     `mapstructure:"ssh_keys"`
	EtcFiles          bool     `mapstructure:"etc_files"`
	CustomPaths       []string `mapstructure:"custom_paths"`
}

// AlertConfig configures alert destinations
type AlertConfig struct {
	Clawdbot struct {
		Enabled bool   `mapstructure:"enabled"`
		Webhook string `mapstructure:"webhook"`
		Secret  string `mapstructure:"secret"`
		To      string `mapstructure:"to"`
	} `mapstructure:"clawdbot"`

	Slack struct {
		Enabled    bool   `mapstructure:"enabled"`
		WebhookURL string `mapstructure:"webhook_url"`
	} `mapstructure:"slack"`

	LocalNotification bool `mapstructure:"local_notification"`
}

// ResponseConfig configures response actions
type ResponseConfig struct {
	OnCritical []string `mapstructure:"on_critical"`
	OnWarning  []string `mapstructure:"on_warning"`
	OnInfo     []string `mapstructure:"on_info"`
}

// DefaultConfig returns sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Indicators: IndicatorConfig{
			SystemBinaries:    true,
			LaunchAgents:      true,
			LaunchDaemons:     true,
			BrowserExtensions: true,
			SSHKeys:           true,
			EtcFiles:          true,
			CustomPaths:       []string{},
		},
		ScanInterval: 5 * time.Minute,
		Alerts: AlertConfig{
			LocalNotification: true,
		},
		Response: ResponseConfig{
			OnCritical: []string{"alert"},
			OnWarning:  []string{"alert"},
			OnInfo:     []string{"log"},
		},
	}
}

// Load reads configuration from file
func Load() (*Config, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	configDir := filepath.Join(home, ".config", "feelgoodbot")
	configFile := filepath.Join(configDir, "config.yaml")

	// Create default config if doesn't exist
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		if err := os.MkdirAll(configDir, 0700); err != nil {
			return nil, err
		}
		return DefaultConfig(), nil
	}

	viper.SetConfigFile(configFile)
	viper.SetConfigType("yaml")

	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}

	cfg := DefaultConfig()
	if err := viper.Unmarshal(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// ConfigPath returns the path to the config file
func ConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "feelgoodbot", "config.yaml")
}
