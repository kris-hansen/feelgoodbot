package alerts

import (
	"github.com/kris-hansen/feelgoodbot/internal/scanner"
)

// DistributedAlert is the payload sent via Darwin notifications and console socket
type DistributedAlert struct {
	Timestamp string              `json:"timestamp"`
	Severity  string              `json:"severity"` // critical, warning, info
	Changes   []DistributedChange `json:"changes"`
}

// DistributedChange represents a single file change in an alert
type DistributedChange struct {
	Path     string `json:"path"`
	Type     string `json:"type"` // modified, added, deleted
	Category string `json:"category"`
	Severity string `json:"severity"`
}

// ConvertToDistributedAlert converts an internal Alert to a DistributedAlert
func ConvertToDistributedAlert(alert Alert) DistributedAlert {
	da := DistributedAlert{
		Timestamp: alert.Timestamp.Format("2006-01-02T15:04:05-07:00"),
		Severity:  "info",
	}

	for _, c := range alert.Changes {
		change := DistributedChange{
			Path:     c.Path,
			Type:     string(c.Type),
			Category: c.Category,
			Severity: c.Severity.String(),
		}
		da.Changes = append(da.Changes, change)

		// Set overall severity to highest found
		if c.Severity == scanner.SeverityCritical {
			da.Severity = "critical"
		} else if c.Severity == scanner.SeverityWarning && da.Severity != "critical" {
			da.Severity = "warning"
		}
	}

	return da
}
