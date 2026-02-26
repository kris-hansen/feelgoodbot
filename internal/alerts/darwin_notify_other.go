//go:build !darwin

package alerts

type DistributedAlert struct {
	Timestamp string              `json:"timestamp"`
	Severity  string              `json:"severity"`
	Changes   []DistributedChange `json:"changes"`
}

type DistributedChange struct {
	Path     string `json:"path"`
	Type     string `json:"type"`
	Category string `json:"category"`
	Severity string `json:"severity"`
}

func PostDistributedNotification(alert DistributedAlert) error {
	return nil // No-op on non-darwin
}

func ConvertToDistributedAlert(alert Alert) DistributedAlert {
	return DistributedAlert{}
}
