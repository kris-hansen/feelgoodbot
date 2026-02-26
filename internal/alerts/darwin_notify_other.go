//go:build !darwin || !cgo

package alerts

// PostDistributedNotification is a no-op on non-darwin or when cgo is disabled
func PostDistributedNotification(alert DistributedAlert) error {
	return nil
}
