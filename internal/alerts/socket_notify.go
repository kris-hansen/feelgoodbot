package alerts

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"time"
)

const socketName = "feelgoodbot.sock"

// SendToConsoleSocket sends alert to the console via Unix socket
func SendToConsoleSocket(alert DistributedAlert) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	socketPath := filepath.Join(home, ".config", "feelgoodbot", socketName)

	// Check if socket exists
	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		return nil // Console not running, that's OK
	}

	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		return nil // Console not available, that's OK
	}
	defer conn.Close()

	payload, err := json.Marshal(alert)
	if err != nil {
		return err
	}

	// Write payload followed by newline
	_, err = conn.Write(append(payload, '\n'))
	return err
}
