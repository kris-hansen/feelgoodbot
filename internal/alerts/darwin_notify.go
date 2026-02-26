//go:build darwin

package alerts

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Foundation
#import <Foundation/Foundation.h>

void postDistributedNotification(const char* name, const char* jsonPayload) {
    NSString *notificationName = [NSString stringWithUTF8String:name];
    NSString *payload = [NSString stringWithUTF8String:jsonPayload];

    NSDictionary *userInfo = @{@"payload": payload};

    [[NSDistributedNotificationCenter defaultCenter]
        postNotificationName:notificationName
        object:nil
        userInfo:userInfo
        deliverImmediately:YES];
}
*/
import "C"

import (
	"encoding/json"
	"unsafe"

	"github.com/kris-hansen/feelgoodbot/internal/scanner"
)

const DistributedNotificationName = "com.feelgoodbot.alert"

// DistributedAlert is the payload sent via Darwin notifications
type DistributedAlert struct {
	Timestamp string              `json:"timestamp"`
	Severity  string              `json:"severity"` // critical, warning, info
	Changes   []DistributedChange `json:"changes"`
}

type DistributedChange struct {
	Path     string `json:"path"`
	Type     string `json:"type"` // modified, added, deleted
	Category string `json:"category"`
	Severity string `json:"severity"`
}

// PostDistributedNotification sends an alert via macOS distributed notifications
func PostDistributedNotification(alert DistributedAlert) error {
	payload, err := json.Marshal(alert)
	if err != nil {
		return err
	}

	cName := C.CString(DistributedNotificationName)
	cPayload := C.CString(string(payload))
	defer C.free(unsafe.Pointer(cName))
	defer C.free(unsafe.Pointer(cPayload))

	C.postDistributedNotification(cName, cPayload)
	return nil
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
