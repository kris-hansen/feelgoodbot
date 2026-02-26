//go:build darwin && cgo

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
)

const DistributedNotificationName = "com.feelgoodbot.alert"

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
