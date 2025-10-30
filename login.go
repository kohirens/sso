package sso

import (
	"fmt"
	"github.com/mileusna/useragent"
)

type LoginInfo struct {
	AccountID    string
	Devices      map[string]*Device `json:"devices"`
	Email        string
	ClientID     string      `json:"google_id"`
	RefreshToken interface{} `json:"refresh_token"`
}

// LookupDevice Search for the device in the login information.
func (li *LoginInfo) LookupDevice(deviceID, sessionID, userAgent string) (*Device, error) {
	points := 0
	// Lookup the device, otherwise treat it as a new device.
	device, found := li.Devices[deviceID]
	if !found {
		return nil, fmt.Errorf("%v", "Device not found")
	}

	// Compare User Agent to validate it is the same device.
	dua := device.UserAgent
	ua := useragent.Parse(userAgent)
	if dua.Device != ua.Device || dua.OSVersion != ua.OSVersion || dua.Name != ua.Name {
		// this is a new device
		return nil, fmt.Errorf("device has bad signature, tampering suspected")
	}

	// TODO: what to do if session does not match.
	if sessionID == device.SessionID {
		points++
	}
	return device, nil
}
