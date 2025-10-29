package sso

import (
	"fmt"
	"github.com/mileusna/useragent"
)

type LoginInfo struct {
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

type OIDCProvider interface {
	// AuthLink Generate a link, when clicked, send the browser to where a user
	// can consent to authenticate with the provider.
	AuthLink(loginHint string) (string, error)
	// Name of the provider.
	Name() string
	// Application ID of the OIDC application registered with the provider
	Application() string
	// ClientEmail Address of the client that is logged in.
	ClientEmail() string
	// ClientID Make an ID unique to the client.
	ClientID() string
	// SignOut Sign out of the OIDC provider.
	SignOut() error
}

type SessionManager interface {
	Get(key string) []byte
	Remove(key string) error
	Set(key string, value []byte)
}

const (
	SessionTokenGoogle = "__gp__"
	SessionTokenApple  = "__ap__"
)
