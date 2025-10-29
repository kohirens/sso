package sso

import (
	"github.com/google/uuid"
	"github.com/mileusna/useragent"
	"time"
)

type Device struct {
	ID           string               `json:"id"`
	LastActivity time.Time            `json:"last_activity"`
	OIDCProvider string               `json:"oidc_provider"`
	SessionID    string               `json:"session_id"`
	UserAgent    *useragent.UserAgent `json:"user_agent"`
}

func DeviceId(userAgent []byte) string {
	id := uuid.NewSHA1(uuid.NameSpaceOID, userAgent)
	return id.String()
}

func NewDevice(userAgent string, sessionID, oidcProvider string) *Device {
	ua := useragent.Parse(userAgent)
	return &Device{
		ID:           DeviceId([]byte(userAgent)),
		OIDCProvider: oidcProvider,
		SessionID:    sessionID,
		UserAgent:    &ua,
	}
}
