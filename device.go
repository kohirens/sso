package sso

import (
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/mileusna/useragent"
)

type Device struct {
	ID           string              `json:"id"`
	OIDCProvider string              `json:"oidc_provider"`
	SessionID    string              `json:"session_id"`
	UserAgent    useragent.UserAgent `json:"user_agent"`
}

func DeviceId(userAgent []byte) string {
	id := uuid.NewSHA1(uuid.NameSpaceOID, userAgent)
	return id.String()
}

func NewDevice(userAgent []byte, sessionID, oidcProvider string) (*Device, error) {
	var ua useragent.UserAgent
	if e := json.Unmarshal(userAgent, &ua); e != nil {
		return nil, fmt.Errorf(stderr.DecodeJSON, e.Error())
	}

	return &Device{
		ID:           DeviceId(userAgent),
		OIDCProvider: oidcProvider,
		SessionID:    sessionID,
		UserAgent:    ua,
	}, nil
}
