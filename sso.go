package sso

import (
	"github.com/kohirens/stdlib/logger"
)

type OIDCProvider interface {
	// AuthLink Generate a link, when clicked, send the browser to where a user
	// can consent to authenticate with the provider.
	AuthLink(loginHint string) (string, error)
	// Name ID of the OIDC application registered with the provider
	Name() string
	// ClientEmail Address of the client that is logged in.
	ClientEmail() string
	// ClientID Make an ID unique to the client.
	ClientID() string
}

type SessionManager interface {
	Get(key string) []byte
	Remove(string) error
}

const (
	SessionTokenGoogle = "__gp__"
	SessionTokenApple  = "__ap__"
)

var Log = logger.Standard{}
