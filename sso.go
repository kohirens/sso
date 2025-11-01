package sso

import "github.com/google/uuid"

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

type Token interface{}

const (
	SessionTokenGoogle = "__gp__"
	SessionTokenApple  = "__ap__"
)

// NewState Generates an anti-forgery unique session token.
func NewState() string {
	return uuid.New().String()
}

// NewNonce A random value generated that enables replay protection.
func NewNonce() string {
	return uuid.New().String()
}
