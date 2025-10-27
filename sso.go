package sso

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
