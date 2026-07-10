package oidc

type Provider interface {
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
	// UserInfo provided basic user information such as first and last name,
	// email, and phone.
	UserInfo() *UserInfo
	// String convert to JSON output for serialization.
	String() string
}
