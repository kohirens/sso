package oidc

import "net/http"

// Provider the API your application uses to prevent getting too specific with
// one provider, afforing it the opportunity to easily add/removing providers
// as needed.
// TODO: Think about removing ClientEmail and ClientID now that we have UserInfo.
type Provider interface {
	// AuthLink Generate a link, when clicked, send the browser to where a user
	// can consent to authenticate with the provider.
	AuthLink(loginHint string) (string, error)
	Callback(r *http.Request) error
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
	UserInfo() UserInfo
	// String convert to JSON output for serialization.
	String() string
}
