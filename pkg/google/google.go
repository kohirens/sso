package google

import (
	"fmt"
	"github.com/kohirens/stdlib/logger"
	"github.com/kohirens/www/storage"
	"net/http"
	"os"
)

const (
	envOIDCAuthURI      = "GOOGLE_OIDC_AUTH_URI"
	envOIDCCertURL      = "GOOGLE_OIDC_AUTH_PROVIDER_X509_CERT_URL"
	envOIDCClientID     = "GOOGLE_OIDC_CLIENT_ID"
	envOIDCClientSecret = "GOOGLE_OIDC_CLIENT_SECRET"
	envOIDCProjectID    = "GOOGLE_OIDC_PROJECT_ID"
	envOIDCTokenURI     = "GOOGLE_OIDC_TOKEN_URI"
	envOIDCRedirectURIs = "GOOGLE_OIDC_REDIRECT_URIS"
	envDiscoverDocURL   = "GOOGLE_DISCOVERY_DOC_URL"

	keyDiscoveryDoc = "google_discovery_document"
	keyCertificate  = "google_certificate"
)

// HttpClient Methods needed to make HTTP request.
type HttpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Session An session manager to be compatible with this library.
type Session interface {
	// Get Return any data previously stored by this library.
	Get(key string) []byte
	// Remove Delete any data previously stored by this library.
	Remove(key string) error
	// Set Save any data this library will need to retrieve at a later time.
	// This should persist across request, for example HTTP request.
	Set(key string, value []byte)
}

// Log A logger that follows the Kohirens standard of logging; where a human
// comprehensible error message is treated as equal to an error code. Having
// either one should point directly to where to problem in the code lies. In
// fact the error code can be omitted if so desired.
var Log = &logger.Standard{}

// NewAuth Provider Authentication object using credentials found in the
// environment.
//
//	Will look for:
//	  GOOGLE_OIDC_CLIENT_ID
//	  GOOGLE_OIDC_CLIENT_SECRET
//	  GOOGLE_OIDC_REDIRECT_URIS
func NewAuth() (*OAuth2, error) {
	clientID, ok1 := os.LookupEnv(envOIDCClientID)
	if !ok1 {
		return nil, fmt.Errorf(stderr.MissEnvVar, envOIDCClientID)
	}

	clientSecret, ok2 := os.LookupEnv(envOIDCClientSecret)
	if !ok2 {
		return nil, fmt.Errorf(stderr.MissEnvVar, envOIDCClientSecret)
	}

	redirectURI := os.Getenv(envOIDCRedirectURIs)
	if redirectURI == "" {
		return nil, fmt.Errorf(stderr.MissEnvVar, envOIDCRedirectURIs)
	}

	return &OAuth2{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURI:  redirectURI,
	}, nil
}

// NewProvider Initialize a Google OIDC provider to authenticate a client
// requesting access to your application.
func NewProvider(client HttpClient, store storage.Storage, session Session, prefix string) (*Provider, error) {
	oauth2, e1 := NewAuth()
	if e1 != nil {
		return nil, e1
	}

	projectID := os.Getenv(envOIDCProjectID)
	if projectID == "" {
		return nil, fmt.Errorf(stderr.MissEnvVar, envOIDCProjectID)
	}

	gp := &Provider{
		DiscoveryDoc: &DiscoverDoc{},
		ProjectID:    projectID,
		OAuth2:       oauth2,
		Scopes:       []string{"openid", "profile", "email"},
		State:        NewStateWith(oauth2.RedirectURI),
		client:       client,
		session:      session,
		store:        store,
		Prefix:       prefix,
	}

	if e := gp.LoadDiscoveryDoc(); e != nil {
		return gp, e
	}

	if e := gp.LoadCertificate(); e != nil {
		return gp, e
	}

	return gp, nil
}
