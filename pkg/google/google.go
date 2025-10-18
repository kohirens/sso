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

	keyDiscoveryDoc = "google_discovery_document.json"
	keyCertificate  = "google_certificate.json"
)

type HttpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type Session interface {
	Get(key string) []byte
	Remove(key string) error
	Set(key string, value []byte)
}

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
func NewProvider(client HttpClient, store storage.Storage) (*Provider, error) {
	oauth2, e1 := NewAuth()
	if e1 != nil {
		return nil, e1
	}

	projectID := os.Getenv(envOIDCProjectID)
	if projectID == "" {
		return nil, fmt.Errorf(stderr.MissEnvVar, envOIDCProjectID)
	}

	return &Provider{
		DiscoveryDoc: &DiscoverDoc{},
		ProjectID:    projectID,
		OAuth2:       oauth2,
		Scopes:       []string{"openid", "profile", "email"},
		State:        NewStateWith(oauth2.RedirectURI),
		client:       client,
		store:        store,
	}, nil
}
