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

var Log = &logger.Standard{}

type HttpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

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

// NewGoogleProvider configure a Google OIDC provider to authenticate a HttpClient.
func NewGoogleProvider(client HttpClient, store storage.Storage) (*Provider, error) {
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
		store:        store,
	}

	return gp, nil
}
