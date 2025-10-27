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

type Device struct {
	ID        string `json:"id"`
	SessionID string `json:"session_id"`
}

type LoginInfo struct {
	RefreshToken interface{}        `json:"refresh_token"`
	Devices      map[string]*Device `json:"devices"`
	GoogleID     string             `json:"google_id"`
	Email        string
}

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
