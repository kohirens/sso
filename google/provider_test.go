package google

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/kohirens/sso/oidc"
	"github.com/kohirens/stdlib/test"
	"github.com/kohirens/storage"
)

const (
	fixtureDir = "testdata"
	tmpDir     = "tmp"
)

func TestMain(m *testing.M) {
	test.ResetDir(tmpDir, 0777)

	os.Exit(m.Run())
}
func fixtureStore() (storage.Storage, error) {
	_ = os.MkdirAll(tmpDir+"/"+prefixProvider, os.ModePerm)
	store, e1 := storage.NewLocalStorage(tmpDir)
	if e1 != nil {
		return nil, e1
	}
	return store, nil
}
func TestProvider_ExchangeCodeForToken(t *testing.T) {
	b, _ := os.ReadFile(fixtureDir + "/google_discovery_document.json")
	fixedDiscovery := &DiscoveryDoc{}
	_ = json.Unmarshal(b, fixedDiscovery)
	emptyDiscovery := &DiscoveryDoc{}

	tests := []struct {
		name      string
		state     string
		code      string
		envs      map[string]string
		client    oidc.HttpClient
		discovery *DiscoveryDoc
		wantErr   bool
	}{
		{
			"unknown",
			"abc",
			"xyz",
			nil,
			nil,
			nil,
			true,
		},
		{
			"env_oidc_token_uri_not_set",
			"abcdefghijklmnopqrstuvwxyz1234",
			"xyz",
			nil,
			nil,
			emptyDiscovery,
			true,
		},
		{
			"good_token_uri",
			"abcdefghijklmnopqrstuvwxyz1234",
			"xyz",
			map[string]string{
				"GOOGLE_OIDC_TOKEN_URI":     "https://test.local/oauth2/v3/token",
				"GOOGLE_OIDC_CLIENT_ID":     "testid",
				"GOOGLE_OIDC_CLIENT_SECRET": "1234",
				"GOOGLE_OIDC_REDIRECT_URIS": "https://test.local/callback",
			},
			&test.MockHttpClient{
				DoHandler: func(r *http.Request) (*http.Response, error) {
					b, _ := os.ReadFile(fixtureDir + "/test-token-01.json")
					return &http.Response{
						Body:       io.NopCloser(bytes.NewReader(b)),
						StatusCode: 200,
					}, nil
				},
			},
			fixedDiscovery,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Provider{
				State:        tt.state,
				client:       tt.client,
				DiscoveryDoc: tt.discovery,
			}
			if tt.envs != nil {
				for k, v := range tt.envs {
					t.Setenv(k, v)
				}
			}

			creds, e1 := NewAuth()
			if e1 == nil {
				p.OAuth2 = creds
			}
			err := p.ExchangeCodeForToken(tt.state, tt.code)

			if (err != nil) != tt.wantErr {
				t.Errorf("ExchangeCodeForToken() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
