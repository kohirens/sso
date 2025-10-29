package google

import (
	"bytes"
	jwt "github.com/kohirens/json-web-token"
	"github.com/kohirens/sso"
	"github.com/kohirens/stdlib/fsio"
	"github.com/kohirens/stdlib/test"
	"github.com/kohirens/www/storage"
	"io"
	"net/http"
	"os"
	"testing"
)

const (
	fixtureDir = "testdata"
	tmpDir     = "tmp"
)

func TestMain(m *testing.M) {
	test.ResetDir(tmpDir, 0777)

	os.Exit(m.Run())
}

func TestProvider_ExchangeCodeForToken(t *testing.T) {
	type fields struct {
		Code         string
		DiscoveryDoc *DiscoverDoc
		Hd           string
		JWKs         *JwksUriv3
		OAuth2       *OAuth2
		ProjectID    string
		Scopes       []string
		State        string
		Token        *Token
		client       HttpClient
		session      Session
		store        storage.Storage
	}
	tests := []struct {
		name    string
		state   string
		code    string
		envs    map[string]string
		client  HttpClient
		wantErr bool
	}{
		{
			"unknown",
			"abc",
			"xyz",
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
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Provider{
				//Code:         tt.Code,
				//DiscoveryDoc: tt.DiscoveryDoc,
				//Hd:           tt.Hd,
				//JWKs:         tt.JWKs,
				//OAuth2:       tt.OAuth2,
				//ProjectID:    tt.ProjectID,
				//Scopes:       tt.Scopes,
				State: tt.state,
				//Token:        tt.Token,
				client: tt.client,
				//session:      tt.session,
				//store:        tt.store,
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

func TestProvider_SaveLoginInfo(t *testing.T) {
	fixedStore, _ := storage.NewLocalStorage(tmpDir)

	tests := []struct {
		name         string
		makePrefix   bool
		Token        *Token
		Store        storage.Storage
		expectedFile string
		wantErr      bool
	}{
		{
			"save_location_does_not_exist",
			false,
			&Token{
				info: &jwt.Info{
					Payload: jwt.ClaimSet{
						"sub":   "should-not-save",
						"email": "test@example.com",
					},
				},
			},
			fixedStore,
			"",
			true,
		},
		{
			"good",
			true,
			&Token{
				info: &jwt.Info{
					Payload: jwt.ClaimSet{
						"sub":   "save-login-info-good",
						"email": "test@example.com",
					},
				},
			},
			fixedStore,
			tmpDir + "/logins/save-login-info-good.json",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			p := &Provider{
				Token: tt.Token,
				store: tt.Store,
				loginInfo: &sso.LoginInfo{
					CurrentDeviceID: "1234",
					ClientID:        "4321",
					Devices:         make(map[string]*sso.Device),
				},
			}

			if tt.makePrefix {
				_ = os.MkdirAll(tmpDir+"/logins", 0777)
			}

			// Run and assert.
			if err := p.SaveLoginInfo(); (err != nil) != tt.wantErr {
				t.Errorf("SaveLoginInfo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.makePrefix && !fsio.Exist(tt.expectedFile) {
				t.Errorf("SaveLoginInfo() did not save login info")
				return
			}
		})
	}
}

func TestProvider_LoadLoginInfo(t *testing.T) {
	ps := string(os.PathSeparator)
	_ = fsio.CopyDirToDir(fixtureDir+ps+"logins", tmpDir+ps+"logins", ps, os.FileMode(0777))
	fixedStore, _ := storage.NewLocalStorage(tmpDir)

	tests := []struct {
		name         string
		Token        *Token
		Store        storage.Storage
		expectedFile string
		deviceID     string
		wantID       string
		wantErr      bool
	}{
		{
			"account_not_found",
			&Token{
				info: &jwt.Info{
					Payload: jwt.ClaimSet{
						"sub": "account-not-found",
					},
				},
			},
			fixedStore,
			"",
			"",
			"",
			true,
		},
		{
			"good",
			&Token{
				info: &jwt.Info{
					Payload: jwt.ClaimSet{
						"sub":   "load-login-info-good",
						"email": "test@exmaple.com",
					},
				},
			},
			fixedStore,
			tmpDir + "/logins/load-login-info-good.json",
			"84779adf-91d2-50a4-bffe-ddd2f43b6c53",
			"load-login-info-good",
			false,
		},
		{
			"malformed-json",
			&Token{
				info: &jwt.Info{
					Payload: jwt.ClaimSet{
						"sub": "bad-login-info-good",
					},
				},
			},
			fixedStore,
			"",
			"",
			"",
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			p := &Provider{
				Token: tt.Token,
				store: tt.Store,
			}

			// Run and assert.
			err := p.UpdateLoginInfo(tt.deviceID, "4321", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36")
			if (err != nil) != tt.wantErr {
				t.Errorf("loadLoginInfo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if p.loginInfo != nil && p.loginInfo.ClientID != tt.wantID {
				t.Errorf("loadLoginInfo() incorrect info")
				return
			}
		})
	}
}

func TestProvider_RegisterLoginInfo(t *testing.T) {
	ps := string(os.PathSeparator)
	_ = fsio.CopyDirToDir(fixtureDir+ps+"logins", tmpDir+ps+"logins", ps, os.FileMode(0777))
	fixedStore, _ := storage.NewLocalStorage(tmpDir)

	tests := []struct {
		name         string
		Token        *Token
		Store        storage.Storage
		expectedFile string
		sessionID    string
		userAgent    string
		wantID       string
		wantErr      bool
	}{
		{
			"good",
			&Token{
				info: &jwt.Info{
					Payload: jwt.ClaimSet{
						"sub":   "load-login-info-good",
						"email": "test@exmaple.com",
					},
				},
			},
			fixedStore,
			tmpDir + "/logins/load-login-info-good.json",
			"session_id_4321",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
			"load-login-info-good",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			p := &Provider{
				Token: tt.Token,
				store: tt.Store,
			}

			// Run and assert.
			err := p.RegisterLoginInfo(tt.sessionID, tt.userAgent)
			if (err != nil) != tt.wantErr {
				t.Errorf("loadLoginInfo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && p.loginInfo.ClientID != tt.wantID {
				t.Errorf("loadLoginInfo() incorrect info")
				return
			}
		})
	}
}
