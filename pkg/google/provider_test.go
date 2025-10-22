package google

import (
	jwt "github.com/kohirens/json-web-token"
	"github.com/kohirens/stdlib/fsio"
	"github.com/kohirens/stdlib/test"
	"github.com/kohirens/www/storage"
	"os"
	"testing"
)

const (
	tmpDir = "tmp"
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
		fields  fields
		state   string
		code    string
		wantErr bool
	}{
		{
			"unknown",
			fields{},
			"abc",
			"xyz",
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Provider{
				Code:         tt.fields.Code,
				DiscoveryDoc: tt.fields.DiscoveryDoc,
				Hd:           tt.fields.Hd,
				JWKs:         tt.fields.JWKs,
				OAuth2:       tt.fields.OAuth2,
				ProjectID:    tt.fields.ProjectID,
				Scopes:       tt.fields.Scopes,
				State:        tt.fields.State,
				Token:        tt.fields.Token,
				client:       tt.fields.client,
				session:      tt.fields.session,
				store:        tt.fields.store,
			}
			if err := p.ExchangeCodeForToken(tt.state, tt.code); (err != nil) != tt.wantErr {
				t.Errorf("ExchangeCodeForToken() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestProvider_SaveLoginInfo(t *testing.T) {
	fixedStore, _ := storage.NewLocalStorage(tmpDir)

	tests := []struct {
		name         string
		prefix       string
		makePrefix   bool
		Token        *Token
		Store        storage.Storage
		expectedFile string
		wantErr      bool
	}{
		{
			"save_location_does_not_exist",
			"logins",
			false,
			&Token{
				info: &jwt.Info{
					Payload: jwt.ClaimSet{
						"sub": "should-not-save",
					},
				},
			},
			fixedStore,
			"",
			true,
		},
		{
			"good",
			"logins",
			true,
			&Token{
				info: &jwt.Info{
					Payload: jwt.ClaimSet{
						"sub": "save-login-info-good",
					},
				},
			},
			fixedStore,
			tmpDir + "/logins/save-login-info-good",
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

			if tt.makePrefix {
				_ = os.MkdirAll(tmpDir+"/"+tt.prefix, 0777)
			}

			// Run and assert.
			if err := p.SaveLoginInfo(tt.prefix); (err != nil) != tt.wantErr {
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
