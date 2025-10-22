package sso

import (
	jwt "github.com/kohirens/json-web-token"
	"github.com/kohirens/sso/pkg/google"
	"testing"
)

type MockStorage struct{}

func TestClientID(t *testing.T) {
	fixTokenID, _ := jwt.Token(jwt.ClaimSet{"alg": "HS256"}, jwt.ClaimSet{"sub": "10769150350006150715113082367"}, []byte("none"))
	//mockHttp := &test.MockHttpClient{}
	//mockStorage := &MockStorage{}

	cases := []struct {
		name string
		p    OIDCProvider
		want string
	}{
		{
			name: "consistent",
			p: &google.Provider{
				ProjectID: "test-app",
				Token:     &google.Token{IDToken: fixTokenID},
				OAuth2:    nil,
				Scopes:    nil,
				State:     "",
				Code:      "",
			},
			want: "10769150350006150715113082367",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			//p, _ := &google.NewGoogleProvider(mockHttp, mockStorage)
			if got := c.p.ClientID(); got != c.want {
				t.Errorf("ClientID() = %v, want %v", got, c.want)
				return
			}
		})
	}
}
