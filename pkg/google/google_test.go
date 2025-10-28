package google

import (
	jwt "github.com/kohirens/json-web-token"
	"testing"
	"time"
)

func TestGoogleProvider_Authenticated(t *testing.T) {
	oldTime := time.Now().Add(-5 * time.Minute)
	cases := []struct {
		name  string
		Token *Token
		want  bool
	}{
		{
			"good-token",
			&Token{
				ExpiresIn: int(time.Now().Add(5 * time.Minute).Unix()),
			},
			true,
		},
		{
			"expired-token",
			&Token{
				Exp: &oldTime,
			},
			false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gp := &Provider{
				Token: c.Token,
			}

			if got := gp.Authenticated(); got != c.want {
				t.Errorf("Authenticated() = %v, want %v", got, c.want)
				return
			}
		})
	}
}

func TestClientID(t *testing.T) {
	fixTokenID, _ := jwt.Token(jwt.ClaimSet{"alg": "HS256"}, jwt.ClaimSet{"sub": "10769150350006150715113082367"}, []byte("none"))

	cases := []struct {
		name string
		p    *Provider
		want string
	}{
		{
			name: "consistent",
			p: &Provider{
				ProjectID: "test-app",
				Token:     &Token{IDToken: fixTokenID},
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
