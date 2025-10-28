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
