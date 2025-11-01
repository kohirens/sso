package google

import (
	"github.com/kohirens/sso"
	"regexp"
	"testing"
)

// TestNewState Check that unique session tokens meet expectations
// Samples:
// cdff558e-f23a-46a2-9be4-0c586549d8ce
func TestNewState(t *testing.T) {
	cases := []struct {
		name string
		uri  string
	}{
		{"tokenonly", ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := sso.NewState()

			re := regexp.MustCompile(`^[a-f0-9-]{36,}$`)
			if !re.MatchString(got) {
				t.Errorf("NewState() = %v, is not a valid unique session token", got)
				return
			}
		})
	}
}

// TestNewStateWith Check that unique session tokens meet expectations
// Samples:
// security_token%3D90bd70cc-1bd7-4ccc-818a-7aeae9414195url%3Dhttps%3A%2F%2Fexample.com%2Foauth-2-callback
func TestNewStateWith(t *testing.T) {
	cases := []struct {
		name string
		uri  string
	}{
		{"tokenonly", ""},
		{"tokenonly", "https://example.com/oauth-2-callback"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := NewStateWith(c.uri)
			re := regexp.MustCompile(`^[a-zA-Z0-9-_%.]{36,}$`)

			if !re.MatchString(got) {
				t.Errorf("NewState() = %v, is not a valid unique session token", got)
				return
			}
		})
	}
}
