package google

import (
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/kohirens/json-web-token"
	"io"
	"net/url"
	"time"
)

type OAuth2 struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
}

type Token struct {
	AccessToken  string `json:"access_token"`            // AccessToken A token that can be sent to a Google API.
	ExpiresIn    int    `json:"expires_in"`              // ExpiresIn The remaining lifetime of the access token in seconds.
	IDToken      string `json:"id_token"`                // IDToken A JWT that contains identity information about the user that is digitally signed by Google.
	Scope        string `json:"scope"`                   // Scope The scopes of access granted by the access_token expressed as a list of space-delimited, case-sensitive strings.
	TokenType    string `json:"token_type"`              // TokenType Identifies the type of token returned. At this time, this field always has the value Bearer.
	RefreshToken string `json:"refresh_token,omitempty"` // RefreshToken (optional) This field is only present if the access_type parameter was set to offline in the authentication request. For details, see Refresh tokens.
	info         *jwt.Info
	Exp          *time.Time
}

func (t *Token) Expired() bool {
	return t.Exp != nil && t.Exp.Before(time.Now().UTC())
}

// IDTokenInfo Convert the ID token string into code we can use to extract
// values that will be used to validate it.
// NOTE: This is NOT what performs validation, but aids in the process.
func (t *Token) IDTokenInfo() (*jwt.Info, error) {
	if t.info == nil {
		info, e1 := jwt.Parse(t.IDToken)
		if e1 != nil {
			return nil, e1
		}
		t.info = info
	}
	return t.info, nil
}

// Validate This token after retrieving, for details see:
// https://developers.google.com/identity/openid-connect/openid-connect#validatinganidtoken
func (t *Token) Validate() bool {

	// Verify that the ID token is properly signed by the issuer. Google-issued tokens are signed using one of the certificates found at the URI specified in the jwks_uri metadata value of the Discovery document.
	// Verify that the value of the iss claim in the ID token is equal to https://accounts.google.com or accounts.google.com.
	if t.IDToken != "https://accounts.google.com" && t.IDToken != "accounts.google.com" {
		return false
	}
	// Verify that the value of the aud claim in the ID token is equal to your app's client ID.
	// Verify that the expiry time (exp claim) of the ID token has not passed.
	return t.Expired()
}

// NewState Generates an anti-forgery unique session token.
func NewState() string {
	return uuid.New().String()
}

// NewStateWith Generates an anti-forgery unique session token, along with the
// URI needed to recover the context when the user returns to your application
// Read more at state:
// https://developers.google.com/identity/openid-connect/openid-connect#state-param
func NewStateWith(uri string) string {
	state := fmt.Sprintf("security_token=%vurl=%v", NewState(), uri)

	return url.QueryEscape(state)
}

// NewNonce A random value generated that enables replay protection.
func NewNonce() string {
	return uuid.New().String()
}

// loadToken Convert token data to a Token.
func loadToken(rc io.ReadCloser) (*Token, error) {
	resBody, e2 := io.ReadAll(rc)
	if e2 != nil {
		return nil, fmt.Errorf(stderr.ReadResponse, e2.Error())
	}

	token := &Token{}
	if e := json.Unmarshal(resBody, token); e != nil {
		return nil, fmt.Errorf(stderr.DecodeJSON, e.Error())
	}

	exp := time.Now().UTC().Add(time.Duration(token.ExpiresIn) * time.Second)
	token.Exp = &exp

	return token, nil
}
