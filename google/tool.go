package google

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"time"

	"github.com/kohirens/sso/oidc"
)

func LoadJwksUriv3(data []byte) (*JwksUriv3, error) {
	cert := &JwksUriv3{}

	if e := json.Unmarshal(data, cert); e != nil {
		return nil, fmt.Errorf(stderr.DecodeJSON, e.Error())
	}

	cert.rawBytes = data

	return cert, nil
}

// NewStateWith Generates an anti-forgery unique session token, along with the
// URI needed to recover the context when the user returns to your application
// Read more at state:
// https://developers.google.com/identity/openid-connect/openid-connect#state-param
func NewStateWith(uri string) string {
	state := fmt.Sprintf("security_token=%vurl=%v", oidc.State(), uri)

	return url.QueryEscape(state)
}

// ParseRSAPublicKeys Convert JWK structures into keys. This is meant to handle
// certs in the format that Google jwks_uri v3 returns.
func ParseRSAPublicKeys(certs []*JWK) ([]*rsa.PublicKey, error) {
	keys := make([]*rsa.PublicKey, len(certs))
	for i, key := range certs {
		n := make([]byte, base64.RawURLEncoding.DecodedLen(len(key.N)))
		e := make([]byte, base64.RawURLEncoding.DecodedLen(len(key.E)))

		_, e1 := base64.RawURLEncoding.Decode(n, []byte(key.N))
		if e1 != nil {
			return nil, fmt.Errorf(stderr.DecodeBase64URL, e1.Error())
		}

		_, e2 := base64.RawURLEncoding.Decode(e, []byte(key.E))
		if e2 != nil {
			return nil, fmt.Errorf(stderr.DecodeBase64URL, e2.Error())
		}

		eVar := int(new(big.Int).SetBytes(e).Int64())
		nVar := new(big.Int).SetBytes(n)
		pk := &rsa.PublicKey{E: eVar, N: nVar}

		keys[i] = pk
	}

	return keys, nil
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
