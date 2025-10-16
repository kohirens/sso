package google

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
)

type JWK struct {
	Kty string `json:"kty"`
	E   string `json:"e"`
	Use string `json:"use"`
	N   string `json:"n"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
}

type JwksUriv3 struct {
	Keys     []*JWK `json:"keys"`
	rawBytes []byte
}

func (k *JwksUriv3) Bytes() []byte {
	return k.rawBytes
}

func (k *JwksUriv3) String() string {
	return string(k.rawBytes)
}

func LoadJwksUriv3(data []byte) (*JwksUriv3, error) {
	cert := &JwksUriv3{}

	if e := json.Unmarshal(data, cert); e != nil {
		return nil, fmt.Errorf(stderr.DecodeJSON, e.Error())
	}

	cert.rawBytes = data

	return cert, nil
}

// ParseRSAPublicKeys Convert JWK structures into keys. This was meant to handle
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
