package google

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
