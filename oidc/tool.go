package oidc

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/gofrs/uuid/v5"
)

// State generates a new anti-forgery unique session token.
func State() string {
	return generateUUID()
}

// Nonce generates a new random value that enables replay protection.
func Nonce() string {
	return generateUUID()
}

func generateUUID() string {
	id, e1 := uuid.NewV4()
	if e1 != nil {
		msg := fmt.Sprintf(stderr.GenerateUUID, e1.Error())
		panic(msg)
	}
	return id.String()
}

// generateSecureToken gives 256 bits of entropy using a random generated
// number of bytes and base64 encoding.
//
//	NOTE: Panics on failure to generate random bytes.
func generateSecureToken(length int) string {
	b := make([]byte, length)
	_, e1 := rand.Read(b)
	if e1 != nil {
		panic(e1)
	}
	return base64.URLEncoding.EncodeToString(b)
}
