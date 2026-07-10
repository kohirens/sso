package oidc

type SessionManager interface {
	// Get any data previously stored.
	Get(key string) []byte
	// Remove any data previously stored.
	Remove(key string) error
	// Set any data that will be needed to be retrieved at a later time.
	Set(key string, value []byte)
}
