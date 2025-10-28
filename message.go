package sso

var stderr = struct {
	DecodeJSON,
	EncodeJSON string
}{
	DecodeJSON: "could not decode JSON: %v",
	EncodeJSON: "unable encode JSON: %v",
}

var stdout = struct {
}{}
