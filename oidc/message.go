package oidc

var stderr = struct {
	BuildRequest,
	GenerateUUID,
	RetryRequest,
	UnexpectedCode string
}{
	BuildRequest:   "cannot build the request: %v",
	GenerateUUID:   "unable to generate uuid: %v",
	RetryRequest:   "request with retry %v",
	UnexpectedCode: "attempt %v to url %v has returned HTTP status code %v with body %v",
}

var stdout = struct {
}{}
