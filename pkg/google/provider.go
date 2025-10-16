package google

import (
	"bytes"
	"crypto/md5"
	"encoding/json"
	"fmt"
	jwt "github.com/kohirens/json-web-token"
	"github.com/kohirens/www/storage"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type Provider struct {
	Code string `json:"code"`
	// DiscoveryDoc contains well known info about the OIDC G discoveryDocument
	DiscoveryDoc *DiscoverDoc `json:"discoveryDocument"`
	// Hd To optimize the OpenID Connect flow for users of a particular domain
	// associated with a Google Workspace or Cloud organization.
	Hd string `json:"hd"`
	// OAuth2 The credentials generated and the RedirectURI assigned to the
	// Google Cloud app for this application. These will come from the
	// environment this application runs in.
	JWKs   *JwksUriv3 `json:"keys"`
	OAuth2 *OAuth2
	// ProjectID name of the made in Google Cloud app.
	ProjectID string   `json:"application"`
	Scopes    []string `json:"scopes"`
	State     string   `json:"state"`
	// Credentials Clients login username and password.
	Token  *Token `json:"credentials"`
	client HttpClient
	store  storage.Storage
}

// Authenticated Indicates if the HttpClient has been successfully authenticated by
// Google.
func (gp *Provider) Authenticated() bool {
	Log.Dbugf(stdout.VerifyAuth)

	return gp.Token != nil && !gp.Token.Expired() // Time has expired
}

// AuthLink Generate an link for the user to authenticate with the provider.
func (gp *Provider) AuthLink(loginHint string) (string, error) {
	epAuthentication := os.Getenv(envOIDCAuthURI)
	if epAuthentication == "" {
		return "", fmt.Errorf(stderr.MissEnvVar, envOIDCAuthURI)
	}

	// NOTE: Set the access_type parameter to offline so that a refresh token
	// is returned with the ID token, see:
	// https://developers.google.com/identity/openid-connect/openid-connect#exchangecode
	uri := fmt.Sprintf(
		"%v?response_type=code&scope=%v&redirect_uri=%v&client_id=%v&state=%v&nonce=%v&access_type=offline&prompt=consent",
		epAuthentication,
		strings.Join(gp.Scopes, "%20"),
		url.QueryEscape(gp.OAuth2.RedirectURI),
		gp.OAuth2.ClientID,
		gp.State,
		NewNonce(),
	)

	if loginHint != "" {
		uri = uri + "&login_hint=" + loginHint
	}

	if gp.Hd != "" {
		uri = uri + "&hd=" + gp.Hd
	}

	Log.Dbugf("Google OIDC Auth URI: %s", uri)

	return uri, nil
}

// Certificate JWK Grab the certs for validating ID tokens from Google.
func (gp *Provider) Certificate() error {
	uri := gp.DiscoveryDoc.JwksUri
	if uri == "" {
		return fmt.Errorf(stderr.MissEnvVar, envOIDCCertURL)
	}

	Log.Infof(stdout.Url, uri)

	res, e1 := gp.sendWithRetry("GET", uri, nil, nil, 200, 3)
	if e1 != nil {
		return fmt.Errorf(stderr.Response, e1.Error())
	}

	resBody, e2 := io.ReadAll(res.Body)
	if e2 != nil {
		return fmt.Errorf(stderr.ReadResponse, e2.Error())
	}

	var err error
	gp.JWKs, err = LoadJwksUriv3(resBody)
	if err != nil {
		return err
	}

	return nil
}

// ClientID is unique to a Google Account even if the user changes their email
// address.
// Warning: When implementing your account management system, you shouldn't
// use the email field in the ID token as a unique identifier for a user.
// Always use the `sub` field as it is unique to a Google Account even if the
// user changes their email address.
// For details see:
// https://developers.google.com/identity/openid-connect/openid-connect#obtainuserinfo
func (gp *Provider) ClientID() string {
	idToken, e1 := gp.Token.IDTokenInfo()
	if e1 != nil {
		panic(e1)
	}
	sub, ok := idToken.Payload["sub"]
	if !ok {
		panic(fmt.Sprintf(stderr.IDTokenNoSub))
	}
	return fmt.Sprintf("%v-google-%v", gp.Name(), sub.(string))
}

func (gp *Provider) DownloadDiscoveryDoc() error {
	uri := os.Getenv(envDiscoverDocURL)
	if uri == "" {
		return fmt.Errorf(stderr.MissEnvVar, envDiscoverDocURL)
	}

	Log.Infof(stdout.Url, uri)

	res, e1 := gp.sendWithRetry("GET", uri, nil, nil, 200, 3)
	if e1 != nil {
		return fmt.Errorf(stderr.Response, e1.Error())
	}

	resBody, e2 := io.ReadAll(res.Body)
	if e2 != nil {
		return fmt.Errorf(stderr.ReadResponse, e2.Error())
	}

	if e := json.Unmarshal(resBody, gp.DiscoveryDoc); e != nil {
		return fmt.Errorf(stderr.DecodeJSON, e.Error())
	}

	gp.DiscoveryDoc.rawBytes = resBody

	return nil
}

func (gp *Provider) GoogleDiscoverDoc(dd []byte) error {
	if e := json.Unmarshal(dd, gp.DiscoveryDoc); e != nil {
		return fmt.Errorf(stderr.DecodeJSON, e.Error())
	}

	gp.DiscoveryDoc.rawBytes = dd

	return nil
}

// LoadCertificate Load the Google public Certificate, try from cache first,
// then download from the internet if that fails.
func (gp *Provider) LoadCertificate() error {
	var e2 error
	dd, e1 := gp.store.Load(keyCertificate)
	if e1 != nil {
		Log.Warnf(e1.Error())
		goto download
	}

	gp.JWKs, e2 = LoadJwksUriv3(dd)
	if e2 == nil {
		return nil
	}
	Log.Warnf(e2.Error())

download:
	Log.Errf(stderr.CertificateCache)

	// Download the Google Certificate
	if e := gp.Certificate(); e != nil {
		return e
	}

	// Save to the storage device.
	if e := gp.store.Save(keyCertificate, gp.JWKs.rawBytes); e != nil {
		Log.Warnf(e.Error())
	}

	Log.Infof("should have saved certificate to %v", keyCertificate)
	return nil
}

// LoadDiscoveryDoc Load the Google Discovery document, try from cache first,
// then download from the internet if that fails.
func (gp *Provider) LoadDiscoveryDoc() error {
	dd, e1 := gp.store.Load(keyDiscoveryDoc)
	if e1 != nil {
		Log.Warnf(e1.Error())
		goto download
	}

	{ // Even though e2 is only used before the download label, Go prevents using goto that skips over this declaration, the blocks help a little.
		e2 := gp.GoogleDiscoverDoc(dd)
		if e2 == nil {
			return nil
		}
		Log.Errf(stderr.LoadDiscoveryDoc, e2.Error())
	}

download:

	Log.Errf(stderr.DiscoveryDocCache)
	// Download the Google Discover Document
	if e := gp.DownloadDiscoveryDoc(); e != nil {
		return e
	}

	if e := gp.store.Save(keyDiscoveryDoc, gp.DiscoveryDoc.rawBytes); e != nil {
		Log.Warnf(e.Error())
	}

	//  to the storage device.
	return nil
}

func (gp *Provider) Logout() {
	// TODO: Implement
}

// ClientEmail Return the logged in clients email address.
func (gp *Provider) ClientEmail() string {
	// TODO: Implement
	return ""
}

// ExchangeCodeForToken An authorization code obtained after the HttpClient
// approves the permission request, which is then sent to Google for an ID
// token obtained from Google.
func (gp *Provider) ExchangeCodeForToken(state, code string) error {

	// TODO: Validate input state and code, before using
	//if !validation.MaxLen(code, maxLen) {
	//	Log.Errf(stderr.MaxLen, fieldCode, maxLen)
	//	w.WriteHeader(http.StatusBadRequest)
	//}

	if e := gp.VerifyState(state); e != nil {
		return e
	}

	uri := os.Getenv(envOIDCTokenURI)
	if uri == "" {
		return fmt.Errorf(stderr.MissEnvVar, envOIDCTokenURI)
	}

	Log.Dbugf(stdout.GoogleTokenUri, uri)

	reqBody := fmt.Sprintf(
		"code=%v&client_id=%v&client_secret=%v&redirect_uri=%v&grant_type=authorization_code",
		code,
		gp.OAuth2.ClientID,
		gp.OAuth2.ClientSecret,
		url.QueryEscape(gp.OAuth2.RedirectURI),
	)

	headers := http.Header{}
	headers.Add("Content-Type", "application/x-www-form-urlencoded")

	res, e1 := gp.sendWithRetry("POST", uri, []byte(reqBody), headers, http.StatusOK, 3)
	if e1 != nil {
		return fmt.Errorf(e1.Error())
	}

	token, e3 := loadToken(res.Body)
	if e3 != nil {
		return e3
	}

	if e := gp.ValidateToken(token); e != nil {
		return e
	}

	gp.Token = token

	Log.Dbugf(stdout.GoogleTokenExp, gp.Token.ExpiresIn)

	return nil
}

func (gp *Provider) HasTokenExpired(auth2 *OAuth2) bool {
	// TODO Implement
	return true
}

// Name ID of the OIDC application registered with the provider
func (gp *Provider) Name() string {
	return gp.ProjectID
}

// RefreshToken Get a new token from Google authentication servers.
func (gp *Provider) RefreshToken() error {
	uri := os.Getenv(envOIDCTokenURI)
	if uri == "" {
		return fmt.Errorf(stderr.MissEnvVar, envOIDCTokenURI)
	}

	reqBody := fmt.Sprintf(
		"client_id=%v&client_secret=%v&refresh_token=%v&grant_type=refresh_token",
		gp.OAuth2.ClientID,
		gp.OAuth2.ClientSecret,
		gp.Token.RefreshToken,
	)

	headers := http.Header{}
	headers.Add("Content-Type", "application/x-www-form-urlencoded")
	res, e1 := gp.sendWithRetry("POST", uri, []byte(reqBody), headers, http.StatusOK, 3)
	if e1 != nil {
		return fmt.Errorf(e1.Error())
	}

	token, e3 := loadToken(res.Body)
	if e3 != nil {
		return e3
	}

	if e := gp.ValidateToken(token); e != nil {
		return e
	}

	gp.Token = token

	return nil
}

// StorageID An ID safe to use as a key or filename when storing this data.
func (gp *Provider) StorageID() string {
	//TODO ClientID also has -google- in it.
	return fmt.Sprintf("%v-google-%x", gp.Name(), md5.Sum([]byte(gp.ClientID())))
}

// ValidateToken Validate an ID token came from Google.
// https://developers.google.com/identity/openid-connect/openid-connect#validatinganidtoken
func (gp *Provider) ValidateToken(token *Token) error {
	if token == nil {
		return fmt.Errorf(stderr.ValidateTokenNil)
	}

	// Convert the ID token string into code.
	info, e1 := token.IDTokenInfo()
	if e1 != nil {
		return fmt.Errorf(stderr.ParsingIDToken, e1.Error())
	}

	if gp.JWKs == nil {
		return fmt.Errorf(stderr.NoCerts)
	}

	// Get the RSA public keys which we have retrieved from Google.
	keys, e2 := ParseRSAPublicKeys(gp.JWKs.Keys)
	if e2 != nil {
		return fmt.Errorf(stderr.ValidateTokenKeys, e2.Error())
	}

	// 1.Verify that the ID token is properly signed by the issuer.
	valid := false
	for _, key := range keys {
		if e3 := jwt.ValidateSignatureRS256Pub([]byte(token.IDToken), key); e3 == nil {
			valid = true
		}
	}
	if !valid {
		return fmt.Errorf(stderr.SignatureVerify)
	}

	// 2. Verify that the value of the iss claim in the ID token is equal to https://accounts.google.com or accounts.google.com.
	iss, ok1 := info.Payload["iss"]
	if !ok1 || gp.DiscoveryDoc.Issuer != iss {
		return fmt.Errorf(stderr.ValidateTokenIss, iss)
	}

	// 3. Verify that the value of the aud claim in the ID token is equal to your app's client ID.
	encAud, ok2 := info.Payload["aud"]
	if !ok2 {
		return fmt.Errorf(stderr.ValidateTokenAud, encAud, gp.ProjectID)
	}
	aud, e4 := url.QueryUnescape(encAud.(string))
	if e4 != nil {
		return fmt.Errorf(stderr.AudDecode, e4.Error())
	}

	if aud != gp.OAuth2.ClientID {
		return fmt.Errorf(stderr.ValidateTokenPrj, encAud, gp.OAuth2.ClientID)
	}

	// 4. Verify that the expiry time (exp claim) of the ID token has not passed.
	if token.Expired() {
		return fmt.Errorf(stderr.ValidateTokenExp)
	}

	// TODO: Test with an hd passed into the authorization URL.
	// 5. If you specified a hd parameter value in the request, verify that the ID token has a hd claim that matches an accepted domain associated with a Google Cloud organization.
	if gp.Hd != "" {
		hd, ok3 := info.Payload["hd"]
		if !ok3 || hd != gp.Hd {
			return fmt.Errorf(stderr.ValdateTokenHd, hd, gp.Hd)
		}
	}

	return nil
}

// VerifyState Verify the state returned from the request matches the
// original value sent.
func (gp *Provider) VerifyState(returnedSate string) error {
	// Validate the state from the session was restored.
	if len(returnedSate) < 30 || len(gp.State) < 30 { // Log error and redirect to login page.
		return &ErrInvalidState{stderr.InvalidState, "/?m=invalid-state", http.StatusSeeOther}
	}

	sState, e1 := url.QueryUnescape(gp.State)
	if e1 != nil {
		Log.Errf(stderr.QueryUnescape, e1.Error())
	}

	Log.Dbugf("rtn-state: %v", returnedSate)
	Log.Dbugf("org-state: %s", sState)

	// Compare the state field from the URL and the session.
	if returnedSate != sState { // Log error and redirect to login page.
		return &ErrInvalidState{stderr.StateMismatch, "/?=bad-state", http.StatusSeeOther}
	}

	return nil
}

// sendWithRetry Make an HTTP request, retrying up to so many times.
// NOTE: Response will only be nil when something goes wrong. Otherwise,
// it will be a valid http.Response.
func (gp *Provider) sendWithRetry(method, url string, data []byte, headers http.Header, code, retries int) (*http.Response, error) {
	body := bytes.NewBuffer(data)

	req, e1 := http.NewRequest(method, url, body)
	if e1 != nil {
		return nil, fmt.Errorf(stderr.BuildLoginRequest, e1.Error())
	}

	req.Header = headers
	var res *http.Response
	var e2 error

	for attempt := 1; attempt <= retries; attempt++ {
		res, e2 = gp.client.Do(req)
		if e2 != nil {
			return nil, fmt.Errorf(stderr.LoginRequest, e2.Error())
		}

		if res.StatusCode == code {
			break
		}

		resBody, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if attempt == retries {
			return nil, fmt.Errorf(stderr.Response, res.StatusCode, string(resBody))
		}

		Log.Warnf(stderr.Response, res.StatusCode, string(resBody))
		res = nil
	}

	return res, nil
}
