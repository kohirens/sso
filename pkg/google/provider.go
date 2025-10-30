package google

import (
	"bytes"
	"encoding/json"
	"fmt"
	jwt "github.com/kohirens/json-web-token"
	"github.com/kohirens/sso"
	"github.com/kohirens/www/storage"
	"github.com/mileusna/useragent"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type Provider struct {
	Code     string `json:"code"`
	deviceID string
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
	Token     *Token `json:"credentials"`
	client    HttpClient
	Prefix    string
	session   Session
	store     storage.Storage
	loginInfo *sso.LoginInfo
}

// Application Name of the project made in Google Cloud app.
func (p *Provider) Application() string {
	return p.ProjectID
}

// Authenticated Indicates if the HttpClient has been successfully authenticated by
// Google.
func (p *Provider) Authenticated() bool {
	Log.Dbugf(stdout.VerifyAuth)

	return p.Token != nil && !p.Token.Expired() // Time has expired
}

// AuthLink Generate a link to authenticate with the provider.
func (p *Provider) AuthLink(loginHint string) (string, error) {
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
		strings.Join(p.Scopes, "%20"),
		url.QueryEscape(p.OAuth2.RedirectURI),
		p.OAuth2.ClientID,
		p.State,
		NewNonce(),
	)

	if loginHint != "" {
		uri = uri + "&login_hint=" + loginHint
	}

	if p.Hd != "" {
		uri = uri + "&hd=" + p.Hd
	}

	Log.Dbugf("Google OIDC Auth URI: %s", uri)

	return uri, nil
}

// Certificate JWK Download the certificates for validating ID tokens from Google.
func (p *Provider) Certificate() error {
	uri := p.DiscoveryDoc.JwksUri
	if uri == "" {
		return fmt.Errorf(stderr.MissEnvVar, envOIDCCertURL)
	}

	Log.Infof(stdout.Url, uri)

	res, e1 := p.sendWithRetry("GET", uri, nil, nil, 200, 3)
	if e1 != nil {
		return fmt.Errorf(stderr.Response, e1.Error())
	}

	resBody, e2 := io.ReadAll(res.Body)
	if e2 != nil {
		return fmt.Errorf(stderr.ReadResponse, e2.Error())
	}

	var err error
	p.JWKs, err = LoadJwksUriv3(resBody)
	if err != nil {
		return err
	}

	return nil
}

// ClientID An ID unique to a Google Account even if the user changes their
// email address.
//
//	Google ID Tokens contain `sub` always. An identifier for the user, unique
//	among all Google Accounts and never reused. A Google Account can have
//	multiple email addresses at different points in time, but the sub value
//	is never changed. Use sub within your application as the unique-identifier
//	key for the user. Maximum length of 255 case-sensitive ASCII characters.
//	For details see:
//	https://developers.google.com/identity/openid-connect/openid-connect#obtainuserinfo
func (p *Provider) ClientID() string {
	// ClientID will be the users Google ID stores in a folder
	// /login/<google-user-id>. The data has to be encrypted since it will
	// contain PII. For compliance, it will be encrypted with the apps GPG key.
	idToken, e1 := p.Token.IDTokenInfo()
	if e1 != nil {
		panic(e1)
	}

	sub, ok := idToken.Payload["sub"]
	if !ok {
		panic(fmt.Sprintf(stderr.IDTokenNoSub))
	}

	return sub.(string)
}

// DeviceID Get the ID of the device the user is currently logged in with.
func (p *Provider) DeviceID() string {
	return p.deviceID
}

func (p *Provider) DiscoveryDocDownload() error {
	uri := os.Getenv(envDiscoverDocURL)
	if uri == "" {
		return fmt.Errorf(stderr.MissEnvVar, envDiscoverDocURL)
	}

	Log.Infof(stdout.Url, uri)

	res, e1 := p.sendWithRetry("GET", uri, nil, nil, 200, 3)
	if e1 != nil {
		return fmt.Errorf(stderr.Response, e1.Error())
	}

	resBody, e2 := io.ReadAll(res.Body)
	if e2 != nil {
		return fmt.Errorf(stderr.ReadResponse, e2.Error())
	}

	if e := json.Unmarshal(resBody, p.DiscoveryDoc); e != nil {
		return fmt.Errorf(stderr.DecodeJSON, e.Error())
	}

	p.DiscoveryDoc.rawBytes = resBody

	return nil
}

func (p *Provider) DiscoverDoc(dd []byte) error {
	if e := json.Unmarshal(dd, p.DiscoveryDoc); e != nil {
		return fmt.Errorf(stderr.DecodeJSON, e.Error())
	}

	p.DiscoveryDoc.rawBytes = dd

	return nil
}

// LoadCertificate Load the Google public Certificate, try from cache first,
// then download from the internet if that fails.
func (p *Provider) LoadCertificate() error {
	var e2 error
	filename := p.location(keyCertificate)
	dd, e1 := p.store.Load(filename)
	if e1 != nil {
		Log.Warnf(e1.Error())
		goto download
	}

	p.JWKs, e2 = LoadJwksUriv3(dd)
	if e2 == nil {
		return nil
	}
	Log.Warnf(e2.Error())

download:
	Log.Errf(stderr.CertificateCache)

	// Download the Google Certificate
	if e := p.Certificate(); e != nil {
		return e
	}

	// Save to the storage device.
	if e := p.store.Save(filename, p.JWKs.rawBytes); e != nil {
		Log.Warnf(e.Error())
	}

	Log.Infof("should have saved certificate to %v", keyCertificate)
	return nil
}

// LoadDiscoveryDoc Load the Google Discovery document, try from cache first,
// then download from the internet if that fails.
func (p *Provider) LoadDiscoveryDoc() error {
	filename := p.location(keyDiscoveryDoc)
	dd, e1 := p.store.Load(filename)
	if e1 != nil {
		Log.Warnf(e1.Error())
		goto download
	}

	{ // Even though e2 is only used before the download label, Go prevents using goto that skips over this declaration, the blocks help a little.
		e2 := p.DiscoverDoc(dd)
		if e2 == nil {
			return nil
		}
		Log.Errf(stderr.LoadDiscoveryDoc, e2.Error())
	}

download:

	Log.Errf(stderr.DiscoveryDocCache)
	// Download the Google Discover Document
	if e := p.DiscoveryDocDownload(); e != nil {
		return e
	}

	if e := p.store.Save(filename, p.DiscoveryDoc.rawBytes); e != nil {
		Log.Warnf(e.Error())
	}

	//  to the storage device.
	return nil
}

// SignOut Should invalidate any token used to sign in.
// Will also remove any data stored in the session,
func (p *Provider) SignOut() error {
	// TODO: Implement
	return nil
}

// ClientEmail Return the logged in clients email address.
func (p *Provider) ClientEmail() string {
	idToken, e1 := p.Token.IDTokenInfo()
	if e1 != nil {
		panic(e1)
	}

	email, ok := idToken.Payload["email"]
	if !ok {
		panic(fmt.Sprintf(stderr.IDTokenNoEmail))
	}

	return email.(string)
}

// ExchangeCodeForToken An authorization code obtained after the HttpClient
// approves the permission request, which is then sent to Google for an ID
// token obtained from Google.
func (p *Provider) ExchangeCodeForToken(state, code string) error {
	if e := p.VerifyState(state); e != nil {
		return e
	}

	uri := os.Getenv(envOIDCTokenURI)
	if uri == "" {
		return fmt.Errorf(stderr.MissEnvVar, envOIDCTokenURI)
	}

	Log.Dbugf(stdout.GoogleTokenUri, uri)

	if p.OAuth2 == nil {
		return fmt.Errorf(stderr.OAuth2Nil)
	}

	reqBody := fmt.Sprintf(
		"code=%v&client_id=%v&client_secret=%v&redirect_uri=%v&grant_type=authorization_code",
		code,
		p.OAuth2.ClientID,
		p.OAuth2.ClientSecret,
		url.QueryEscape(p.OAuth2.RedirectURI),
	)

	headers := http.Header{}
	headers.Add("Content-Type", "application/x-www-form-urlencoded")

	res, e1 := p.sendWithRetry("POST", uri, []byte(reqBody), headers, http.StatusOK, 3)
	if e1 != nil {
		return e1
	}

	token, e3 := loadToken(res.Body)
	if e3 != nil {
		return e3
	}

	if e := p.ValidateToken(token); e != nil {
		return e
	}

	p.Token = token

	Log.Dbugf(stdout.GoogleTokenExp, p.Token.ExpiresIn)

	return nil
}

func (p *Provider) HasTokenExpired(auth2 *OAuth2) bool {
	// TODO Implement
	return true
}

// LoadLoginInfo retrieve previous login info from storage.
//
//	NOTE: This requires the client to have consented beforehand. The
//	best time to call this method is during or right after the callback.
func (p *Provider) LoadLoginInfo(deviceID, sessionID, userAgent string) (*sso.LoginInfo, error) {
	// Token must be set.
	if p.Token == nil {
		panic(stderr.NoToken)
	}

	// ClientID MUST be set.
	filename := p.loginFilename()
	liData, e1 := p.store.Load(filename)
	if e1 != nil { // When you cannot load it, then just make it.
		return nil, &ErrNoLoginInfo{filename}
	}

	li := &sso.LoginInfo{}
	if e := json.Unmarshal(liData, li); e != nil {
		return nil, fmt.Errorf(stderr.EncodeJSON, e)
	}

	p.loginInfo = li
	// look for the device
	var err error
	if deviceID != "" {
		d, e := p.loginInfo.LookupDevice(deviceID, sessionID, userAgent)
		if e != nil {
			Log.Warnf("%v", e.Error())
		}
		if d != nil {
			p.deviceID = d.ID
		}
	}

	return p.loginInfo, err
}

// Name ID of the OIDC application registered with the provider
func (p *Provider) Name() string {
	return "google"
}

// RefreshToken Get a new token from Google authentication servers.
func (p *Provider) RefreshToken() error {
	uri := os.Getenv(envOIDCTokenURI)
	if uri == "" {
		return fmt.Errorf(stderr.MissEnvVar, envOIDCTokenURI)
	}

	reqBody := fmt.Sprintf(
		"client_id=%v&client_secret=%v&refresh_token=%v&grant_type=refresh_token",
		p.OAuth2.ClientID,
		p.OAuth2.ClientSecret,
		p.Token.RefreshToken,
	)

	headers := http.Header{}
	headers.Add("Content-Type", "application/x-www-form-urlencoded")
	res, e1 := p.sendWithRetry("POST", uri, []byte(reqBody), headers, http.StatusOK, 3)
	if e1 != nil {
		return fmt.Errorf(e1.Error())
	}

	token, e3 := loadToken(res.Body)
	if e3 != nil {
		return e3
	}

	if e := p.ValidateToken(token); e != nil {
		return e
	}

	p.Token = token

	return nil
}

// RegisterLoginInfo Register new login information.
//
//	NOTE: This is the only time the user agent is set on a device.
func (p *Provider) RegisterLoginInfo(sessionID, userAgent string) (*sso.LoginInfo, error) {
	// Token must be set.
	if p.Token == nil {
		panic(stderr.NoToken)
	}

	li := &sso.LoginInfo{
		Devices:      make(map[string]*sso.Device),
		Email:        p.ClientEmail(),
		ClientID:     p.ClientID(),
		RefreshToken: p.Token.RefreshToken,
	}

	device := sso.NewDevice(userAgent, sessionID, p.Name())
	li.Devices[device.ID] = device

	p.deviceID = device.ID
	p.loginInfo = li

	// register the login info
	if e := p.SaveLoginInfo(); e != nil {
		return nil, e
	}

	return p.loginInfo, nil
}

// SaveLoginInfo Save info for retrieval without hitting Google servers.
func (p *Provider) SaveLoginInfo() error {
	liData, e1 := json.Marshal(p.loginInfo)
	if e1 != nil {
		return fmt.Errorf(stderr.EncodeJSON, e1.Error())
	}

	return p.store.Save(p.loginFilename(), liData)
}

// UpdateLoginInfo
// Never update the user agent on the device, its only set on registration.
func (p *Provider) UpdateLoginInfo(deviceID, sessionID, userAgent string) error {
	if p.Token == nil {
		return &ErrNoToken{}
	}

	if p.loginInfo == nil {
		return &ErrNoLoginInfo{deviceID}
	}
	// Update login info.
	p.loginInfo.ClientID = p.ClientID()
	p.loginInfo.RefreshToken = p.RefreshToken()
	p.loginInfo.Email = p.ClientEmail()

	device := p.loginInfo.Devices[deviceID]
	if device == nil {
		return &ErrDeviceNotFound{deviceID}
	}

	p.deviceID = device.ID
	// Sessions are ephemeral, so we just replace them.
	device.SessionID = sessionID
	if device.UserAgent == nil {
		ua := useragent.Parse(userAgent)
		device.UserAgent = &ua
	}
	device.LastActivity = time.Now()

	// Store that token away for safe keeping
	if e := p.SaveLoginInfo(); e != nil {
		return e
	}

	return nil
}

// ValidateToken Validate an ID token came from Google.
// https://developers.google.com/identity/openid-connect/openid-connect#validatinganidtoken
func (p *Provider) ValidateToken(token *Token) error {
	if token == nil {
		return fmt.Errorf(stderr.ValidateTokenNil)
	}

	// Convert the ID token string into code.
	info, e1 := token.IDTokenInfo()
	if e1 != nil {
		return fmt.Errorf(stderr.ParsingIDToken, e1.Error())
	}

	if p.JWKs == nil {
		return fmt.Errorf(stderr.NoCerts)
	}

	// Get the RSA public keys which we have retrieved from Google.
	keys, e2 := ParseRSAPublicKeys(p.JWKs.Keys)
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
	if !ok1 || p.DiscoveryDoc.Issuer != iss {
		return fmt.Errorf(stderr.ValidateTokenIss, iss)
	}

	// 3. Verify that the value of the aud claim in the ID token is equal to your app's client ID.
	encAud, ok2 := info.Payload["aud"]
	if !ok2 {
		return fmt.Errorf(stderr.ValidateTokenAud, encAud, p.ProjectID)
	}
	aud, e4 := url.QueryUnescape(encAud.(string))
	if e4 != nil {
		return fmt.Errorf(stderr.AudDecode, e4.Error())
	}

	if aud != p.OAuth2.ClientID {
		return fmt.Errorf(stderr.ValidateTokenPrj, encAud, p.OAuth2.ClientID)
	}

	// 4. Verify that the expiry time (exp claim) of the ID token has not passed.
	if token.Expired() {
		return fmt.Errorf(stderr.ValidateTokenExp)
	}

	// TODO: Test with an hd passed into the authorization URL.
	// 5. If you specified a hd parameter value in the request, verify that the ID token has a hd claim that matches an accepted domain associated with a Google Cloud organization.
	if p.Hd != "" {
		hd, ok3 := info.Payload["hd"]
		if !ok3 || hd != p.Hd {
			return fmt.Errorf(stderr.ValidateTokenHd, hd, p.Hd)
		}
	}

	return nil
}

// VerifyState Verify the state returned from the request matches the
// original value sent.
func (p *Provider) VerifyState(returnedSate string) error {
	// Check either state is not empty
	if len(returnedSate) < 30 || len(p.State) < 30 { // Log error and redirect to login page.
		return &ErrInvalidState{stderr.InvalidState, "/?m=invalid-state", http.StatusSeeOther}
	}

	sState, e1 := url.QueryUnescape(p.State)
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

// location Return the storage location.
func (p *Provider) location(filename string) string {
	if p.Prefix != "" {
		return p.Prefix + "/" + filename + ".json"
	}
	return filename + ".json"
}

// loginFile where to look for the file containing login information.
func (p *Provider) loginFilename() string {
	return p.location("logins/" + p.ClientID())
}

// sendWithRetry Make an HTTP request, retrying up to so many times.
// NOTE: Response will only be nil when something goes wrong. Otherwise,
// it will be a valid http.Response.
func (p *Provider) sendWithRetry(method, url string, data []byte, headers http.Header, code, retries int) (*http.Response, error) {
	body := bytes.NewBuffer(data)

	req, e1 := http.NewRequest(method, url, body)
	if e1 != nil {
		return nil, fmt.Errorf(stderr.BuildLoginRequest, e1.Error())
	}

	req.Header = headers
	var res *http.Response
	var e2 error

	for attempt := 1; attempt <= retries; attempt++ {
		res, e2 = p.client.Do(req)
		if e2 != nil {
			return nil, fmt.Errorf(stderr.LoginRequest, e2.Error())
		}

		if res.StatusCode == code {
			break
		}

		resBody, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if attempt == retries {
			return nil, fmt.Errorf(stderr.ResponseFinal, res.StatusCode, string(resBody))
		}

		Log.Warnf(stderr.ResponseAttempts, attempt, res.StatusCode, string(resBody))
		res = nil
	}

	return res, nil
}
