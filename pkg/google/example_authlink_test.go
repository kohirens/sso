package google_test

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/kohirens/sso/pkg/google"
	"github.com/kohirens/stdlib/logger"
	"github.com/kohirens/www/backend"
	login "github.com/kohirens/www/login/google"
	"github.com/kohirens/www/session"
	"github.com/kohirens/www/storage"
	"github.com/kohirens/www/validation"
)

const (
	certFile       = "/root/pki/certs/server.crt"
	certKey        = "/root/pki/private/server.key"
	sessionTimeout = time.Minute * 20

	ps = string(os.PathSeparator)

	templateFilesDir = "../../templates"
	baseDir          = "tmp/storage"
	loginDir         = "logins"
	sessionDir       = "session"
)

var (
	log = &logger.Standard{}
)

func Example() {
	var mainErr error

	defer func() {
		if mainErr != nil {
			log.Errf("error %v", mainErr)
		}
	}()

	// Required environment variables:
	// GOOGLE_OIDC_AUTH_URI
	if e := os.Setenv("GOOGLE_OIDC_AUTH_URI", "https://accounts.example.com/o/oauth2/auth"); e != nil {
		mainErr = fmt.Errorf("cannot set environment variable GOOGLE_OIDC_AUTH_URI %v", e.Error())
	}

	wd, e1 := filepath.Abs(".")
	if e1 != nil {
		panic(fmt.Sprintf("directory %v", e1.Error()))
	}

	storageDir := wd + ps + baseDir
	// make some directories to prevent dir exist errors.
	_ = os.MkdirAll(storageDir+ps+sessionDir, 0777)
	_ = os.MkdirAll(storageDir+ps+loginDir, 0777)
	_ = os.MkdirAll(storageDir+ps+backend.PrefixAccounts, 0777)

	// Initialize a storage handler for the backend.
	store, e2 := storage.NewLocalStorage(storageDir)
	if e2 != nil {
		mainErr = fmt.Errorf("cannot initialize storage %v", e2.Error())
		return
	}

	// Initialize a session manager
	sm := session.NewManager(store, sessionDir, sessionTimeout)

	// Initialize a Google OIDC Provider.
	gp, e3 := google.NewProvider(&http.Client{}, store, sm, "")
	if e3 != nil {
		mainErr = e3
		return
	}

	login.LoginRedirect = "/updates.html"
	backend.TmplDir = templateFilesDir

	responder := &Responder{
		Google: gp,
	}

	webapp := http.NewServeMux()
	webapp.HandleFunc("/api/google-auth-link", responder.AuthLink)

	mainErr = http.ListenAndServeTLS(":443", certFile, certKey, nil)
}

type Responder struct {
	Google *google.Provider
}

// AuthLink Build link to authenticate with Google.
//
//	Generate a link to send the client to Google authentication servers where
//	they can choose to consent to grant this application authorization
//	to access their profile and a token.
func (rr *Responder) AuthLink(w http.ResponseWriter, r *http.Request) {
	email, emailOK := validation.Email(r.URL.Query().Get("email"))
	if !emailOK {
		email = "" // It's not required, so it is O.K. to leave it out.
	}

	authURI, e1 := rr.Google.AuthLink(email)
	if e1 != nil {
		log.Errf("error %v", e1.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	s := fmt.Sprintf(`{"status": %q, "link": %q}`, "ok", authURI)

	_, e3 := w.Write([]byte(s))
	if e3 != nil {
		log.Errf("cannot encode JSON %v", e3.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
}
