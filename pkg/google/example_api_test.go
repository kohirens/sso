package google_test

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/kohirens/sso/pkg/google"
	"github.com/kohirens/stdlib/fsio"
	"github.com/kohirens/stdlib/test"
	"github.com/kohirens/www/backend"
	"github.com/kohirens/www/session"
	"github.com/kohirens/www/storage"
)

const (
	fixturesDir = "testdata"
	tmpDir      = "tmp"
)

func ExampleAuthLink() {
	var mainErr error

	defer func() {
		if mainErr != nil {
			log.Errf("error %v", mainErr)
		}
	}()

	// Required environment variables:
	// GOOGLE_DISCOVERY_DOC_URL
	// GOOGLE_OIDC_CLIENT_ID
	// GOOGLE_OIDC_CLIENT_SECRET
	// GOOGLE_OIDC_REDIRECT_URIS
	// GOOGLE_OIDC_PROJECT_ID
	if e := setupForExampleAuthLink(); e != nil {
		mainErr = e
		return
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

	// Initialize a storage manager.
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

	authURI, e4 := gp.AuthLink("user@example.com")
	if e4 != nil {
		log.Errf("error %v", e4.Error())
		return
	}

	fmt.Println(authURI)
}

// quickly set the variables for testing the example. Don't actually do this
// in a real application.
func setupForExampleAuthLink() error {
	if e := os.Setenv("GOOGLE_DISCOVERY_DOC_URL", "https://accounts.google.com/.well-known/openid-configuration"); e != nil {
		return fmt.Errorf("cannot set environment variable GOOGLE_DISCOVERY_DOC_URL %v", e.Error())
	}
	if e := os.Setenv("GOOGLE_OIDC_CLIENT_ID", "1234-abcd"); e != nil {
		return fmt.Errorf("cannot set environment variable GOOGLE_OIDC_AUTH_URI %v", e.Error())
	}
	if e := os.Setenv("GOOGLE_OIDC_CLIENT_SECRET", "54321"); e != nil {
		return fmt.Errorf("cannot set environment variable GOOGLE_OIDC_AUTH_URI %v", e.Error())
	}
	if e := os.Setenv("GOOGLE_OIDC_REDIRECT_URIS", "https://localhost/api/google-is-calling"); e != nil {
		return fmt.Errorf("cannot set environment variable GOOGLE_OIDC_AUTH_URI %v", e.Error())
	}
	if e := os.Setenv("GOOGLE_OIDC_PROJECT_ID", "sso_example"); e != nil {
		return fmt.Errorf("cannot set environment variable GOOGLE_OIDC_AUTH_URI %v", e.Error())
	}

	tmpStorageDir := tmpDir + ps + "storage"

	test.ResetDir(tmpStorageDir, 0777)
	_, e1 := fsio.CopyToDir(
		fixturesDir+ps+"google_discovery_document.json",
		tmpStorageDir,
		ps,
	)

	return e1
}
