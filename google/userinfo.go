package google

import (
	"fmt"

	jwt "github.com/kohirens/json-web-token"
	"github.com/kohirens/sso/oidc"
)

// UserInfo will be the users Google ID stores in a folder
// /login/<google-user-id>. The data has to be encrypted since it will
// contain PII. For compliance, it will be encrypted with the apps GPG key.
type UserInfo struct {
	token     *Token
	jwtInfo   *jwt.Info
	email     string
	firstName string
	id        string
	lastName  string
	locale    string
	phone     string
}

func (ui *UserInfo) Email() string {
	if ui.email == "" {
		email, ok := ui.jwtInfo.Payload["email"]
		if !ok {
			panic(fmt.Sprintf("%v", stderr.IDTokenNoEmail))
		}

		ui.email = email.(string)
	}

	return ui.email
}

func (ui *UserInfo) FirstName() string {
	if ui.firstName == "" {
		name, ok := ui.jwtInfo.Payload["given_name"]
		if !ok {
			panic(fmt.Sprintf("%v", stderr.GetFirstName))
		}

		ui.firstName = name.(string)
	}

	return ui.firstName
}

func (ui *UserInfo) Locale() string {
	if ui.firstName == "" {
		locale, ok := ui.jwtInfo.Payload["locale"]
		if !ok {
			panic(fmt.Sprintf("%v", stderr.GetLocale))
		}

		ui.locale = locale.(string)
	}

	return ui.locale
}

func (ui *UserInfo) LastName() string {
	if ui.lastName == "" {
		name, ok := ui.jwtInfo.Payload["family_name"]
		if !ok {
			panic(fmt.Sprintf("%v", stderr.GetLastName))
		}

		ui.lastName = name.(string)
	}

	return ui.lastName
}

// ID is unique to a Google Account even if the user changes their email
// address.
//
//	Google ID Tokens contain `sub` always. An identifier for the user, unique
//	among all Google Accounts and never reused. A Google Account can have
//	multiple email addresses at different points in time, but the sub value
//	is never changed. Use sub within your application as the unique-identifier
//	key for the user. Maximum length of 255 case-sensitive ASCII characters.
//	For details see:
//	https://developers.google.com/identity/openid-connect/openid-connect#obtainuserinfo
func (ui *UserInfo) ID() string {
	if ui.id == "" {
		sub, ok := ui.jwtInfo.Payload["sub"]
		if !ok {
			panic(fmt.Sprintf("%v", stderr.IDTokenNoSub))
		}

		ui.id = sub.(string)
	}

	return ui.id
}

func (ui *UserInfo) Phone() string {
	panic("implement me")
}

func newUserInfo(t *Token) oidc.UserInfo {
	jwtInfo, e1 := t.IDTokenInfo()
	if e1 != nil {
		panic(e1)
	}

	return &UserInfo{
		token:   t,
		jwtInfo: jwtInfo,
	}
}
