package oidc

// UserInfo information that the provider will provide.
//
//	Only add functions for fields that all providers can supply here. Otherwise,
//	you'll want to cast to a Provider specific implementation in your app to
//	get the bells and whistles.
type UserInfo interface {
	FirstName() string
	LastName() string
	Email() string
	ID() string
	Phone() string
}
