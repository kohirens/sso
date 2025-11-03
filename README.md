# SSO

Single Sign On with OIDC providers Apple and Google, authored by Khalifah
Khalil Shabazz.

## Summary

This library was made to allow clients to sign in with an OIDC provider. By
default, it includes packages for Apple and Google out-of-the-box. It make take
some effort to integrate this library directly into an application since there
is no standard around integration methods currently. Once you do, the benefits
allow your clients use of a login provider they know and may trust, automate
account setup in your system, and semi-automate granting them permissions in
your app. This can save them time of manually making an account; and having to
store yet another password.

## Reasons

To provide the most coverage in the United States (US) for Americans to be able
to use this system Apple and Google have been chosen. A considerable amount of
mobile devices in America use either Apple or Android operating systems (OS).
Making your app very accessible to most US citizens.

Also, other providers can be added to extend the system by implementing the
`OIDCProvider` interface.

## About

This repository was meant to house closely related functionality for SSO using
an OIDC provider.

The `sso` package is the parent package. Child package live in the `pkg`
directory. Normallly these are going to be used directly in the parent package,
but that is not the case here. Any directory in `pkg` named after
a provider, should be the package you integrate into your application, with the
parent `sso` package being used to house shared functionalty between OIDC
providers. For example `google` is of course the implementation of the Google
IpP.

### Storing Information

The GPG library is used to encrypt the account you generate for a user then
store in an HTTP secure cookie. The value of the cookie is also base64 encoded,
to avoid escaping special characters during transit or JSON encoding and
decoding.

## Integrations

It is going to be hard to give examples since every application can do whatever
is necessary to complete the OIDC flow. Also, some OIDC providers do not seem
to provide details on how to properly log out. It seems they only care about
the process of you integrating them as an Idp into your application.

So here is what we will do. We'll try to explain in detail all the public
functions and methods and suggest when you may want to use them in a given flow.
Just in case these function and methods are not self-explanatory.

### Initial Login Flow

This is the flow where the client comes to your site and they do not have an
account.

1. On you login page, use the following method to generate a link, where
   the client will be sent to an OIDC providers consent page to authorize your
   application and gain access to some of the clients profile, like email or
2. name. See this [AuthLink Example] or a [Kohirens webapp Example].

---
[AuthLink Example]: pkg/google/example_authlink_test.go
[Kohirens webapp Example]: pkg/google/example_api_test.go