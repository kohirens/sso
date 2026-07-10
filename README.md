# SSO

Based on OIDC, these libraries were made to allow clients to sign in with an
OIDC provider. You get Apple and Google out-of-the-box.

## Summary

This project consist of several libraries that serve as a framework, which is
meant to provide developers with a comprehensive approach to implementing login
based on OAuth 2.0 using the OIDC layer.

The idea is that you import an OIDC provider that implements rules set by
interfaces in the `oidc` library. At the start of your application, configure
the library with info from your chosen OIDC provider. You SHOULD only need to
write minimal code to get it working. Initially it may take you an hour to
read the docs and comprehend, but 5-20 minutes to implement, depending on your
stack.

There is the main `oidc` library which contains interfaces that each provider
MUST implement. The OIDC Provider implementations are separate libraries so that
you only pull in what you need. To add a provider is just another package, no
worries about conflicts with other providers or versions.

The benefits allow your clients use of a login provider they know and may trust.
Account setup and scheme are integrated into this system. So it is not
compatible with existing login systems. However, for new system this can save
time having to implement your own.

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
[AuthLink Example]: google/example_authlink_test.go
[Kohirens webapp Example]: google/example_api_test.go