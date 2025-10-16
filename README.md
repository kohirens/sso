# SSO

Single Sign On with OIDC providers Apple and Google, authored by Khalifah
Khalil Shabazz.

## Summary

This system provides a library to allow clients to sign in with an OIDC
provider. By default, only Apple and Google are provided out of the box. You
can integrate this library directly into an application to Allow clients to log
in and grant them permissions. This can save them time of manually making an
account; or having to store yet another password.

## Reasons

To provide the most coverage in the United States (US) for Americans to be able
to use this system Apple and Google have been chosen. Most mobile phone devices
in America host their operating systems (OS). So most US citizens are likely
to have at least one, if not both, providers accounts.

Also, other providers can be added to extend the system by implementing the
`OIDCProvider` interface.