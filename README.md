# go-oauth-client-authn

Composable `net/http` round-trippers for **OAuth 2.0 client authentication**.

`go-oauth-client-authn` implements the client-authentication methods defined
across the OAuth 2.0 specifications as small, orthogonal
`http.RoundTripper` decorators. Pick a method, wrap your base transport, and
every request the transport carries to a token endpoint is authenticated — no
coupling to any particular OAuth client library.

> **Status: pre-publication.** The API is taking shape; the first tagged
> release will be `v0.1.0`. Interfaces may change before then.

## Methods

| Method | Spec | Constructor |
| --- | --- | --- |
| `client_secret_basic` | RFC 6749 §2.3.1 | `ClientSecretBasic` |
| `client_secret_post` | RFC 6749 §2.3.1 | `ClientSecretPost` |
| `client_secret_jwt` | RFC 7523 | `ClientSecretJWT` |
| `private_key_jwt` | RFC 7523 | `PrivateKeyJWT` |
| `tls_client_auth` | RFC 8705 | `TLSClientAuth` |
| `self_signed_tls_client_auth` | RFC 8705 | `SelfSignedTLSClientAuth` |

## Install

```sh
go get github.com/hstern/go-oauth-client-authn
```

Requires Go 1.26 or newer. Runtime dependencies are the standard library plus
[`go-jose/go-jose/v4`](https://github.com/go-jose/go-jose) for the JWT
assertion methods.

## Usage

The package exposes a `Method` interface and a small set of constructors. A
configured `Method` decorates a base `http.RoundTripper`; `NewClient` is the
convenience wrapper that returns a ready `*http.Client`. Worked examples land
with the implementation — see the godoc once the methods are in place.

## License

[Apache License 2.0](LICENSE).
