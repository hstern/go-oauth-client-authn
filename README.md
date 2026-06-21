# go-oauth-client-authn

[![CI](https://github.com/hstern/go-oauth-client-authn/actions/workflows/ci.yml/badge.svg)](https://github.com/hstern/go-oauth-client-authn/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/hstern/go-oauth-client-authn.svg)](https://pkg.go.dev/github.com/hstern/go-oauth-client-authn)
[![Go Report Card](https://goreportcard.com/badge/github.com/hstern/go-oauth-client-authn)](https://goreportcard.com/report/github.com/hstern/go-oauth-client-authn)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Composable `net/http` round-trippers for **OAuth 2.0 client authentication**.

`go-oauth-client-authn` implements the client-authentication methods defined
across the OAuth 2.0 specifications as small, orthogonal
`http.RoundTripper` decorators. Pick a method, wrap your base transport, and
every request the transport carries to a token endpoint is authenticated — no
coupling to any particular OAuth client library.

> **Status: pre-publication.** The API is taking shape; the first tagged
> release will be `v0.1.0`. Interfaces may change before then.

## Install

```sh
go get github.com/hstern/go-oauth-client-authn
```

Requires Go 1.26 or newer. Runtime dependencies are the standard library plus
[`go-jose/go-jose/v4`](https://github.com/go-jose/go-jose), which is used only by
the JWT assertion methods (`client_secret_jwt`, `private_key_jwt`). The shared-
secret and mutual-TLS methods are stdlib-only. There are no other runtime
dependencies; the test suite additionally pulls
[`go-token-exchange`](https://github.com/hstern/go-token-exchange) to prove the
composition seam, but that never enters a consumer's `go.sum`.

## Choosing a method

All six methods authenticate the same way at the API level — construct a
`Method`, wrap a transport — but they differ sharply in their security posture.
Pick by the credential you can hold and the assurance you need.

| Method | Spec | Constructor | When to choose it | Security posture |
| --- | --- | --- | --- | --- |
| `client_secret_basic` | RFC 6749 §2.3.1 | `ClientSecretBasic` | Simplest registration; the server only supports HTTP Basic. | Shared secret sent on every request (base64, not encrypted). **Requires TLS.** Weakest. |
| `client_secret_post` | RFC 6749 §2.3.1 | `ClientSecretPost` | The server requires credentials in the form body rather than a header. | Shared secret sent in the body on every request. **Requires TLS.** Equivalent strength to basic. |
| `client_secret_jwt` | RFC 7523 §2.2 | `ClientSecretJWT` | You hold a shared secret but want to keep it off the wire. | HMAC-SHA-256 over a short-lived assertion: the secret signs but is never transmitted. Still a **shared secret** (both sides hold it). Secret MUST be ≥ 32 bytes. |
| `private_key_jwt` | RFC 7523 §2.2 | `PrivateKeyJWT` | New high-security deployments; you can hold a private key. | **Asymmetric.** The server holds only the public key; the private key can live in an HSM/KMS and never leaves it. Strongest software option. |
| `tls_client_auth` | RFC 8705 §2.1 | `TLSClientAuth` | The server validates a client certificate against a CA (PKI). | **Asymmetric**, bound to the TLS channel. Private key can be HSM/KMS-backed. Strongest; resists token replay across channels. |
| `self_signed_tls_client_auth` | RFC 8705 §2.2 | `SelfSignedTLSClientAuth` | mTLS without a CA; the server matches the cert against your registered JWKS. | Same channel-bound strength as `tls_client_auth`; differs only in server-side validation. |

Guidance in short:

- **For new, high-security deployments, prefer `private_key_jwt` or mutual TLS.**
  Both are asymmetric — the authorization server never holds your private key,
  so a breach of the server cannot impersonate you, and the key can sit in an
  HSM or KMS.
- **`client_secret_jwt`** is a meaningful step up from the plaintext-secret
  methods because the secret never travels, but it remains a *shared* secret:
  the server stores a verifier capable of minting your assertions.
- **`client_secret_basic` / `client_secret_post`** are fine for low-risk or
  legacy integrations, but they put a long-lived bearer secret on the wire on
  every request and depend entirely on TLS to protect it.

## Usage

The package exposes a `Method` interface and one constructor per method. A
configured `Method` decorates a base `http.RoundTripper`; `NewClient` is the
convenience wrapper that returns a ready `*http.Client`, and `Transport` returns
the bare `http.RoundTripper` when you want to assign it yourself. A `nil` base
defaults to `http.DefaultTransport`.

```go
import authn "github.com/hstern/go-oauth-client-authn"
```

**client_secret_basic** — credentials in the `Authorization` header:

```go
client := authn.NewClient(
    authn.ClientSecretBasic("s6BhdRkqt3", clientSecret),
    nil,
)
```

**client_secret_post** — credentials in the form body:

```go
client := authn.NewClient(
    authn.ClientSecretPost("s6BhdRkqt3", clientSecret),
    nil,
)
```

**client_secret_jwt** — HMAC-signed assertion (secret ≥ 32 bytes):

```go
client := authn.NewClient(
    authn.ClientSecretJWT("s6BhdRkqt3", clientSecret),
    nil,
)
```

**private_key_jwt** — assertion signed by a `crypto.Signer`:

```go
client := authn.NewClient(
    authn.PrivateKeyJWT("s6BhdRkqt3", signer), // signer is any crypto.Signer
    nil,
)
```

**tls_client_auth / self_signed_tls_client_auth** — mutual TLS. These need an
`*http.Transport` base so the client certificate can be injected into the TLS
handshake (see [Security notes](#security-notes)):

```go
cert, err := tls.LoadX509KeyPair("client.crt", "client.key")
// handle err

base := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13}}
client := authn.NewClient(authn.TLSClientAuth("s6BhdRkqt3", cert), base)
```

### Plugging into an existing transport chain

`Method` decorates whatever base `http.RoundTripper` you pass, so it slots into
an existing chain (logging, retries, tracing) by wrapping the transport you
already have:

```go
authenticated := authn.Transport(method, myExistingTransport)
httpClient := &http.Client{Transport: authenticated, Timeout: 10 * time.Second}
```

The same `Method` value is reusable and stateless: it composes onto any number
of base transports and authenticates requests to any token-family endpoint
(token, pushed-authorization, introspection, revocation), because the wire
effect is derived per request, not fixed at construction.

## Key input

For the asymmetric methods, a [`crypto.Signer`](https://pkg.go.dev/crypto#Signer)
is the canonical key input: it is the interface an HSM- or KMS-backed key
implements, so the private material can stay on the device and never enter your
process memory. `PrivateKeyJWT` takes a `crypto.Signer` directly.

When the key is on disk or arrives in a registration response, two convenience
parsers turn it into a `crypto.Signer` so you don't hand-roll `crypto/x509`:

```go
signer, err := authn.SignerFromPEM(pemBytes) // SEC 1, PKCS#1, or PKCS#8
signer, err := authn.SignerFromJWK(jwkBytes) // RFC 7517 JSON Web Key
```

`SignerFromJWK` rejects a JWK that carries only public-key material, since a key
used to sign assertions must be private.

## Composition

The library's reason to exist is to authenticate the requests a token-family
client makes. `NewClient` returns exactly the `*http.Client` such a client
consumes through its HTTP-client seam. Using
[`go-token-exchange`](https://github.com/hstern/go-token-exchange) (RFC 8693) as
the worked example — the same composition the test suite verifies end to end:

```go
hc := authn.NewClient(authn.PrivateKeyJWT(clientID, signer), nil)

client := tokenexchange.NewClient(
    tokenEndpoint,
    tokenexchange.WithHTTPClient(hc),
)

resp, err := client.Exchange(ctx, &tokenexchange.TokenExchangeRequest{
    GrantType:        tokenexchange.GrantTypeTokenExchange,
    SubjectToken:     subjectToken,
    SubjectTokenType: tokenexchange.TokenTypeAccessToken,
})
```

Client authentication and the grant share one form body without clobbering each
other: the method adds `client_id`, `client_assertion`, or an `Authorization`
header as appropriate, while the grant parameters (`grant_type`,
`subject_token`, …) pass through untouched. Any client that accepts a custom
`*http.Client` composes the same way.

## Security notes

- **Secrets, keys, and assertions are bearer-equivalent and never logged by the
  library.** Error values never embed a secret, a signing key, or an assertion.
  Treat them the same way in your own logs.
- **Always use TLS.** The shared-secret methods put a long-lived credential on
  the wire; the assertion methods put a bearer assertion on the wire. None of
  them is safe over plaintext HTTP.
- **`client_secret_jwt` requires a 32-byte secret floor.** HS256 needs a key at
  least as long as its 256-bit output (RFC 7518 §3.2); shorter secrets are
  rejected rather than silently weakened.
- **Assertions are short-lived and single-use.** Each assertion carries a fresh
  128-bit `jti` (RFC 7523 §3) and a short default lifetime (60 seconds), so a
  captured assertion is useless almost immediately. Tune the window with
  `WithAssertionLifetime` only if your authorization server's clock skew
  demands it.
- **Bind the assertion audience to the endpoint.** By default the `aud` claim is
  derived from the request URL, so one `Method` works across the token, PAR,
  introspection, and revocation endpoints. Use `WithAudience` when the server
  requires its issuer identifier instead.
- **mTLS requires an `*http.Transport` base.** A client certificate can only be
  injected through a transport that exposes a `TLSClientConfig`. The mTLS
  methods clone the base transport and set only the client certificate, leaving
  `MinVersion`, `RootCAs`, `ServerName`, and the rest untouched; if the base is
  not an `*http.Transport`, every request fails with a clear local error rather
  than going out unauthenticated.
- **Rotate keys without downtime.** Set the JWT `kid` header with `WithKeyID`
  and publish multiple keys in your JWKS so the authorization server can select
  the right verification key during a rollover.

## Spec references

- [RFC 6749 §2.3.1](https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1) —
  client password (`client_secret_basic`, `client_secret_post`).
- [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523) — JWT profile for OAuth 2.0
  client authentication (`client_secret_jwt`, `private_key_jwt`).
- [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705) — mutual-TLS client
  authentication (`tls_client_auth`, `self_signed_tls_client_auth`).
- [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591) — dynamic client
  registration, source of the `token_endpoint_auth_method` identifiers each
  `Method` reports via `Name()`.

## Status and versioning

This library is **pre-1.0**. It follows [Semantic Versioning](https://semver.org/);
while the major version is `0`, the public API may change between minor releases.
Pin a version and review the changelog before upgrading. The first tagged
release will be `v0.1.0`. The version is independent of the OAuth specifications
it implements.

## License

[Apache License 2.0](LICENSE).
