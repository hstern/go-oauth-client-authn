# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-06-21

Initial release: composable `net/http` round-trippers for OAuth 2.0 client
authentication.

### Added

- Composition core — the `Method` interface together with `Transport` and
  `NewClient`. A `Method` decorates a base `http.RoundTripper`; `Transport`
  applies it (defaulting to `http.DefaultTransport`); `NewClient` wraps the
  result in a ready `*http.Client`. The wire effect is derived from each
  request, so one configured method authenticates token, pushed-authorization,
  introspection, and revocation requests without per-endpoint configuration.
- Six client-authentication methods, each a small, orthogonal round-tripper
  decorator:
  - `client_secret_basic` and `client_secret_post` (RFC 6749 §2.3.1) via
    `ClientSecretBasic` and `ClientSecretPost`. Basic form-urlencodes the
    credentials before Base64 so secrets containing `:`, spaces, `+`, or
    non-ASCII bytes round-trip correctly.
  - `client_secret_jwt` (HS256) and `private_key_jwt` (RS/ES/PS via a
    `crypto.Signer`) (RFC 7523) via `ClientSecretJWT` and `PrivateKeyJWT`.
  - `tls_client_auth` and `self_signed_tls_client_auth` (RFC 8705) via
    `TLSClientAuth` and `SelfSignedTLSClientAuth`. The certificate
    authenticates, and `client_id` is still sent in the request body.
- JWT assertion options for the RFC 7523 methods: `WithAudience`,
  `WithAssertionLifetime`, `WithKeyID`, and `WithRSAPSS`. When no audience is
  set, the assertion `aud` is derived from the request URL, so a single
  configured method works against any token-family endpoint.
- TLS options for the RFC 8705 methods: `TLSOption` and `WithServerName`. The
  base transport's `TLSClientConfig` is cloned rather than mutated, so only the
  client certificate is added.
- Key helpers: `SignerFromPEM` and `SignerFromJWK`, which parse a PEM block or a
  JWK into a `crypto.Signer` for use with `PrivateKeyJWT`.
- `SpecVersion`, an informational constant naming the specifications the wire
  behavior is verified against (`RFC 6749 / 7523 / 8705`).
- A composition test proving the library sits cleanly underneath a higher-level
  RFC 8693 token-exchange client in the transport chain.

### Notes

- Runtime dependencies are the standard library plus
  [`go-jose/go-jose/v4`](https://github.com/go-jose/go-jose), used by the JWT
  assertion methods.
- Requires Go 1.26 or newer.

[Unreleased]: https://github.com/hstern/go-oauth-client-authn/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/hstern/go-oauth-client-authn/releases/tag/v0.1.0
