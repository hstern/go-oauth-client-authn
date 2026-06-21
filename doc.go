// Copyright 2026 The go-oauth-client-authn Authors
// SPDX-License-Identifier: Apache-2.0

// Package authn provides composable net/http RoundTrippers that perform
// OAuth 2.0 client authentication.
//
// It implements the client-authentication methods defined across the OAuth 2.0
// family of specifications — client_secret_basic and client_secret_post
// (RFC 6749 §2.3.1), client_secret_jwt and private_key_jwt (RFC 7523), and
// tls_client_auth and self_signed_tls_client_auth (RFC 8705) — as small,
// orthogonal http.RoundTripper decorators that wrap a base transport.
//
// The package is intentionally framework-neutral: a configured method produces
// an http.RoundTripper (or a ready *http.Client) that authenticates every
// request it carries to a token endpoint, with no dependency on any particular
// OAuth client library. It composes with higher-level flows — for example an
// RFC 8693 token-exchange client — by sitting underneath them in the transport
// chain.
//
// This is a stub during phase 1 of the build; the Method interface and the
// per-method constructors land in subsequent phases.
package authn
