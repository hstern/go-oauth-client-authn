// Copyright 2026 The go-oauth-client-authn Authors
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"net/http"

	jose "github.com/go-jose/go-jose/v4"
)

// ClientSecretJWT returns the client_secret_jwt client-authentication method
// (RFC 7523 §2.2). It authenticates by signing a short-lived JWT client
// assertion with HMAC-SHA-256 keyed on clientSecret and posting it in the
// client_assertion form parameter, alongside the fixed client_assertion_type
// URN. HS256 is the algorithm the spec fixes for client_secret_jwt: the shared
// secret is the HMAC key, so the same value both signs the assertion and lets
// the authorization server verify it.
//
// The assertion's claims follow RFC 7523 §3 — iss and sub are both clientID,
// aud is the request's endpoint URL (so one method value authenticates at the
// token, pushed-authorization, introspection, and revocation endpoints), jti is
// a fresh per-request crypto/rand identifier, and exp is a short window after
// iat. The opts adjust that build: [WithAudience] substitutes an authorization
// server that wants its issuer identifier as the audience, and
// [WithAssertionLifetime] changes the validity window. [WithKeyID] is accepted
// but rarely meaningful here — a client_secret_jwt client has a single shared
// secret, not a key set to select among; it is more useful with private_key_jwt.
//
// clientSecret is bearer-equivalent: it is the HMAC key, and anyone holding it
// can mint assertions indistinguishable from the client's. The returned Method
// holds it in memory and writes it only into the assertion's signature; it is
// never logged and never embedded in an error (see [buildAssertion]).
//
// HMAC-SHA-256 requires a key at least as long as its 256-bit output (RFC 7518
// §3.2), so clientSecret MUST be at least 32 bytes; a shorter secret makes the
// signing step fail at request time with a key-size error (which, like every
// error here, never echoes the secret). Beyond that floor the security of
// client_secret_jwt rests entirely on the secret's entropy: operators SHOULD
// provision a high-entropy 256-bit-or-longer secret, since RFC 7523 §8 warns a
// weak shared secret is brute-forceable offline from a single captured
// assertion. private_key_jwt avoids the shared-secret exposure altogether and
// is preferable where asymmetric keys are an option.
func ClientSecretJWT(clientID, clientSecret string, opts ...AssertionOption) Method {
	return clientSecretJWT{
		clientID:     clientID,
		clientSecret: clientSecret,
		opts:         opts,
	}
}

// clientSecretJWT is the client_secret_jwt Method. It holds the client identity,
// the shared secret (the HMAC key), and the assertion options captured at
// construction time; it carries no per-request state, so the same value safely
// decorates any number of base transports.
type clientSecretJWT struct {
	clientID     string
	clientSecret string
	opts         []AssertionOption
}

// Name reports the RFC 7591 token_endpoint_auth_method identifier,
// "client_secret_jwt".
func (clientSecretJWT) Name() string { return "client_secret_jwt" }

// RoundTripper returns an http.RoundTripper that builds a fresh HS256 client
// assertion for each request it carries — so every request gets a unique jti and
// an exp anchored to its own send time — adds the client_assertion and
// client_assertion_type form parameters to the body, and delegates to base.
//
// The caller's request is never mutated: augmentForm writes the augmented body
// onto a clone (the http.RoundTripper contract). When the assertion cannot be
// built — the only local failure being a request from which no audience can be
// derived (no URL and no [WithAudience] override) — the error is returned with a
// nil response and base is not reached. The error never contains the secret or
// the assertion.
func (m clientSecretJWT) RoundTripper(base http.RoundTripper) http.RoundTripper {
	return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		cfg := newAssertionConfig(m.opts...)
		key := jose.SigningKey{Algorithm: jose.HS256, Key: []byte(m.clientSecret)}

		assertion, err := buildAssertion(key, m.clientID, req, cfg)
		if err != nil {
			return nil, err
		}

		augmented, err := augmentForm(req, assertionFormParams(assertion))
		if err != nil {
			return nil, err
		}
		return base.RoundTrip(augmented)
	})
}
