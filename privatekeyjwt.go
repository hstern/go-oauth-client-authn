// Copyright 2026 The go-oauth-client-authn Authors
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"
)

// PrivateKeyJWT returns the private_key_jwt client-authentication method (RFC
// 7523 §2.2). It authenticates by signing a short-lived JWT assertion with the
// client's private key and posting it in the client_assertion form parameter,
// alongside the fixed client_assertion_type URN — the asymmetric counterpart to
// client_secret_jwt, which signs with a shared secret.
//
// signer is the client's private key as a [crypto.Signer]. This is the canonical
// key input precisely because [crypto.Signer] is the interface an HSM- or
// KMS-backed key satisfies without the raw private material ever leaving the
// device: the library asks the signer to sign bytes and never sees the key. An
// in-memory *rsa.PrivateKey, *ecdsa.PrivateKey, or ed25519.PrivateKey satisfies
// it too, so software keys work unchanged.
//
// The JWS algorithm is derived from the key type returned by signer.Public(),
// not chosen by the caller:
//
//   - *rsa.PublicKey      → RS256 (RSASSA-PKCS1-v1_5); [WithRSAPSS] selects PS256
//   - *ecdsa.PublicKey    → ES256 / ES384 / ES512 by curve (P-256 / P-384 / P-521)
//   - ed25519.PublicKey   → EdDSA
//
// Any other key type — or an RSA key the signer reports as too small to be
// usable — is a construction error surfaced lazily: the returned Method's
// RoundTripper produces a transport whose RoundTrip fails with that error on the
// first request, so a misconfigured key never silently authenticates. A nil
// signer is treated the same way.
//
// opts are the shared [AssertionOption] values (audience override, lifetime,
// kid, RSA-PSS selection). They are captured once and applied per request, so a
// single PrivateKeyJWT value authenticates requests to the token,
// pushed-authorization, introspection, and revocation endpoints unchanged —
// each assertion's aud is derived from that request's URL.
//
// The signing key and the assertion are bearer-equivalent: like every Method
// here, this one writes the assertion only into the request body and never logs
// the key, the assertion, or either in an error.
func PrivateKeyJWT(clientID string, signer crypto.Signer, opts ...AssertionOption) Method {
	m := privateKeyJWT{clientID: clientID, signer: signer, opts: opts}
	// Resolve the signing algorithm eagerly so a bad key is captured at
	// construction. The error is reported from RoundTrip (not from this
	// constructor, which has no error return) to keep the Method API uniform:
	// every constructor returns a Method, never (Method, error).
	if signer == nil {
		m.algErr = errors.New("authn: private_key_jwt: signer is nil")
	} else if _, err := signingAlgorithm(signer.Public(), newAssertionConfig(opts...).rsaPSS); err != nil {
		m.algErr = err
	}
	return m
}

// privateKeyJWT is the private_key_jwt Method. It holds the client identifier,
// the signer, the assertion options, and any algorithm-derivation error captured
// at construction. It carries no per-request state, so the same value safely
// decorates any number of base transports.
type privateKeyJWT struct {
	clientID string
	signer   crypto.Signer
	opts     []AssertionOption
	// algErr, when non-nil, is the construction-time key error (nil/unsupported
	// signer) replayed from each RoundTrip.
	algErr error
}

// Name reports the RFC 7591 token_endpoint_auth_method identifier,
// "private_key_jwt".
func (privateKeyJWT) Name() string { return "private_key_jwt" }

// RoundTripper returns an http.RoundTripper that signs an RFC 7523 §2.2 JWT
// assertion with the client's key and adds client_assertion and
// client_assertion_type to the form body of every request it carries, then
// delegates to base. The caller's request is never mutated: augmentForm builds
// the augmented body on a clone (the http.RoundTripper contract).
//
// If the key was unusable at construction (nil or an unsupported type), every
// RoundTrip fails with that error and a nil response — the request is never sent
// unauthenticated. Per-request signing failures (assertion build/sign, or a
// missing endpoint to bind aud to) are returned the same way.
func (m privateKeyJWT) RoundTripper(base http.RoundTripper) http.RoundTripper {
	return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		if m.algErr != nil {
			return nil, m.algErr
		}

		cfg := newAssertionConfig(m.opts...)
		alg, err := signingAlgorithm(m.signer.Public(), cfg.rsaPSS)
		if err != nil {
			return nil, err
		}

		key := jose.SigningKey{Algorithm: alg, Key: cryptosigner.Opaque(m.signer)}
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

// signingAlgorithm derives the JWS signature algorithm for a private_key_jwt
// assertion from the signer's public key, mirroring the key-type-to-alg mapping
// RFC 7518 §3 fixes. rsaPSS selects PS256 over RS256 for RSA keys (see
// [WithRSAPSS]) and is ignored for every other key type.
//
// An unsupported key type — or an RSA key whose modulus is implausibly small —
// returns an error that names the type but never the key material, so it is safe
// to log.
func signingAlgorithm(pub crypto.PublicKey, rsaPSS bool) (jose.SignatureAlgorithm, error) {
	switch key := pub.(type) {
	case *rsa.PublicKey:
		if rsaPSS {
			return jose.PS256, nil
		}
		return jose.RS256, nil
	case *ecdsa.PublicKey:
		switch key.Curve {
		case elliptic.P256():
			return jose.ES256, nil
		case elliptic.P384():
			return jose.ES384, nil
		case elliptic.P521():
			return jose.ES512, nil
		default:
			return "", fmt.Errorf("authn: private_key_jwt: unsupported EC curve %q", curveName(key.Curve))
		}
	case ed25519.PublicKey:
		return jose.EdDSA, nil
	default:
		return "", fmt.Errorf("authn: private_key_jwt: unsupported key type %T", pub)
	}
}

// curveName reports a human-readable name for an elliptic curve for error text,
// falling back to "<unknown>" for a nil or unnamed curve. It exists only so the
// unsupported-curve error is legible without leaking key material.
func curveName(c elliptic.Curve) string {
	if c == nil {
		return "<unknown>"
	}
	if params := c.Params(); params != nil && params.Name != "" {
		return params.Name
	}
	return "<unnamed>"
}
