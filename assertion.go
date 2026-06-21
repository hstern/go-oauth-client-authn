// Copyright 2026 The go-oauth-client-authn Authors
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// assertionTypeJWTBearer is the client_assertion_type value for an RFC 7523
// §2.2 JWT bearer client assertion. It is the fixed URN both JWT client-
// authentication methods (client_secret_jwt, private_key_jwt) send alongside
// the assertion itself.
const assertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// defaultAssertionLifetime is the validity window applied to a client assertion
// when [WithAssertionLifetime] is not used: exp = iat + 60s.
//
// RFC 7523 §3 requires a short-lived assertion with a "reasonably soon"
// expiration but fixes no value. Sixty seconds is long enough to absorb modest
// client/AS clock skew on a single token request yet short enough that a
// captured assertion is useless almost immediately — and each assertion carries
// a unique jti, so there is no reuse window to widen by extending the lifetime.
const defaultAssertionLifetime = 60 * time.Second

// jtiBytes is the number of crypto/rand bytes behind each assertion's jti. 16
// bytes (128 bits) is collision-resistant for the per-request identifiers RFC
// 7523 §3 requires, and base64url-encodes to a compact 22-character string.
const jtiBytes = 16

// AssertionOption configures how an RFC 7523 §2.2 JWT client assertion is built.
// Options are supplied to the JWT client-authentication method constructors
// (client_secret_jwt, private_key_jwt), which thread them through to the shared
// builder; they let a caller adapt to an authorization server that deviates from
// the defaults — most often by requiring the issuer URL as the audience instead
// of the concrete endpoint, or a different assertion lifetime.
type AssertionOption func(*assertionConfig)

// assertionConfig is the resolved set of assertion settings for a single build.
// It is produced by [newAssertionConfig] from a method's []AssertionOption and
// consumed by [buildAssertion]; the zero value is not valid (use
// newAssertionConfig, which installs the defaults).
type assertionConfig struct {
	// audience overrides the req.URL-derived audience when non-empty.
	audience string
	// lifetime is the exp-minus-iat window for the assertion.
	lifetime time.Duration
	// keyID, when non-empty, is written as the JWT "kid" header parameter.
	keyID string
	// now supplies the current time; injectable so tests can pin iat/exp.
	now func() time.Time
}

// newAssertionConfig resolves opts over the defaults (60s lifetime, real clock,
// audience derived from the request). The JWT methods call it once per request
// with the options captured at construction time, so a single method value
// authenticates requests to any token-family endpoint.
func newAssertionConfig(opts ...AssertionOption) assertionConfig {
	cfg := assertionConfig{
		lifetime: defaultAssertionLifetime,
		now:      time.Now,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	return cfg
}

// WithAudience overrides the audience of the client assertion. By default the
// audience is derived from the request URL (see [buildAssertion]); some
// authorization servers instead require their issuer identifier, which this
// option supplies verbatim.
func WithAudience(aud string) AssertionOption {
	return func(c *assertionConfig) { c.audience = aud }
}

// WithAssertionLifetime overrides the assertion validity window (the gap between
// the iat and exp claims). The default is 60 seconds; a non-positive duration
// resets it to that default rather than minting an already-expired assertion.
func WithAssertionLifetime(d time.Duration) AssertionOption {
	return func(c *assertionConfig) {
		if d <= 0 {
			d = defaultAssertionLifetime
		}
		c.lifetime = d
	}
}

// WithKeyID sets the JWT "kid" header parameter, identifying which of a client's
// registered keys signed the assertion so the authorization server can select
// the matching verification key. It is most useful with private_key_jwt when a
// client has published several keys in its JWKS.
func WithKeyID(kid string) AssertionOption {
	return func(c *assertionConfig) { c.keyID = kid }
}

// withClock overrides the clock used for the iat and exp claims. It is
// unexported: production callers always want the real clock, and only in-package
// tests need deterministic timestamps.
func withClock(now func() time.Time) AssertionOption {
	return func(c *assertionConfig) {
		if now != nil {
			c.now = now
		}
	}
}

// buildAssertion builds and signs an RFC 7523 §2.2 JWT client assertion and
// returns it in compact serialization, ready to place in the client_assertion
// form parameter.
//
// key carries the signing algorithm and key; the JWT methods supply it — a
// crypto.Signer-backed key (wrapped as needed) with an RSA/EC algorithm for
// private_key_jwt, or the shared secret bytes with HS256 for client_secret_jwt.
// Taking the [jose.SigningKey] rather than a pre-built [jose.Signer] lets this
// one place own every protected-header parameter the spec fixes — alg, typ, and
// the optional kid from [WithKeyID] — so the two methods cannot drift on header
// shape.
//
// The claims follow RFC 7523 §3: iss and sub are both clientID (the client
// authenticates as itself), jti is a fresh 128-bit crypto/rand value generated
// per call so no two assertions collide, and iat/exp bound a short validity
// window from cfg's clock. The aud claim defaults to the request's endpoint URL
// normalized by [assertionAudience] (scheme, host, path — query and fragment
// stripped) so the same method binds correctly at the token, PAR, introspection,
// and revocation endpoints; [WithAudience] overrides it. When the request has no
// URL and no override is set there is no endpoint to bind to and a local error
// is returned.
//
// The returned error never contains the assertion, the signing key, or a
// secret: assertions and secrets are bearer-equivalent and are never logged or
// embedded in error text.
func buildAssertion(key jose.SigningKey, clientID string, req *http.Request, cfg assertionConfig) (string, error) {
	aud := cfg.audience
	if aud == "" {
		if req == nil || req.URL == nil {
			return "", errors.New("authn: cannot derive assertion audience: request has no URL; set WithAudience")
		}
		aud = assertionAudience(req.URL)
	}

	jti, err := newJTI()
	if err != nil {
		return "", err
	}

	signer, err := newAssertionSigner(key, cfg)
	if err != nil {
		return "", err
	}

	now := cfg.now()
	claims := jwt.Claims{
		Issuer:   clientID,
		Subject:  clientID,
		Audience: jwt.Audience{aud},
		ID:       jti,
		IssuedAt: jwt.NewNumericDate(now),
		Expiry:   jwt.NewNumericDate(now.Add(cfg.lifetime)),
	}

	assertion, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("authn: sign client assertion: %w", err)
	}
	return assertion, nil
}

// newAssertionSigner builds the JOSE signer for one assertion, fixing the
// protected header to typ=JWT (RFC 7523 §3 RECOMMENDED) and, when [WithKeyID]
// was set, the kid parameter. alg is implied by key.Algorithm.
func newAssertionSigner(key jose.SigningKey, cfg assertionConfig) (jose.Signer, error) {
	opts := (&jose.SignerOptions{}).WithType("JWT")
	if cfg.keyID != "" {
		opts = opts.WithHeader("kid", cfg.keyID)
	}
	signer, err := jose.NewSigner(key, opts)
	if err != nil {
		return nil, fmt.Errorf("authn: build assertion signer: %w", err)
	}
	return signer, nil
}

// newJTI returns a fresh base64url (unpadded) jti drawn from crypto/rand. RFC
// 7523 §3 requires the assertion identifier be unique; a 128-bit random value
// makes reuse and collision negligible without coordinating state.
func newJTI() (string, error) {
	b := make([]byte, jtiBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("authn: generate assertion jti: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// assertionAudience normalizes an endpoint URL into the assertion's aud claim:
// scheme, host (with any port), and path, with the query, fragment, and userinfo
// stripped. The audience identifies the endpoint, not a specific request, so two
// requests to the same endpoint that differ only in query parameters produce the
// same aud — and one method value works unchanged across the token, PAR,
// introspection, and revocation endpoints.
func assertionAudience(u *url.URL) string {
	normalized := url.URL{
		Scheme: u.Scheme,
		Host:   u.Host,
		Path:   u.Path,
	}
	return normalized.String()
}

// assertionFormParams returns an augmentForm callback that writes the two RFC
// 7523 §2.2 body parameters for assertion: client_assertion_type (the fixed
// jwt-bearer URN) and client_assertion (the signed JWT). Both JWT methods reuse
// it so the parameter names and ordering stay identical. Set, not Add, replaces
// any pre-existing values rather than duplicating them, matching the single-
// valued client-authentication contract.
func assertionFormParams(assertion string) func(url.Values) {
	return func(v url.Values) {
		v.Set("client_assertion_type", assertionTypeJWTBearer)
		v.Set("client_assertion", assertion)
	}
}
