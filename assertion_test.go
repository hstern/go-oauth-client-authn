// Copyright 2026 The go-oauth-client-authn Authors
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/url"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// newTestRSAKey returns an RSA key and the jose.SigningKey (RS256) over it.
func newTestRSAKey(t *testing.T) (*rsa.PrivateKey, jose.SigningKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return key, jose.SigningKey{Algorithm: jose.RS256, Key: key}
}

// newTestECKey returns a P-256 EC key and the jose.SigningKey (ES256) over it.
func newTestECKey(t *testing.T) (*ecdsa.PrivateKey, jose.SigningKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	return key, jose.SigningKey{Algorithm: jose.ES256, Key: key}
}

// parseAssertion verifies the compact JWS signature with pub and returns its
// claims plus the protected header.
func parseAssertion(t *testing.T, raw string, alg jose.SignatureAlgorithm, pub crypto.PublicKey) (jwt.Claims, jose.Header) {
	t.Helper()
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{alg})
	if err != nil {
		t.Fatalf("parse assertion: %v", err)
	}
	var claims jwt.Claims
	if err := tok.Claims(pub, &claims); err != nil {
		t.Fatalf("verify/parse claims: %v", err)
	}
	return claims, tok.Headers[0]
}

func mustRequest(t *testing.T, method, rawURL string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, rawURL, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	return req
}

func TestBuildAssertionRSAClaimsAndHeader(t *testing.T) {
	t.Parallel()
	key, sk := newTestRSAKey(t)
	const clientID = "s6BhdRkqt3"
	req := mustRequest(t, http.MethodPost, "https://as.example.com/token")

	fixed := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	cfg := newAssertionConfig(withClock(func() time.Time { return fixed }))

	raw, err := buildAssertion(sk, clientID, req, cfg)
	if err != nil {
		t.Fatalf("buildAssertion: %v", err)
	}

	claims, hdr := parseAssertion(t, raw, jose.RS256, key.Public())

	if claims.Issuer != clientID {
		t.Errorf("iss = %q, want %q", claims.Issuer, clientID)
	}
	if claims.Subject != clientID {
		t.Errorf("sub = %q, want %q", claims.Subject, clientID)
	}
	if claims.Issuer != claims.Subject {
		t.Errorf("iss (%q) must equal sub (%q)", claims.Issuer, claims.Subject)
	}
	if got, want := claims.Audience, (jwt.Audience{"https://as.example.com/token"}); len(got) != 1 || got[0] != want[0] {
		t.Errorf("aud = %v, want %v", got, want)
	}
	if claims.ID == "" {
		t.Error("jti is empty, want a unique identifier")
	}
	if claims.IssuedAt == nil || claims.Expiry == nil {
		t.Fatal("iat and exp must both be set")
	}
	if got := claims.IssuedAt.Time(); !got.Equal(fixed) {
		t.Errorf("iat = %v, want %v", got, fixed)
	}
	if got, want := claims.Expiry.Time(), fixed.Add(defaultAssertionLifetime); !got.Equal(want) {
		t.Errorf("exp = %v, want %v", got, want)
	}
	if got := claims.Expiry.Time().Sub(claims.IssuedAt.Time()); got != defaultAssertionLifetime {
		t.Errorf("exp-iat = %v, want %v", got, defaultAssertionLifetime)
	}

	if hdr.Algorithm != string(jose.RS256) {
		t.Errorf("alg header = %q, want %q", hdr.Algorithm, jose.RS256)
	}
	if got := hdr.ExtraHeaders[jose.HeaderType]; got != "JWT" {
		t.Errorf("typ header = %v, want JWT", got)
	}
	if hdr.KeyID != "" {
		t.Errorf("kid header = %q, want empty when WithKeyID unset", hdr.KeyID)
	}
}

func TestBuildAssertionECKey(t *testing.T) {
	t.Parallel()
	key, sk := newTestECKey(t)
	const clientID = "ec-client"
	req := mustRequest(t, http.MethodPost, "https://as.example.com/token")

	raw, err := buildAssertion(sk, clientID, req, newAssertionConfig())
	if err != nil {
		t.Fatalf("buildAssertion: %v", err)
	}
	claims, hdr := parseAssertion(t, raw, jose.ES256, key.Public())
	if claims.Issuer != clientID {
		t.Errorf("iss = %q, want %q", claims.Issuer, clientID)
	}
	if hdr.Algorithm != string(jose.ES256) {
		t.Errorf("alg header = %q, want %q", hdr.Algorithm, jose.ES256)
	}
}

func TestBuildAssertionJTIUniquePerCall(t *testing.T) {
	t.Parallel()
	_, sk := newTestRSAKey(t)
	req := mustRequest(t, http.MethodPost, "https://as.example.com/token")

	raw1, err := buildAssertion(sk, "c", req, newAssertionConfig())
	if err != nil {
		t.Fatalf("buildAssertion #1: %v", err)
	}
	raw2, err := buildAssertion(sk, "c", req, newAssertionConfig())
	if err != nil {
		t.Fatalf("buildAssertion #2: %v", err)
	}
	c1 := unsafeClaims(t, raw1)
	c2 := unsafeClaims(t, raw2)
	if c1.ID == "" || c2.ID == "" {
		t.Fatal("both assertions must carry a jti")
	}
	if c1.ID == c2.ID {
		t.Errorf("jti must differ across calls; both were %q", c1.ID)
	}
}

func TestBuildAssertionWithAudienceOverride(t *testing.T) {
	t.Parallel()
	_, sk := newTestRSAKey(t)
	req := mustRequest(t, http.MethodPost, "https://as.example.com/token?foo=bar")

	const issuerAud = "https://issuer.example.com"
	raw, err := buildAssertion(sk, "c", req, newAssertionConfig(WithAudience(issuerAud)))
	if err != nil {
		t.Fatalf("buildAssertion: %v", err)
	}
	c := unsafeClaims(t, raw)
	if len(c.Audience) != 1 || c.Audience[0] != issuerAud {
		t.Errorf("aud = %v, want override %q", c.Audience, issuerAud)
	}
}

func TestBuildAssertionWithLifetime(t *testing.T) {
	t.Parallel()
	_, sk := newTestRSAKey(t)
	req := mustRequest(t, http.MethodPost, "https://as.example.com/token")

	const lifetime = 5 * time.Minute
	raw, err := buildAssertion(sk, "c", req, newAssertionConfig(WithAssertionLifetime(lifetime)))
	if err != nil {
		t.Fatalf("buildAssertion: %v", err)
	}
	c := unsafeClaims(t, raw)
	if got := c.Expiry.Time().Sub(c.IssuedAt.Time()); got != lifetime {
		t.Errorf("exp-iat = %v, want %v", got, lifetime)
	}
}

func TestBuildAssertionWithKeyID(t *testing.T) {
	t.Parallel()
	key, sk := newTestRSAKey(t)
	req := mustRequest(t, http.MethodPost, "https://as.example.com/token")

	const kid = "2026-key-1"
	raw, err := buildAssertion(sk, "c", req, newAssertionConfig(WithKeyID(kid)))
	if err != nil {
		t.Fatalf("buildAssertion: %v", err)
	}
	_, hdr := parseAssertion(t, raw, jose.RS256, key.Public())
	if hdr.KeyID != kid {
		t.Errorf("kid header = %q, want %q", hdr.KeyID, kid)
	}
}

func TestBuildAssertionClockInjection(t *testing.T) {
	t.Parallel()
	_, sk := newTestRSAKey(t)
	req := mustRequest(t, http.MethodPost, "https://as.example.com/token")

	fixed := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	cfg := newAssertionConfig(withClock(func() time.Time { return fixed }))
	raw, err := buildAssertion(sk, "c", req, cfg)
	if err != nil {
		t.Fatalf("buildAssertion: %v", err)
	}
	c := unsafeClaims(t, raw)
	if got := c.IssuedAt.Time(); !got.Equal(fixed) {
		t.Errorf("iat = %v, want %v", got, fixed)
	}
	if got, want := c.Expiry.Time(), fixed.Add(defaultAssertionLifetime); !got.Equal(want) {
		t.Errorf("exp = %v, want %v", got, want)
	}
}

func TestAssertionAudienceNormalization(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		rawURL string
		want   string
	}{
		{"plain", "https://as.example.com/token", "https://as.example.com/token"},
		{"strip query", "https://as.example.com/token?grant_type=x&code=y", "https://as.example.com/token"},
		{"strip fragment", "https://as.example.com/token#frag", "https://as.example.com/token"},
		{"strip query and fragment", "https://as.example.com/token?a=b#c", "https://as.example.com/token"},
		{"preserve port", "https://as.example.com:8443/token", "https://as.example.com:8443/token"},
		{"par endpoint", "https://as.example.com/as/par", "https://as.example.com/as/par"},
		{"no path", "https://as.example.com", "https://as.example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			u, err := url.Parse(tt.rawURL)
			if err != nil {
				t.Fatalf("parse %q: %v", tt.rawURL, err)
			}
			if got := assertionAudience(u); got != tt.want {
				t.Errorf("assertionAudience(%q) = %q, want %q", tt.rawURL, got, tt.want)
			}
		})
	}
}

func TestBuildAssertionDerivedAudienceStripsQuery(t *testing.T) {
	t.Parallel()
	_, sk := newTestRSAKey(t)
	req := mustRequest(t, http.MethodPost, "https://as.example.com:8443/token?grant_type=client_credentials#x")

	raw, err := buildAssertion(sk, "c", req, newAssertionConfig())
	if err != nil {
		t.Fatalf("buildAssertion: %v", err)
	}
	c := unsafeClaims(t, raw)
	const want = "https://as.example.com:8443/token"
	if len(c.Audience) != 1 || c.Audience[0] != want {
		t.Errorf("aud = %v, want %q", c.Audience, want)
	}
}

func TestBuildAssertionNoURLNoOverride(t *testing.T) {
	t.Parallel()
	_, sk := newTestRSAKey(t)
	// A request with a nil URL and no WithAudience override is a local failure:
	// there is no endpoint to bind the assertion to.
	req := &http.Request{}

	_, err := buildAssertion(sk, "c", req, newAssertionConfig())
	if err == nil {
		t.Fatal("expected an error when neither req.URL nor WithAudience supplies an audience")
	}
}

func TestAssertionFormParams(t *testing.T) {
	t.Parallel()
	v := url.Values{"grant_type": {"client_credentials"}}
	assertionFormParams("the.signed.jwt")(v)

	if got := v.Get("client_assertion_type"); got != assertionTypeJWTBearer {
		t.Errorf("client_assertion_type = %q, want %q", got, assertionTypeJWTBearer)
	}
	if got := v.Get("client_assertion"); got != "the.signed.jwt" {
		t.Errorf("client_assertion = %q, want %q", got, "the.signed.jwt")
	}
	if got := v.Get("grant_type"); got != "client_credentials" {
		t.Errorf("existing grant_type clobbered: %q", got)
	}
}

func TestAssertionTypeConstant(t *testing.T) {
	t.Parallel()
	const want = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	if assertionTypeJWTBearer != want {
		t.Errorf("assertionTypeJWTBearer = %q, want %q", assertionTypeJWTBearer, want)
	}
}

// unsafeClaims extracts the claims of a compact JWS WITHOUT verifying the
// signature. It exists only so tests can read jti/iat/exp/aud without threading
// the public key through; signature-verifying paths use parseAssertion.
func unsafeClaims(t *testing.T, raw string) jwt.Claims {
	t.Helper()
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256, jose.ES256})
	if err != nil {
		t.Fatalf("parse assertion: %v", err)
	}
	var claims jwt.Claims
	if err := tok.UnsafeClaimsWithoutVerification(&claims); err != nil {
		t.Fatalf("read claims: %v", err)
	}
	return claims
}
