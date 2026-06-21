// Copyright 2026 The go-oauth-client-authn Authors
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// captureForm runs an httptest server that records the posted form body, drives
// one form POST through the supplied Method, and returns the captured values. It
// is the shared harness behind every per-key-type assertion test: the assertion
// lands in the body exactly as a real authorization server would receive it.
func captureForm(t *testing.T, m Method, endpointPath, formBody string) url.Values {
	t.Helper()

	var captured url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read server-side body: %v", err)
		}
		captured, err = url.ParseQuery(string(body))
		if err != nil {
			t.Errorf("parse server-side body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := NewClient(m, nil)
	req, err := http.NewRequest(http.MethodPost, srv.URL+endpointPath, strings.NewReader(formBody))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", formContentType)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	_ = resp.Body.Close()

	return captured
}

// verifyAssertion parses and signature-verifies a captured client_assertion with
// pub, then returns its claims and protected header. A verification failure fails
// the test — the whole point of these tests is that the assertion is genuinely
// signed by the matching key.
func verifyAssertion(t *testing.T, raw string, alg jose.SignatureAlgorithm, pub crypto.PublicKey) (jwt.Claims, jose.Header) {
	t.Helper()
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{alg})
	if err != nil {
		t.Fatalf("parse assertion: %v", err)
	}
	var claims jwt.Claims
	if err := tok.Claims(pub, &claims); err != nil {
		t.Fatalf("verify assertion signature with public key: %v", err)
	}
	return claims, tok.Headers[0]
}

func TestPrivateKeyJWTName(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	if got := PrivateKeyJWT("c", key).Name(); got != "private_key_jwt" {
		t.Errorf("Name() = %q, want %q", got, "private_key_jwt")
	}
}

// TestPrivateKeyJWTPerKeyType exercises the canonical path for every supported
// key type: generate a key, round-trip a form POST through the method, capture
// the client_assertion, verify its signature with the matching public key, and
// assert the alg header and the iss/sub/aud claims.
func TestPrivateKeyJWTPerKeyType(t *testing.T) {
	t.Parallel()

	const clientID = "s6BhdRkqt3"
	const path = "/token"

	tests := []struct {
		name    string
		signer  crypto.Signer
		public  func(crypto.Signer) crypto.PublicKey
		opts    []AssertionOption
		wantAlg jose.SignatureAlgorithm
	}{
		{
			name:    "RSA default RS256",
			signer:  mustRSAKey(t, 2048),
			public:  func(s crypto.Signer) crypto.PublicKey { return s.Public() },
			wantAlg: jose.RS256,
		},
		{
			name:    "RSA PSS override PS256",
			signer:  mustRSAKey(t, 2048),
			public:  func(s crypto.Signer) crypto.PublicKey { return s.Public() },
			opts:    []AssertionOption{WithRSAPSS()},
			wantAlg: jose.PS256,
		},
		{
			name:    "EC P-256 ES256",
			signer:  mustECKey(t, elliptic.P256()),
			public:  func(s crypto.Signer) crypto.PublicKey { return s.Public() },
			wantAlg: jose.ES256,
		},
		{
			name:    "EC P-384 ES384",
			signer:  mustECKey(t, elliptic.P384()),
			public:  func(s crypto.Signer) crypto.PublicKey { return s.Public() },
			wantAlg: jose.ES384,
		},
		{
			name:    "EC P-521 ES512",
			signer:  mustECKey(t, elliptic.P521()),
			public:  func(s crypto.Signer) crypto.PublicKey { return s.Public() },
			wantAlg: jose.ES512,
		},
		{
			name:    "Ed25519 EdDSA",
			signer:  mustEd25519Key(t),
			public:  func(s crypto.Signer) crypto.PublicKey { return s.Public() },
			wantAlg: jose.EdDSA,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m := PrivateKeyJWT(clientID, tt.signer, tt.opts...)
			form := captureForm(t, m, path, "grant_type=client_credentials")

			if got := form.Get("client_assertion_type"); got != assertionTypeJWTBearer {
				t.Errorf("client_assertion_type = %q, want %q", got, assertionTypeJWTBearer)
			}
			if got := form.Get("grant_type"); got != "client_credentials" {
				t.Errorf("grant_type clobbered: got %q", got)
			}

			raw := form.Get("client_assertion")
			if raw == "" {
				t.Fatal("client_assertion is empty")
			}

			claims, hdr := verifyAssertion(t, raw, tt.wantAlg, tt.public(tt.signer))

			if hdr.Algorithm != string(tt.wantAlg) {
				t.Errorf("alg header = %q, want %q", hdr.Algorithm, tt.wantAlg)
			}
			if got := hdr.ExtraHeaders[jose.HeaderType]; got != "JWT" {
				t.Errorf("typ header = %v, want JWT", got)
			}
			if claims.Issuer != clientID {
				t.Errorf("iss = %q, want %q", claims.Issuer, clientID)
			}
			if claims.Subject != clientID {
				t.Errorf("sub = %q, want %q", claims.Subject, clientID)
			}
			if claims.Issuer != claims.Subject {
				t.Errorf("iss (%q) must equal sub (%q)", claims.Issuer, claims.Subject)
			}
			// aud is the endpoint URL the request was sent to.
			if len(claims.Audience) != 1 || !strings.HasSuffix(claims.Audience[0], path) {
				t.Errorf("aud = %v, want a single value ending in %q", claims.Audience, path)
			}
			if claims.ID == "" {
				t.Error("jti is empty, want a unique identifier")
			}
			if claims.IssuedAt == nil || claims.Expiry == nil {
				t.Error("iat and exp must both be set")
			}
		})
	}
}

// TestPrivateKeyJWTWrongKeyRejectsSignature is the negative of the verify path:
// an assertion signed by one RSA key must NOT verify against a different key.
func TestPrivateKeyJWTWrongKeyRejectsSignature(t *testing.T) {
	t.Parallel()
	signer := mustRSAKey(t, 2048)
	other := mustRSAKey(t, 2048)

	form := captureForm(t, PrivateKeyJWT("c", signer), "/token", "grant_type=client_credentials")
	raw := form.Get("client_assertion")

	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var claims jwt.Claims
	if err := tok.Claims(other.Public(), &claims); err == nil {
		t.Fatal("assertion verified against the wrong public key; signature check is broken")
	}
}

func TestPrivateKeyJWTWithKeyID(t *testing.T) {
	t.Parallel()
	signer := mustRSAKey(t, 2048)
	const kid = "2026-key-1"

	form := captureForm(t, PrivateKeyJWT("c", signer, WithKeyID(kid)), "/token", "grant_type=client_credentials")
	_, hdr := verifyAssertion(t, form.Get("client_assertion"), jose.RS256, signer.Public())
	if hdr.KeyID != kid {
		t.Errorf("kid header = %q, want %q", hdr.KeyID, kid)
	}
}

func TestPrivateKeyJWTWithAudienceOverride(t *testing.T) {
	t.Parallel()
	signer := mustECKey(t, elliptic.P256())
	const issuer = "https://issuer.example.com"

	form := captureForm(t, PrivateKeyJWT("c", signer, WithAudience(issuer)), "/token", "grant_type=client_credentials")
	claims, _ := verifyAssertion(t, form.Get("client_assertion"), jose.ES256, signer.Public())
	if len(claims.Audience) != 1 || claims.Audience[0] != issuer {
		t.Errorf("aud = %v, want override %q", claims.Audience, issuer)
	}
}

// TestPrivateKeyJWTNilSigner asserts a nil signer yields a Method whose RoundTrip
// fails rather than panicking, and that the error names neither key nor secret
// (there is none, but the contract is uniform).
func TestPrivateKeyJWTNilSigner(t *testing.T) {
	t.Parallel()
	m := PrivateKeyJWT("c", nil)
	if m.Name() != "private_key_jwt" {
		t.Errorf("Name() = %q, want private_key_jwt even with a nil signer", m.Name())
	}

	rt := m.RoundTripper(http.DefaultTransport)
	req, err := http.NewRequest(http.MethodPost, "https://as.example.com/token", strings.NewReader("grant_type=x"))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", formContentType)

	resp, err := rt.RoundTrip(req)
	if resp != nil {
		_ = resp.Body.Close()
		t.Errorf("expected a nil response on error, got %v", resp)
	}
	if err == nil {
		t.Fatal("expected an error from RoundTrip with a nil signer")
	}
	if !strings.Contains(err.Error(), "nil") {
		t.Errorf("error %q should explain the nil signer", err)
	}
}

// TestPrivateKeyJWTUnsupportedKeyType uses a stub crypto.Signer reporting an
// unsupported public-key type and asserts construction captures the error,
// surfaced from RoundTrip, naming the type but not the key.
func TestPrivateKeyJWTUnsupportedKeyType(t *testing.T) {
	t.Parallel()
	signer := stubSigner{public: unsupportedPublicKey{}}
	m := PrivateKeyJWT("c", signer)

	rt := m.RoundTripper(http.DefaultTransport)
	req, err := http.NewRequest(http.MethodPost, "https://as.example.com/token", strings.NewReader("grant_type=x"))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", formContentType)

	resp, err := rt.RoundTrip(req)
	if resp != nil {
		_ = resp.Body.Close()
		t.Errorf("expected a nil response on error, got %v", resp)
	}
	if err == nil {
		t.Fatal("expected an error from RoundTrip with an unsupported key type")
	}
	if !strings.Contains(err.Error(), "unsupported key type") {
		t.Errorf("error %q should name the unsupported key type", err)
	}
}

// TestPrivateKeyJWTSecretNeverInError signs with a real key, forces a failure by
// stripping the request URL (so aud cannot be derived), and asserts the error
// text contains neither the assertion nor any key-derived bytes.
func TestPrivateKeyJWTSecretNeverInError(t *testing.T) {
	t.Parallel()
	signer := mustRSAKey(t, 2048)
	m := PrivateKeyJWT("c", signer)

	rt := m.RoundTripper(roundTripperFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("base.RoundTrip should not be reached when assertion build fails")
		return nil, nil
	}))

	// A request with a nil URL and no WithAudience: buildAssertion fails before
	// signing, exercising the error path.
	req := &http.Request{Header: http.Header{"Content-Type": {formContentType}}}
	req.Body = io.NopCloser(strings.NewReader("grant_type=x"))

	resp, err := rt.RoundTrip(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Fatal("expected an error when no audience can be derived")
	}
	// The error must not embed any signing material. There is no assertion yet
	// (it failed before signing), but assert the modulus bytes never appear.
	mod := signer.Public().(*rsa.PublicKey).N.String()
	if strings.Contains(err.Error(), mod) {
		t.Error("error text leaked RSA modulus bytes")
	}
}

// --- key + signer helpers ---

func mustRSAKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return key
}

func mustECKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	return key
}

func mustEd25519Key(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	return priv
}

// stubSigner is a crypto.Signer whose Public reports an arbitrary key type. It
// drives the unsupported-key-type path without a real key.
type stubSigner struct {
	public crypto.PublicKey
}

func (s stubSigner) Public() crypto.PublicKey { return s.public }

func (stubSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}

// unsupportedPublicKey is a public-key type the library does not handle.
type unsupportedPublicKey struct{}
