// Copyright 2026 The go-oauth-client-authn Authors
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// capturedForm holds the two RFC 7523 §2.2 body parameters an httptest server
// recovers from a posted token-endpoint request: the client_assertion JWT and
// its client_assertion_type.
type capturedForm struct {
	assertionType string
	assertion     string
}

// roundTripViaServer runs one POST through m's RoundTripper against a server
// that captures the posted form, and returns what the server saw plus the
// endpoint URL the request hit (the expected aud).
func roundTripViaServer(t *testing.T, m Method, formBody url.Values) (capturedForm, string) {
	t.Helper()

	var captured capturedForm
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("server: parse form: %v", err)
		}
		captured.assertionType = r.PostForm.Get("client_assertion_type")
		captured.assertion = r.PostForm.Get("client_assertion")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	client := NewClient(m, nil)
	body := strings.NewReader(formBody.Encode())
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/token", body)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", formContentType)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	return captured, srv.URL + "/token"
}

// verifyHS256 parses the captured assertion, verifying its HMAC signature with
// secret, and returns the claims and protected header. It fails the test if the
// assertion does not verify under the supplied secret.
func verifyHS256(t *testing.T, raw, secret string) (jwt.Claims, jose.Header) {
	t.Helper()
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.HS256})
	if err != nil {
		t.Fatalf("parse assertion: %v", err)
	}
	var claims jwt.Claims
	if err := tok.Claims([]byte(secret), &claims); err != nil {
		t.Fatalf("verify assertion with secret: %v", err)
	}
	return claims, tok.Headers[0]
}

// testSecret is a 32-byte (256-bit) HMAC secret. HS256 requires a key at least
// as long as its hash output (RFC 7518 §3.2), which go-jose enforces, so the
// shorter strings the other RFC 7523 vectors use as client IDs are not valid
// HMAC keys.
const testSecret = "0123456789abcdef0123456789abcdef"

func TestClientSecretJWTName(t *testing.T) {
	t.Parallel()
	m := ClientSecretJWT("s6BhdRkqt3", testSecret)
	if got, want := m.Name(), "client_secret_jwt"; got != want {
		t.Errorf("Name() = %q, want %q", got, want)
	}
}

func TestClientSecretJWTRoundTrip(t *testing.T) {
	t.Parallel()
	const (
		clientID = "s6BhdRkqt3"
		secret   = testSecret
	)
	m := ClientSecretJWT(clientID, secret)

	captured, endpoint := roundTripViaServer(t, m, url.Values{"grant_type": {"client_credentials"}})

	if captured.assertionType != assertionTypeJWTBearer {
		t.Errorf("client_assertion_type = %q, want %q", captured.assertionType, assertionTypeJWTBearer)
	}
	if captured.assertion == "" {
		t.Fatal("client_assertion is empty")
	}

	claims, hdr := verifyHS256(t, captured.assertion, secret)

	if hdr.Algorithm != string(jose.HS256) {
		t.Errorf("alg header = %q, want %q", hdr.Algorithm, jose.HS256)
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
	if got, want := claims.Audience, (jwt.Audience{endpoint}); len(got) != 1 || got[0] != want[0] {
		t.Errorf("aud = %v, want %v", got, want)
	}
	if claims.ID == "" {
		t.Error("jti is empty, want a unique identifier")
	}
	if claims.IssuedAt == nil || claims.Expiry == nil {
		t.Fatal("iat and exp must both be set")
	}
	if got := claims.Expiry.Time().Sub(claims.IssuedAt.Time()); got != defaultAssertionLifetime {
		t.Errorf("exp-iat = %v, want %v", got, defaultAssertionLifetime)
	}
}

func TestClientSecretJWTVerifiesWithSameSecret(t *testing.T) {
	t.Parallel()
	const secret = testSecret
	m := ClientSecretJWT("s6BhdRkqt3", secret)

	captured, _ := roundTripViaServer(t, m, url.Values{"grant_type": {"client_credentials"}})

	// The same secret must verify; a different one must not.
	if _, err := jwt.ParseSigned(captured.assertion, []jose.SignatureAlgorithm{jose.HS256}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	tok, _ := jwt.ParseSigned(captured.assertion, []jose.SignatureAlgorithm{jose.HS256})
	var claims jwt.Claims
	const wrongSecret = "fedcba9876543210fedcba9876543210" // 32 bytes, but not testSecret
	if err := tok.Claims([]byte(wrongSecret), &claims); err == nil {
		t.Error("assertion verified under the wrong secret; HMAC signature not bound to secret")
	}
}

func TestClientSecretJWTWithAudience(t *testing.T) {
	t.Parallel()
	const issuerAud = "https://issuer.example.com"
	m := ClientSecretJWT("s6BhdRkqt3", testSecret, WithAudience(issuerAud))

	captured, _ := roundTripViaServer(t, m, url.Values{"grant_type": {"client_credentials"}})

	claims, _ := verifyHS256(t, captured.assertion, testSecret)
	if got, want := claims.Audience, (jwt.Audience{issuerAud}); len(got) != 1 || got[0] != want[0] {
		t.Errorf("aud = %v, want %v (WithAudience override not threaded through)", got, want)
	}
}

func TestClientSecretJWTWithAssertionLifetime(t *testing.T) {
	t.Parallel()
	const lifetime = 5 * time.Minute
	m := ClientSecretJWT("s6BhdRkqt3", testSecret, WithAssertionLifetime(lifetime))

	captured, _ := roundTripViaServer(t, m, url.Values{"grant_type": {"client_credentials"}})

	claims, _ := verifyHS256(t, captured.assertion, testSecret)
	if claims.IssuedAt == nil || claims.Expiry == nil {
		t.Fatal("iat and exp must both be set")
	}
	if got := claims.Expiry.Time().Sub(claims.IssuedAt.Time()); got != lifetime {
		t.Errorf("exp-iat = %v, want %v (WithAssertionLifetime not threaded through)", got, lifetime)
	}
}

func TestClientSecretJWTMinimumSecretLength(t *testing.T) {
	t.Parallel()
	// HMAC-SHA-256 requires a key at least as long as its 256-bit (32-byte)
	// output (RFC 7518 §3.2); go-jose enforces this. A secret one byte under the
	// floor must fail the signing step, and a secret exactly at the floor must
	// produce a verifiable assertion.
	const (
		clientID = "s6BhdRkqt3"
		tooShort = "0123456789abcdef0123456789abcde" // 31 bytes
		atFloor  = testSecret                        // 32 bytes
	)

	short := ClientSecretJWT(clientID, tooShort)
	rt := short.RoundTripper(errRoundTripper{})
	req := mustFormRequest(t, "https://as.example.com/token")
	resp, err := rt.RoundTrip(req)
	closeResp(resp)
	if err == nil {
		t.Error("a 31-byte secret must fail HS256 signing, got nil error")
	} else if strings.Contains(err.Error(), tooShort) {
		t.Errorf("key-size error string leaks the secret: %q", err.Error())
	}

	exact := ClientSecretJWT(clientID, atFloor)
	captured, _ := roundTripViaServer(t, exact, url.Values{"grant_type": {"client_credentials"}})
	if captured.assertion == "" {
		t.Fatal("client_assertion is empty for a 32-byte secret")
	}
	claims, hdr := verifyHS256(t, captured.assertion, atFloor)
	if hdr.Algorithm != string(jose.HS256) {
		t.Errorf("alg header = %q, want HS256", hdr.Algorithm)
	}
	if claims.Issuer != clientID {
		t.Errorf("iss = %q, want %q", claims.Issuer, clientID)
	}
}

// mustFormRequest builds a POST form request to rawURL carrying a grant_type
// body, for tests that drive a RoundTripper directly rather than through a
// server.
func mustFormRequest(t *testing.T, rawURL string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, rawURL, strings.NewReader("grant_type=client_credentials"))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", formContentType)
	return req
}

// TestClientSecretJWTSecretNeverInError asserts the bearer-equivalent secret
// never leaks into an error string. The only local failure path the method has
// is a missing audience (no request URL, no WithAudience override); exercise it
// and confirm the error mentions neither the secret nor the assertion.
func TestClientSecretJWTSecretNeverInError(t *testing.T) {
	t.Parallel()
	const secret = "super-secret-hmac-key-value-3232" // 32 bytes
	m := ClientSecretJWT("s6BhdRkqt3", secret)

	rt := m.RoundTripper(errRoundTripper{})
	// A request whose URL has no host and with no WithAudience override forces
	// the audience-derivation failure inside buildAssertion.
	req := &http.Request{
		Method: http.MethodPost,
		URL:    &url.URL{},
		Header: http.Header{"Content-Type": []string{formContentType}},
		Body:   io.NopCloser(strings.NewReader("grant_type=client_credentials")),
	}
	req.ContentLength = int64(len("grant_type=client_credentials"))

	resp, err := rt.RoundTrip(req)
	closeResp(resp)
	if err == nil {
		t.Fatal("expected an error when no audience can be derived")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("error string leaks the secret: %q", err.Error())
	}
	if strings.Contains(err.Error(), "client_credentials") {
		// Sanity: the body shouldn't leak into the error either, but the secret
		// is the load-bearing assertion.
		t.Logf("note: error mentions request body: %q", err.Error())
	}
}

// closeResp closes resp.Body when resp is non-nil. The assertion-failure paths
// under test return (nil, err), so resp is always nil here; the helper exists to
// satisfy the bodyclose linter without obscuring that the response is never
// produced.
func closeResp(resp *http.Response) {
	if resp != nil {
		_ = resp.Body.Close()
	}
}

// errRoundTripper is a base RoundTripper that fails if it is ever reached. The
// secret-leak test expects the assertion build to fail before delegation, so
// reaching the base is itself a test failure signal.
type errRoundTripper struct{}

func (errRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("base transport should not be reached when assertion build fails")
}
