// Copyright 2026 The go-oauth-client-authn Authors
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"crypto"
	"crypto/elliptic"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

// Endpoint-agnosticism: one Method value authenticates requests to every
// token-family endpoint, with no per-endpoint configuration. The token endpoint
// (RFC 6749 §3.2), pushed authorization request (RFC 9126 §2), introspection
// (RFC 7662 §2.1), and revocation (RFC 7009 §2.1) all share the same client-
// authentication contract: the credential is carried in the request, and for the
// RFC 7523 JWT-assertion methods the assertion's aud claim is derived from each
// request's URL rather than fixed at construction time. These tests prove that
// property across the matrix of methods × endpoints.

// endpointCase describes one token-family endpoint: the path it is served at and
// a representative endpoint-specific form parameter that a real client would post
// to it (RFC 7009/7662 use "token"; RFC 9126 PAR uses authorization-request
// params such as "response_type"). The endpoint-specific param lets the form
// methods prove they augment, rather than replace, the body the endpoint already
// carries.
type endpointCase struct {
	name      string
	path      string
	bodyParam string // "key=value" the endpoint itself requires
}

// endpointCases is the token-family endpoint table. The four entries differ only
// in path (and the body param a real caller would send) — never in client-auth
// configuration. That is the whole point: the same Method is reused across all of
// them.
var endpointCases = []endpointCase{
	{name: "token RFC 6749", path: "/token", bodyParam: "grant_type=client_credentials"},
	{name: "par RFC 9126", path: "/par", bodyParam: "response_type=code"},
	{name: "introspection RFC 7662", path: "/introspect", bodyParam: "token=2YotnFZFEjr1zCsicMWpAA"},
	{name: "revocation RFC 7009", path: "/revoke", bodyParam: "token=45ghiukldjahdnhzdauz"},
}

// endpointCapture records what a single token-family request delivered: the path
// it hit, the parsed form body, and the Authorization header. One server fans the
// whole endpoint table out to a single handler, so a test can drive every
// endpoint through one Method value and inspect each landing.
type endpointCapture struct {
	path   string
	form   url.Values
	header http.Header
}

// endpointServer is a single httptest server that serves every endpoint in the
// table and records each request it receives keyed by path. It models a real
// authorization server exposing token/PAR/introspection/revocation on one origin,
// which is exactly the deployment the endpoint-agnosticism property targets: the
// same scheme://host, several paths, one client-auth method.
type endpointServer struct {
	srv      *httptest.Server
	captured map[string]endpointCapture
}

// endpointBaseURL returns the server origin (scheme://host) the endpoints are
// served under. Per-endpoint URLs are this joined with each case's path.
func (e *endpointServer) endpointBaseURL() string { return e.srv.URL }

// newEndpointServer starts a server whose single handler records every request
// against the path it arrived on. The recorded form and header are what the test
// asserts the client authentication against.
func newEndpointServer(t *testing.T) *endpointServer {
	t.Helper()

	e := &endpointServer{captured: make(map[string]endpointCapture)}
	e.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read server-side body at %s: %v", r.URL.Path, err)
		}
		form, err := url.ParseQuery(string(body))
		if err != nil {
			t.Errorf("parse server-side body at %s: %v", r.URL.Path, err)
		}
		e.captured[r.URL.Path] = endpointCapture{
			path:   r.URL.Path,
			form:   form,
			header: r.Header.Clone(),
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(e.srv.Close)
	return e
}

// drive sends one form POST to the named path through client and returns what the
// server recorded for it. A query string is appended to prove the JWT methods
// strip the query when deriving aud (RFC 7523 §3 audience is the endpoint, not the
// full request-target).
func (e *endpointServer) drive(t *testing.T, client *http.Client, path, query, bodyParam string) endpointCapture {
	t.Helper()

	target := e.srv.URL + path
	if query != "" {
		target += "?" + query
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, target, strings.NewReader(bodyParam))
	if err != nil {
		t.Fatalf("build request for %s: %v", path, err)
	}
	req.Header.Set("Content-Type", formContentType)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do for %s: %v", path, err)
	}
	_ = resp.Body.Close()

	got, ok := e.captured[path]
	if !ok {
		t.Fatalf("server recorded no request at %s", path)
	}
	return got
}

// endpointWantAudience returns the aud an RFC 7523 assertion should carry for a
// request to base+path: scheme://host/path with any query stripped. It mirrors
// the library's own assertionAudience derivation so the test pins the externally
// observable contract rather than re-deriving it differently.
func endpointWantAudience(t *testing.T, base, path string) string {
	t.Helper()
	u, err := url.Parse(base + path)
	if err != nil {
		t.Fatalf("parse %s%s: %v", base, path, err)
	}
	return (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}).String()
}

// TestEndpointAgnosticClientSecretBasic proves client_secret_basic authenticates
// at every token-family endpoint: the Authorization: Basic header is present and
// decodes to the configured credential regardless of which path the request hits.
// Basic is header-based, so the endpoint's own form params pass through untouched.
func TestEndpointAgnosticClientSecretBasic(t *testing.T) {
	t.Parallel()

	const clientID, clientSecret = "s6BhdRkqt3", "7Fjfp0ZBr1KtDRbnfVdmIw"
	server := newEndpointServer(t)
	client := NewClient(ClientSecretBasic(clientID, clientSecret), nil)

	for _, ec := range endpointCases {
		t.Run(ec.name, func(t *testing.T) {
			got := server.drive(t, client, ec.path, "", ec.bodyParam)

			authz := got.header.Get("Authorization")
			if authz == "" {
				t.Fatalf("no Authorization header at %s", ec.path)
			}
			if !strings.HasPrefix(authz, "Basic ") {
				t.Fatalf("Authorization at %s = %q, want a Basic credential", ec.path, authz)
			}
			assertHeaderDecodes(t, authz, clientID, clientSecret)

			// The endpoint's own param survives — Basic touches only the header.
			wantKey, wantVal, _ := strings.Cut(ec.bodyParam, "=")
			if got := got.form.Get(wantKey); got != wantVal {
				t.Errorf("endpoint param %q at %s = %q, want %q", wantKey, ec.path, got, wantVal)
			}
		})
	}
}

// TestEndpointAgnosticClientSecretPost proves client_secret_post authenticates at
// every endpoint: client_id and client_secret arrive in the form and coexist with
// the endpoint's own param (RFC 7662/7009 "token", RFC 9126 "response_type"),
// proving the body is augmented, not replaced.
func TestEndpointAgnosticClientSecretPost(t *testing.T) {
	t.Parallel()

	const clientID, clientSecret = "s6BhdRkqt3", "7Fjfp0ZBr1KtDRbnfVdmIw"
	server := newEndpointServer(t)
	client := NewClient(ClientSecretPost(clientID, clientSecret), nil)

	for _, ec := range endpointCases {
		t.Run(ec.name, func(t *testing.T) {
			got := server.drive(t, client, ec.path, "", ec.bodyParam)

			if got := got.form.Get("client_id"); got != clientID {
				t.Errorf("client_id at %s = %q, want %q", ec.path, got, clientID)
			}
			if got := got.form.Get("client_secret"); got != clientSecret {
				t.Errorf("client_secret at %s = %q, want %q", ec.path, got, clientSecret)
			}
			// No header-based credential: post is body-only.
			if authz := got.header.Get("Authorization"); authz != "" {
				t.Errorf("client_secret_post must not set Authorization, got %q at %s", authz, ec.path)
			}
			// The endpoint's own param coexists with the injected credentials.
			wantKey, wantVal, _ := strings.Cut(ec.bodyParam, "=")
			if got := got.form.Get(wantKey); got != wantVal {
				t.Errorf("endpoint param %q at %s = %q, want %q", wantKey, ec.path, got, wantVal)
			}
		})
	}
}

// endpointJWTMethod is one RFC 7523 assertion method exercised for
// aud-per-endpoint derivation. Each entry pairs a constructed Method with the
// public key and algorithm needed to verify the assertion it produces.
type endpointJWTMethod struct {
	name   string
	method Method
	pub    crypto.PublicKey
	alg    jose.SignatureAlgorithm
}

// TestEndpointAgnosticJWTAudPerEndpoint is the key proof: for each RFC 7523
// assertion method, a single Method value sent to every token-family endpoint
// produces a verifiable client_assertion whose aud claim equals that endpoint's
// URL (scheme://host/path, query stripped). Because aud is request-derived rather
// than fixed at construction, one method value works everywhere.
func TestEndpointAgnosticJWTAudPerEndpoint(t *testing.T) {
	t.Parallel()

	const clientID = "s6BhdRkqt3"
	const secret = "a-256-bit-or-longer-high-entropy-shared-secret!"
	ecKey := mustECKey(t, elliptic.P256())

	methods := []endpointJWTMethod{
		{
			name:   "private_key_jwt ES256",
			method: PrivateKeyJWT(clientID, ecKey),
			pub:    ecKey.Public(),
			alg:    jose.ES256,
		},
		{
			name:   "client_secret_jwt HS256",
			method: ClientSecretJWT(clientID, secret),
			pub:    []byte(secret),
			alg:    jose.HS256,
		},
	}

	for _, jm := range methods {
		t.Run(jm.name, func(t *testing.T) {
			t.Parallel()
			server := newEndpointServer(t)
			client := NewClient(jm.method, nil)

			for _, ec := range endpointCases {
				t.Run(ec.name, func(t *testing.T) {
					// A query string is attached to prove it is stripped from aud.
					got := server.drive(t, client, ec.path, "state=xyz", ec.bodyParam)

					if typ := got.form.Get("client_assertion_type"); typ != assertionTypeJWTBearer {
						t.Errorf("client_assertion_type at %s = %q, want %q", ec.path, typ, assertionTypeJWTBearer)
					}
					raw := got.form.Get("client_assertion")
					if raw == "" {
						t.Fatalf("client_assertion missing at %s", ec.path)
					}
					claims, _ := verifyAssertion(t, raw, jm.alg, jm.pub)

					wantAud := endpointWantAudience(t, server.endpointBaseURL(), ec.path)
					if len(claims.Audience) != 1 || claims.Audience[0] != wantAud {
						t.Errorf("aud at %s = %v, want single value %q", ec.path, claims.Audience, wantAud)
					}
					if claims.Issuer != clientID || claims.Subject != clientID {
						t.Errorf("iss/sub at %s = %q/%q, want %q", ec.path, claims.Issuer, claims.Subject, clientID)
					}
					if claims.ID == "" {
						t.Errorf("jti empty at %s", ec.path)
					}
					// The endpoint's own param coexists with the assertion params.
					wantKey, wantVal, _ := strings.Cut(ec.bodyParam, "=")
					if got := got.form.Get(wantKey); got != wantVal {
						t.Errorf("endpoint param %q at %s = %q, want %q", wantKey, ec.path, got, wantVal)
					}
				})
			}
		})
	}
}

// TestEndpointAgnosticSingleMethodAcrossAllEndpoints reuses one PrivateKeyJWT
// value, constructed exactly once, across all four endpoints in sequence. It
// proves the Method carries no per-endpoint state: each request gets a fresh
// assertion whose aud tracks the path it was sent to, and the jti differs per
// request (a fresh assertion, not a cached one).
func TestEndpointAgnosticSingleMethodAcrossAllEndpoints(t *testing.T) {
	t.Parallel()

	const clientID = "s6BhdRkqt3"
	key := mustECKey(t, elliptic.P256())
	method := PrivateKeyJWT(clientID, key) // constructed ONCE, reused below
	server := newEndpointServer(t)
	client := NewClient(method, nil)

	seenJTI := make(map[string]string)
	for _, ec := range endpointCases {
		got := server.drive(t, client, ec.path, "", ec.bodyParam)

		raw := got.form.Get("client_assertion")
		if raw == "" {
			t.Fatalf("client_assertion missing at %s", ec.path)
		}
		claims, _ := verifyAssertion(t, raw, jose.ES256, key.Public())

		wantAud := endpointWantAudience(t, server.endpointBaseURL(), ec.path)
		if len(claims.Audience) != 1 || claims.Audience[0] != wantAud {
			t.Errorf("aud at %s = %v, want single value %q", ec.path, claims.Audience, wantAud)
		}
		if prev, dup := seenJTI[claims.ID]; dup {
			t.Errorf("jti %q reused: %s and %s share an assertion; method is caching per-endpoint",
				claims.ID, prev, ec.path)
		}
		seenJTI[claims.ID] = ec.path
	}

	if len(seenJTI) != len(endpointCases) {
		t.Errorf("expected %d distinct assertions, got %d distinct jti", len(endpointCases), len(seenJTI))
	}
}

// TestEndpointAgnosticAudDerivation is the focused aud-derivation case: the same
// PrivateKeyJWT value sent to two different endpoint URLs yields two assertions
// whose aud claims differ, each matching its own endpoint. This isolates the
// request-derived nature of aud from the broader matrix above.
func TestEndpointAgnosticAudDerivation(t *testing.T) {
	t.Parallel()

	const clientID = "s6BhdRkqt3"
	key := mustECKey(t, elliptic.P256())
	method := PrivateKeyJWT(clientID, key)
	server := newEndpointServer(t)
	client := NewClient(method, nil)

	tokenGot := server.drive(t, client, "/token", "", "grant_type=client_credentials")
	revokeGot := server.drive(t, client, "/revoke", "", "token=45ghiukldjahdnhzdauz")

	tokenClaims, _ := verifyAssertion(t, tokenGot.form.Get("client_assertion"), jose.ES256, key.Public())
	revokeClaims, _ := verifyAssertion(t, revokeGot.form.Get("client_assertion"), jose.ES256, key.Public())

	wantToken := endpointWantAudience(t, server.endpointBaseURL(), "/token")
	wantRevoke := endpointWantAudience(t, server.endpointBaseURL(), "/revoke")

	if len(tokenClaims.Audience) != 1 || tokenClaims.Audience[0] != wantToken {
		t.Errorf("/token aud = %v, want %q", tokenClaims.Audience, wantToken)
	}
	if len(revokeClaims.Audience) != 1 || revokeClaims.Audience[0] != wantRevoke {
		t.Errorf("/revoke aud = %v, want %q", revokeClaims.Audience, wantRevoke)
	}
	if tokenClaims.Audience[0] == revokeClaims.Audience[0] {
		t.Fatalf("aud did not track the endpoint: both assertions carry %q", tokenClaims.Audience[0])
	}
}
