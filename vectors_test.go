// Copyright 2026 The go-oauth-client-authn Authors
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// This file is the conformance layer for the library: it pins the byte-stable
// parts of each method's wire output against the RFC example figures and drives
// every method through a single httptest authorization-server stub that asserts
// the exact request shape uniformly. It deliberately does not re-prove the
// per-method unit behaviour the *_test.go siblings already cover; its value is
// the RFC 6749 §2.3.1 canonical-example anchor and the one AS stub that checks
// all methods the same way, so a regression in any method's wire shape surfaces
// here regardless of which method introduced it.
//
// Sources of truth:
//   - RFC 6749 §2.3.1 (https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1) —
//     the Basic credential figure and the client_secret_post form parameters.
//   - RFC 7523 §2.2 (https://www.rfc-editor.org/rfc/rfc7523#section-2.2) — the
//     client_assertion / client_assertion_type parameters and JWT claim set.
//   - RFC 8705 §2 (https://www.rfc-editor.org/rfc/rfc8705) — client_id in the
//     body under a mutual-TLS handshake.
//
// All helpers and types added here are prefixed "vector" so they cannot collide
// with the other conformance files that land in this package in parallel.

// vectorClientID and vectorClientSecret are the credentials from the worked
// example in RFC 6749 §2.3.1. Pinning the library's output against these exact
// values is the strongest available conformance anchor: the RFC prints the
// resulting Basic header verbatim, so the golden string below is the spec's own
// bytes, not a value this test invented.
const (
	vectorClientID     = "s6BhdRkqt3"
	vectorClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw"

	// vectorBasicHeader is the literal Authorization header RFC 6749 §2.3.1
	// shows for the credentials above. base64("s6BhdRkqt3:7Fjfp0ZBr1KtDRbnfVdmIw")
	// — neither value contains a character the form-urlencoding step alters, so
	// the figure doubles as a check that the encode-then-base64 pipeline is a
	// no-op on already-safe input.
	vectorBasicHeader = "Basic czZCaGRSa3F0Mzo3RmpmcDBaQnIxS3REUmJuZlZkbUl3"

	// vectorEndpointPath is the token-family endpoint every vector drives. The
	// AS stub mounts here; the JWT vectors expect it as the assertion audience.
	vectorEndpointPath = "/token"

	// vectorHMACSecret is a 32-byte HMAC key for the client_secret_jwt vector.
	// HS256 requires a key at least as long as its 256-bit output (RFC 7518
	// §3.2), which go-jose enforces, so the short RFC client id is not itself a
	// usable secret here.
	vectorHMACSecret = "0123456789abcdef0123456789abcdef"
)

// vectorASStub is a reusable conformance harness: an httptest authorization
// server that, for one expected client-authentication method, parses each
// incoming request and records the parts of its wire shape that matter to that
// method (the Basic header, the form parameters, the presented client-cert
// subject). A test drives a method through NewClient against the stub and then
// asserts the recorded fields equal the spec-mandated bytes.
//
// One stub type serves every method so the conformance check is uniform: the
// difference between methods is only which recorded fields a test inspects, not
// a bespoke server per method.
type vectorASStub struct {
	srv *httptest.Server

	// Recorded per request. The last request wins; the vectors send one each.
	authorization string     // raw Authorization header
	form          url.Values // parsed POST form (client_id, client_secret, assertions, grant_type, …)
	clientCertCN  string     // CommonName of the presented client cert, "" if none
	sawClientCert bool
}

// newVectorASStub starts a plain-HTTP AS stub. It fits client_secret_basic,
// client_secret_post, and the JWT-assertion methods — everything whose wire
// effect is a header or a body parameter. mTLS needs the TLS variant below.
func newVectorASStub(t *testing.T) *vectorASStub {
	t.Helper()
	s := &vectorASStub{}
	mux := http.NewServeMux()
	mux.HandleFunc(vectorEndpointPath, s.record)
	s.srv = httptest.NewServer(mux)
	t.Cleanup(s.srv.Close)
	return s
}

// endpoint is the absolute URL of the stub's token endpoint, suitable as the
// expected assertion audience.
func (s *vectorASStub) endpoint() string { return s.srv.URL + vectorEndpointPath }

// record captures the request shape and returns a canned OK. Parsing failures
// fail the test rather than being swallowed: a vector that cannot even be parsed
// as a form is a wire-shape regression worth surfacing loudly.
func (s *vectorASStub) record(w http.ResponseWriter, r *http.Request) {
	s.authorization = r.Header.Get("Authorization")
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		s.sawClientCert = true
		s.clientCertCN = r.TLS.PeerCertificates[0].Subject.CommonName
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "parse form: "+err.Error(), http.StatusBadRequest)
		return
	}
	s.form = r.PostForm
	w.WriteHeader(http.StatusOK)
}

// vectorDrive sends a single form POST carrying body through a client built from
// m against the stub, then returns the stub so a test can assert on what it saw.
// body is the pre-existing form the request already carries (e.g. grant_type),
// the parameters the method must preserve while adding its own.
//
// The method decorates a per-call *http.Transport rather than the default one:
// these vectors run in parallel against several short-lived httptest servers,
// and sharing http.DefaultTransport's connection pool across them lets one
// server's Close() tear down a pooled connection another request is mid-flight
// on ("connection broken: CloseIdleConnections called"). A dedicated base per
// client keeps each vector's connections isolated, and t.Cleanup drains the pool.
func (s *vectorASStub) vectorDrive(t *testing.T, m Method, body url.Values) {
	t.Helper()
	base := &http.Transport{}
	t.Cleanup(base.CloseIdleConnections)
	s.vectorDriveClient(t, NewClient(m, base), body)
}

// vectorDriveClient is vectorDrive's lower half, split out so the mTLS vector can
// supply a client whose base transport already trusts the stub's CA.
func (s *vectorASStub) vectorDriveClient(t *testing.T, client *http.Client, body url.Values) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, s.endpoint(), strings.NewReader(body.Encode()))
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
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stub returned %d, want 200 — the request did not parse as expected", resp.StatusCode)
	}
}

// TestVectorClientSecretBasicCanonicalRFC6749 pins the single strongest
// conformance anchor the library has: the exact Authorization header printed in
// RFC 6749 §2.3.1 for its worked-example credentials. If this byte string ever
// drifts, the library no longer matches the figure every other OAuth
// implementation is also written against.
func TestVectorClientSecretBasicCanonicalRFC6749(t *testing.T) {
	t.Parallel()
	stub := newVectorASStub(t)

	stub.vectorDrive(t,
		ClientSecretBasic(vectorClientID, vectorClientSecret),
		url.Values{"grant_type": {"client_credentials"}},
	)

	if stub.authorization != vectorBasicHeader {
		t.Fatalf("Authorization header\n got = %q\nwant = %q (RFC 6749 §2.3.1 figure)",
			stub.authorization, vectorBasicHeader)
	}
	// The credentials travel in the header, never the body, for this method.
	if got := stub.form.Get("client_secret"); got != "" {
		t.Errorf("client_secret leaked into the body: %q", got)
	}
	if got := stub.form.Get("grant_type"); got != "client_credentials" {
		t.Errorf("grant_type = %q, want the preserved client_credentials", got)
	}
}

// TestVectorClientSecretBasicSpecialCharacters pins the form-urlencode-before-
// base64 step (RFC 6749 §2.3.1, Appendix B) for credentials that actually
// exercise it: a colon, a space, a "+", and a non-ASCII rune. A naive
// base64("id:secret") would produce different bytes for every row here, so these
// golden strings guard the encoding pipeline the canonical example cannot (its
// inputs are already encoding-safe). The expected bytes are computed the same
// way the spec describes — QueryEscape each half, join on ":", base64 — and were
// cross-checked against the existing per-method unit vectors.
func TestVectorClientSecretBasicSpecialCharacters(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		id     string
		secret string
		want   string
	}{
		{
			name:   "colon space plus and non-ascii in secret",
			id:     "client",
			secret: "pä:ss word+1",
			want:   "Basic Y2xpZW50OnAlQzMlQTQlM0Fzcyt3b3JkJTJCMQ==",
		},
		{
			name:   "space in id",
			id:     "id with space",
			secret: "plain",
			want:   "Basic aWQrd2l0aCtzcGFjZTpwbGFpbg==",
		},
		{
			name:   "plus in both halves",
			id:     "a+b",
			secret: "c+d",
			want:   "Basic YSUyQmI6YyUyQmQ=",
		},
		{
			name:   "colon in both halves",
			id:     "id:colon",
			secret: "sec:ret",
			want:   "Basic aWQlM0Fjb2xvbjpzZWMlM0FyZXQ=",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			stub := newVectorASStub(t)
			stub.vectorDrive(t,
				ClientSecretBasic(tt.id, tt.secret),
				url.Values{"grant_type": {"client_credentials"}},
			)
			if stub.authorization != tt.want {
				t.Fatalf("Authorization header\n got = %q\nwant = %q", stub.authorization, tt.want)
			}
		})
	}
}

// TestVectorClientSecretPost pins the client_secret_post wire shape (RFC 6749
// §2.3.1): the credentials arrive as single-valued form parameters, the body's
// pre-existing grant_type survives, and the canonical RFC example values come
// through verbatim.
func TestVectorClientSecretPost(t *testing.T) {
	t.Parallel()
	stub := newVectorASStub(t)

	stub.vectorDrive(t,
		ClientSecretPost(vectorClientID, vectorClientSecret),
		url.Values{"grant_type": {"authorization_code"}, "code": {"xyz"}},
	)

	if got := vectorSingle(t, stub.form, "client_id"); got != vectorClientID {
		t.Errorf("client_id = %q, want %q", got, vectorClientID)
	}
	if got := vectorSingle(t, stub.form, "client_secret"); got != vectorClientSecret {
		t.Errorf("client_secret = %q, want %q", got, vectorClientSecret)
	}
	if got := vectorSingle(t, stub.form, "grant_type"); got != "authorization_code" {
		t.Errorf("grant_type = %q, want the preserved authorization_code", got)
	}
	if got := vectorSingle(t, stub.form, "code"); got != "xyz" {
		t.Errorf("code = %q, want the preserved xyz", got)
	}
	// No method should ever leak credentials into the Authorization header for
	// the post variant.
	if stub.authorization != "" {
		t.Errorf("Authorization header set for client_secret_post: %q", stub.authorization)
	}
}

// vectorSingle returns the sole value of key, failing if the parameter is absent
// or multi-valued. RFC 6749 §2.3.1 treats client authentication parameters as
// single-valued, so a duplicated client_id is itself a conformance failure.
func vectorSingle(t *testing.T, form url.Values, key string) string {
	t.Helper()
	vals := form[key]
	if len(vals) != 1 {
		t.Fatalf("%s appeared %d times, want exactly one (RFC 6749 §2.3.1 single-valued): %v", key, len(vals), vals)
	}
	return vals[0]
}

// TestVectorClientAssertionWireShape pins the deterministic parts of the RFC
// 7523 §2.2 client-assertion wire shape for both assertion methods. The literal
// JWT bytes are not deterministic (the jti is random and the signature varies),
// so this asserts the structure: the exact client_assertion_type URN, the alg
// and typ header, and the iss=sub=client_id / aud=endpoint / jti-present /
// exp>iat claim relationships — verifying the signature so the claims read are
// the signed ones, not an attacker-substituted payload.
func TestVectorClientAssertionWireShape(t *testing.T) {
	t.Parallel()

	rsaKey := mustRSAKey(t, 2048)

	tests := []struct {
		name    string
		method  Method
		alg     jose.SignatureAlgorithm
		verify  func(t *testing.T, raw string) jwt.Claims
		wantTyp string
	}{
		{
			name:   "client_secret_jwt HS256",
			method: ClientSecretJWT(vectorClientID, vectorHMACSecret),
			alg:    jose.HS256,
			verify: func(t *testing.T, raw string) jwt.Claims {
				return vectorVerifyClaims(t, raw, jose.HS256, []byte(vectorHMACSecret))
			},
		},
		{
			name:   "private_key_jwt RS256",
			method: PrivateKeyJWT(vectorClientID, rsaKey),
			alg:    jose.RS256,
			verify: func(t *testing.T, raw string) jwt.Claims {
				return vectorVerifyClaims(t, raw, jose.RS256, rsaKey.Public())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			stub := newVectorASStub(t)
			stub.vectorDrive(t, tt.method, url.Values{"grant_type": {"client_credentials"}})

			// client_assertion_type is byte-deterministic: the fixed URN.
			if got := stub.form.Get("client_assertion_type"); got != assertionTypeJWTBearer {
				t.Errorf("client_assertion_type = %q, want %q", got, assertionTypeJWTBearer)
			}
			raw := stub.form.Get("client_assertion")
			if raw == "" {
				t.Fatal("client_assertion is empty")
			}
			// grant_type the request already carried must survive.
			if got := stub.form.Get("grant_type"); got != "client_credentials" {
				t.Errorf("grant_type = %q, want the preserved client_credentials", got)
			}

			claims := tt.verify(t, raw)

			// Structural claim relationships from RFC 7523 §2.2.
			if claims.Issuer != vectorClientID {
				t.Errorf("iss = %q, want %q", claims.Issuer, vectorClientID)
			}
			if claims.Subject != vectorClientID {
				t.Errorf("sub = %q, want %q", claims.Subject, vectorClientID)
			}
			if claims.Issuer != claims.Subject {
				t.Errorf("iss (%q) must equal sub (%q)", claims.Issuer, claims.Subject)
			}
			if len(claims.Audience) != 1 || claims.Audience[0] != stub.endpoint() {
				t.Errorf("aud = %v, want the single endpoint %q", claims.Audience, stub.endpoint())
			}
			if claims.ID == "" {
				t.Error("jti is empty, want a unique identifier (RFC 7523 §3 MUST)")
			}
			if claims.IssuedAt == nil || claims.Expiry == nil {
				t.Fatal("iat and exp must both be set")
			}
			if !claims.Expiry.Time().After(claims.IssuedAt.Time()) {
				t.Errorf("exp (%v) must be after iat (%v)", claims.Expiry.Time(), claims.IssuedAt.Time())
			}

			// The protected header carries the expected alg and typ=JWT.
			hdr := vectorHeader(t, raw, tt.alg)
			if hdr.Algorithm != string(tt.alg) {
				t.Errorf("alg header = %q, want %q", hdr.Algorithm, tt.alg)
			}
			if got := hdr.ExtraHeaders[jose.HeaderType]; got != "JWT" {
				t.Errorf("typ header = %v, want JWT", got)
			}
		})
	}
}

// vectorVerifyClaims parses raw, verifies its signature under key (an HMAC []byte
// secret or a public key), and returns the verified claims. A verification
// failure fails the test: the assertion vectors only mean something if the bytes
// the stub captured are genuinely signed.
func vectorVerifyClaims(t *testing.T, raw string, alg jose.SignatureAlgorithm, key any) jwt.Claims {
	t.Helper()
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{alg})
	if err != nil {
		t.Fatalf("parse assertion: %v", err)
	}
	var claims jwt.Claims
	if err := tok.Claims(key, &claims); err != nil {
		t.Fatalf("verify assertion signature: %v", err)
	}
	return claims
}

// vectorHeader returns the protected header of a compact JWS, parsing under alg.
func vectorHeader(t *testing.T, raw string, alg jose.SignatureAlgorithm) jose.Header {
	t.Helper()
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{alg})
	if err != nil {
		t.Fatalf("parse assertion header: %v", err)
	}
	return tok.Headers[0]
}

// TestVectorMTLSClientIDInBody pins the one deterministic wire effect of the
// mutual-TLS methods (RFC 8705 §2): the client certificate authenticates at the
// handshake, but client_id MUST still be sent in the request body. The stub
// requires and verifies a client certificate, so reaching the handler at all
// proves the handshake carried the cert; the body assertion proves client_id
// rode along beside the preserved grant_type. Both tls_client_auth and
// self_signed_tls_client_auth produce the identical body effect.
func TestVectorMTLSClientIDInBody(t *testing.T) {
	t.Parallel()

	pki := newVectorPKI(t)

	tests := []struct {
		name   string
		method Method
	}{
		{"tls_client_auth", TLSClientAuth(vectorClientID, pki.clientCert)},
		{"self_signed_tls_client_auth", SelfSignedTLSClientAuth(vectorClientID, pki.clientCert)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			stub := newVectorMTLSStub(t, pki)

			base := &http.Transport{TLSClientConfig: &tls.Config{
				RootCAs:    pki.caPool,
				MinVersion: tls.VersionTLS12,
			}}
			client := NewClient(tt.method, base)
			stub.vectorDriveClient(t, client, url.Values{"grant_type": {"client_credentials"}})

			if !stub.sawClientCert {
				t.Fatal("stub did not see a client certificate; the handshake carried none")
			}
			if got := vectorSingle(t, stub.form, "client_id"); got != vectorClientID {
				t.Errorf("client_id in body = %q, want %q (RFC 8705 §2 MUST)", got, vectorClientID)
			}
			if got := stub.form.Get("grant_type"); got != "client_credentials" {
				t.Errorf("grant_type = %q, want the preserved client_credentials", got)
			}
		})
	}
}

// vectorPKI is a minimal in-test certificate authority plus the server and
// client certificates it signs, enough to drive a real mutual-TLS handshake
// through httptest. It is self-contained (rather than reusing the external
// authn_test PKI) because this conformance file lives in the internal authn
// package, where it can reach the unexported helpers and constants the other
// vectors reuse.
type vectorPKI struct {
	caPool     *x509.CertPool
	serverCert tls.Certificate
	clientCert tls.Certificate
}

// newVectorPKI builds a CA and issues a 127.0.0.1 server certificate and a
// client certificate, both chaining to that CA.
func newVectorPKI(t *testing.T) *vectorPKI {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "vector-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	return &vectorPKI{
		caPool:     caPool,
		serverCert: vectorLeaf(t, caCert, caKey, vectorClientID+" server", x509.ExtKeyUsageServerAuth),
		clientCert: vectorLeaf(t, caCert, caKey, vectorClientID+" client", x509.ExtKeyUsageClientAuth),
	}
}

// vectorLeaf issues a leaf certificate signed by ca/caKey. Server leaves get a
// 127.0.0.1 SAN so httptest's loopback server verifies.
func vectorLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, eku x509.ExtKeyUsage) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{eku},
	}
	if eku == x509.ExtKeyUsageServerAuth {
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	}
}

// newVectorMTLSStub starts a TLS variant of the AS stub that requires and
// verifies a client certificate against pki's CA. It records the same wire-shape
// fields as the plain stub, so the mTLS vector asserts client_id in the body the
// same way every other vector reads its parameters.
func newVectorMTLSStub(t *testing.T, pki *vectorPKI) *vectorASStub {
	t.Helper()
	s := &vectorASStub{}
	mux := http.NewServeMux()
	mux.HandleFunc(vectorEndpointPath, s.record)
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{pki.serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pki.caPool,
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	s.srv = srv
	return s
}
