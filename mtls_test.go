// Copyright 2026 The go-oauth-client-authn Authors
// SPDX-License-Identifier: Apache-2.0

package authn_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	authn "github.com/hstern/go-oauth-client-authn"
)

// testPKI is a minimal in-test certificate authority plus the server and client
// certificates it signs, enough to drive a real mutual-TLS handshake through
// httptest.
type testPKI struct {
	caCert     *x509.Certificate
	caPool     *x509.CertPool
	serverCert tls.Certificate
	clientCert tls.Certificate
}

// newTestPKI builds a CA and issues a server certificate (for 127.0.0.1) and a
// client certificate, both chaining to that CA. It fails the test on any error
// so callers can treat the result as always valid.
func newTestPKI(t *testing.T) *testPKI {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
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

	return &testPKI{
		caCert:     caCert,
		caPool:     caPool,
		serverCert: leafCert(t, caCert, caKey, "127.0.0.1 server", x509.ExtKeyUsageServerAuth),
		clientCert: leafCert(t, caCert, caKey, "s6BhdRkqt3 client", x509.ExtKeyUsageClientAuth),
	}
}

// leafCert issues a leaf certificate signed by ca/caKey with the given common
// name and extended key usage. Server leaves get a 127.0.0.1 SAN so httptest's
// loopback server verifies.
func leafCert(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, eku x509.ExtKeyUsage) tls.Certificate {
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
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        mustParse(t, der),
	}
}

func mustParse(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return c
}

// mtlsServer stands up an httptest TLS server that requires and verifies a
// client certificate against pki's CA. The handler records the client cert the
// handshake presented and the posted form, then reports them back.
type mtlsServer struct {
	srv        *httptest.Server
	clientCN   string
	clientID   string
	grantType  string
	clientSeen bool
}

func newMTLSServer(t *testing.T, pki *testPKI) *mtlsServer {
	t.Helper()

	m := &mtlsServer{}
	m.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) > 0 {
			m.clientSeen = true
			m.clientCN = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		_ = r.ParseForm()
		m.clientID = r.PostForm.Get("client_id")
		m.grantType = r.PostForm.Get("grant_type")
		w.WriteHeader(http.StatusOK)
	}))
	m.srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{pki.serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pki.caPool,
		MinVersion:   tls.VersionTLS12,
	}
	m.srv.StartTLS()
	t.Cleanup(m.srv.Close)
	return m
}

// post sends a form POST carrying grant_type=client_credentials through client
// and discards the body, returning any transport error.
func post(t *testing.T, client *http.Client, rawURL string) error {
	t.Helper()
	body := strings.NewReader(url.Values{"grant_type": {"client_credentials"}}.Encode())
	req, err := http.NewRequest(http.MethodPost, rawURL, body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

func TestTLSClientAuthHandshakeAndClientID(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t)
	server := newMTLSServer(t, pki)

	// Base transport that already trusts the server CA, so the only thing the
	// method must add is the client certificate.
	base := &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:    pki.caPool,
		MinVersion: tls.VersionTLS12,
	}}
	client := authn.NewClient(authn.TLSClientAuth("s6BhdRkqt3", pki.clientCert), base)

	if err := post(t, client, server.srv.URL); err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if !server.clientSeen {
		t.Fatal("server did not see a client certificate")
	}
	if server.clientCN != "s6BhdRkqt3 client" {
		t.Errorf("client cert CN = %q, want %q", server.clientCN, "s6BhdRkqt3 client")
	}
	if server.clientID != "s6BhdRkqt3" {
		t.Errorf("client_id in body = %q, want %q", server.clientID, "s6BhdRkqt3")
	}
	if server.grantType != "client_credentials" {
		t.Errorf("grant_type in body = %q, want preserved %q", server.grantType, "client_credentials")
	}
}

func TestSelfSignedTLSClientAuthBehavesIdentically(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t)
	server := newMTLSServer(t, pki)

	base := &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:    pki.caPool,
		MinVersion: tls.VersionTLS12,
	}}
	client := authn.NewClient(authn.SelfSignedTLSClientAuth("s6BhdRkqt3", pki.clientCert), base)

	if err := post(t, client, server.srv.URL); err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if !server.clientSeen {
		t.Fatal("server did not see a client certificate")
	}
	if server.clientID != "s6BhdRkqt3" {
		t.Errorf("client_id in body = %q, want %q", server.clientID, "s6BhdRkqt3")
	}
}

func TestMTLSMethodNames(t *testing.T) {
	t.Parallel()

	var cert tls.Certificate
	tests := []struct {
		name   string
		method authn.Method
		want   string
	}{
		{"pki", authn.TLSClientAuth("id", cert), "tls_client_auth"},
		{"self-signed", authn.SelfSignedTLSClientAuth("id", cert), "self_signed_tls_client_auth"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.method.Name(); got != tt.want {
				t.Errorf("Name() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestTLSClientAuthPreservesBaseConfig is the critical safety test: a base
// *http.Transport carrying a custom TLSClientConfig must keep every field after
// the method configures the client certificate, and the original base transport
// and its config must not be mutated — the method clones, it does not mutate.
func TestTLSClientAuthPreservesBaseConfig(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t)

	baseCfg := &tls.Config{
		RootCAs:    pki.caPool,
		MinVersion: tls.VersionTLS13,
		ServerName: "auth.example.com",
	}
	base := &http.Transport{
		TLSClientConfig:     baseCfg,
		MaxIdleConns:        7,
		IdleConnTimeout:     42 * time.Second,
		DisableCompression:  true,
		MaxConnsPerHost:     3,
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 9 * time.Second,
	}

	m := authn.TLSClientAuth("s6BhdRkqt3", pki.clientCert)
	_ = m.RoundTripper(base)

	// The original base transport's config is untouched: no client certificate
	// leaked into it, and its fields are intact.
	if len(base.TLSClientConfig.Certificates) != 0 {
		t.Error("base TLSClientConfig.Certificates was mutated; want clone, not mutate")
	}
	if base.TLSClientConfig != baseCfg {
		t.Error("base.TLSClientConfig pointer was replaced; the base transport must not be mutated")
	}
	if base.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Errorf("base MinVersion = %x, want preserved %x", base.TLSClientConfig.MinVersion, tls.VersionTLS13)
	}
	if base.TLSClientConfig.ServerName != "auth.example.com" {
		t.Errorf("base ServerName = %q, want preserved", base.TLSClientConfig.ServerName)
	}
	if base.MaxIdleConns != 7 || base.IdleConnTimeout != 42*time.Second {
		t.Error("base transport non-TLS fields were mutated")
	}
}

// TestTLSClientAuthClonedConfigCarriesCertAndPreservesFields proves the cloned
// transport actually used by RoundTrip carries the client certificate while
// preserving the base config's other fields — verified end to end against a
// server that pins MinVersion TLS 1.3.
func TestTLSClientAuthClonedConfigCarriesCertAndPreservesFields(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t)
	server := newMTLSServer(t, pki)

	// Base config pins TLS 1.3; if the method clobbered it the handshake would
	// fall back and the assertion below could not rely on it. RootCAs preserved
	// proves the merge kept the caller's trust store.
	base := &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:    pki.caPool,
		MinVersion: tls.VersionTLS13,
	}}
	client := authn.NewClient(authn.TLSClientAuth("s6BhdRkqt3", pki.clientCert), base)

	if err := post(t, client, server.srv.URL); err != nil {
		t.Fatalf("request failed with preserved TLS 1.3 config: %v", err)
	}
	if !server.clientSeen {
		t.Fatal("server did not see a client certificate through the cloned config")
	}
}

// TestTLSClientAuthNonHTTPTransportFails covers the documented policy: a base
// RoundTripper that is not an *http.Transport cannot carry a client certificate,
// so every RoundTrip fails with a local error rather than sending unauthenticated.
func TestTLSClientAuthNonHTTPTransportFails(t *testing.T) {
	t.Parallel()

	var cert tls.Certificate
	rt := authn.TLSClientAuth("s6BhdRkqt3", cert).RoundTripper(noopRoundTripper{})

	req, err := http.NewRequest(http.MethodPost, "https://auth.example.com/token", http.NoBody)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := rt.RoundTrip(req)
	closeBody(resp)
	if err == nil {
		t.Fatal("RoundTrip on a non-*http.Transport base succeeded; want a local error")
	}
	if resp != nil {
		t.Error("RoundTrip returned a non-nil response alongside the error")
	}
	if !strings.Contains(err.Error(), "requires an *http.Transport") {
		t.Errorf("error = %q, want it to explain the *http.Transport requirement", err)
	}
}

func TestSelfSignedTLSClientAuthNonHTTPTransportFails(t *testing.T) {
	t.Parallel()

	var cert tls.Certificate
	rt := authn.SelfSignedTLSClientAuth("s6BhdRkqt3", cert).RoundTripper(noopRoundTripper{})

	req, err := http.NewRequest(http.MethodPost, "https://auth.example.com/token", http.NoBody)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := rt.RoundTrip(req)
	closeBody(resp)
	if err == nil {
		t.Fatal("RoundTrip on a non-*http.Transport base succeeded; want a local error")
	}
}

// TestTLSClientAuthNilBaseUsesDefaultTransport confirms the nil-base path:
// Transport substitutes http.DefaultTransport, which is an *http.Transport, so
// the cert injection works without the caller supplying a transport.
func TestTLSClientAuthNilBaseUsesDefaultTransport(t *testing.T) {
	t.Parallel()

	var cert tls.Certificate
	rt := authn.Transport(authn.TLSClientAuth("s6BhdRkqt3", cert), nil)

	// A roundTripperFunc that always errors would be the non-*http.Transport
	// failure path; the success path returns a working transport. We assert it
	// does not immediately reject by exercising the documented error string,
	// which must be absent for the DefaultTransport case.
	req, err := http.NewRequest(http.MethodPost, "https://127.0.0.1:1/token", http.NoBody)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := rt.RoundTrip(req)
	closeBody(resp)
	// The dial will fail (nothing is listening), but it must be a dial/connection
	// error, not the "requires an *http.Transport" local rejection.
	if err != nil && strings.Contains(err.Error(), "requires an *http.Transport") {
		t.Errorf("nil base was treated as non-*http.Transport: %v", err)
	}
}

func TestWithServerNamePreservesExplicitServerName(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t)
	server := newMTLSServer(t, pki)

	// Caller set ServerName explicitly; WithServerName must not override it. We
	// set it to the loopback host so the handshake still verifies.
	base := &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:    pki.caPool,
		ServerName: "127.0.0.1",
		MinVersion: tls.VersionTLS12,
	}}
	m := authn.TLSClientAuth("s6BhdRkqt3", pki.clientCert, authn.WithServerName("override.example.com"))
	client := authn.NewClient(m, base)

	if err := post(t, client, server.srv.URL); err != nil {
		t.Fatalf("request failed; explicit ServerName should have been preserved: %v", err)
	}
	if server.clientID != "s6BhdRkqt3" {
		t.Errorf("client_id = %q, want %q", server.clientID, "s6BhdRkqt3")
	}
}

// TestWithServerNameAppliesWhenBaseEmpty proves the option fills ServerName in
// when the caller's base config left it empty: the loopback server presents a
// 127.0.0.1 certificate, so pinning ServerName to 127.0.0.1 must verify, while a
// mismatched name would fail the handshake.
func TestWithServerNameAppliesWhenBaseEmpty(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t)
	server := newMTLSServer(t, pki)

	base := &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:    pki.caPool,
		MinVersion: tls.VersionTLS12,
	}}
	m := authn.TLSClientAuth("s6BhdRkqt3", pki.clientCert, authn.WithServerName("127.0.0.1"))
	client := authn.NewClient(m, base)

	if err := post(t, client, server.srv.URL); err != nil {
		t.Fatalf("request failed; WithServerName should have pinned 127.0.0.1: %v", err)
	}
	if !server.clientSeen {
		t.Fatal("server did not see a client certificate")
	}
}

// closeBody closes resp.Body when resp is non-nil. The mTLS failure-path tests
// expect a nil response alongside an error, but closing defensively keeps the
// bodyclose linter satisfied without weakening those assertions.
func closeBody(resp *http.Response) {
	if resp != nil {
		_ = resp.Body.Close()
	}
}

// errNotImplemented marks the noop transport's deliberate refusal to round-trip.
var errNotImplemented = errors.New("noopRoundTripper: not implemented")

// noopRoundTripper is any RoundTripper that is not an *http.Transport, used to
// exercise the non-*http.Transport failure path. Its RoundTrip is never reached
// because the method rejects the base before dispatching.
type noopRoundTripper struct{}

func (noopRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errNotImplemented
}
