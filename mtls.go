// Copyright 2026 The go-oauth-client-authn Authors
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
)

// TLSClientAuth returns the tls_client_auth client-authentication method
// (RFC 8705 §2.1, "PKI Mutual-TLS"). The client is authenticated by the TLS
// certificate it presents during the handshake; there is no client secret. The
// authorization server validates that certificate by building a chain to a
// configured certificate authority and matching it against the subject DN or a
// subject alternative name registered for the client.
//
// On the wire the method does two things. It arranges for cert to be presented
// as the client certificate when the request's transport dials TLS, and it adds
// client_id to the form body: the certificate authenticates the connection, but
// RFC 8705 §2.1 still requires the request to identify the client, so client_id
// MUST be sent alongside it.
//
// Transport requirement: a client certificate can only be injected into a TLS
// handshake through an [*http.Transport], because that is the only standard
// RoundTripper that exposes a TLSClientConfig. When the base RoundTripper is an
// *http.Transport (including the http.DefaultTransport that [Transport] and
// [NewClient] substitute for a nil base), it is cloned and its TLS configuration
// is augmented with cert without disturbing the original. When the base is some
// other RoundTripper the certificate has nowhere to go; rather than silently
// send an unauthenticated request, the returned transport fails every RoundTrip
// with a clear local error. Wrap an *http.Transport, or let the method default
// to one, if you need mutual-TLS client authentication.
//
// The same value safely decorates any number of base transports: it carries no
// per-request state, only the client id and certificate.
func TLSClientAuth(clientID string, cert tls.Certificate, opts ...TLSOption) Method {
	return newMTLS("tls_client_auth", clientID, cert, opts)
}

// SelfSignedTLSClientAuth returns the self_signed_tls_client_auth
// client-authentication method (RFC 8705 §2.2, "Self-Signed Certificate
// Mutual-TLS"). It is identical to [TLSClientAuth] on the client side — it
// presents cert during the TLS handshake and sends client_id in the form body —
// and differs only in how the authorization server validates the certificate.
// Under §2.2 the server does not build a chain to a certificate authority; it
// matches the presented certificate against the client's registered JWKS by
// thumbprint, so the certificate may be self-signed.
//
// Because the difference is entirely server-side, the constructed method behaves
// exactly like the one [TLSClientAuth] returns except for the value [Method.Name]
// reports. The same transport requirement applies — see [TLSClientAuth] for the
// *http.Transport rule and the non-*http.Transport failure mode.
func SelfSignedTLSClientAuth(clientID string, cert tls.Certificate, opts ...TLSOption) Method {
	return newMTLS("self_signed_tls_client_auth", clientID, cert, opts)
}

// TLSOption configures an mTLS Method beyond the client id and certificate every
// mutual-TLS request needs. The option set is intentionally small: the methods
// already clone and preserve the caller's TLSClientConfig (MinVersion, RootCAs,
// ServerName, and the rest survive untouched), so most TLS configuration belongs
// on the caller's base *http.Transport rather than here.
type TLSOption func(*mtls)

// WithServerName sets tls.Config.ServerName on the cloned configuration, pinning
// the host name the *server* certificate is verified against (and the SNI sent
// in the handshake). It is a convenience for the common case of naming the
// expected token-endpoint host; it never affects the client certificate this
// method presents. A ServerName already present on the caller's base
// TLSClientConfig is preserved and this option is ignored, so the caller's
// explicit choice on their own base transport always wins.
func WithServerName(serverName string) TLSOption {
	return func(m *mtls) { m.serverName = serverName }
}

// mtls is the shared Method behind tls_client_auth and self_signed_tls_client_auth.
// The two RFC 8705 variants are identical on the client side, differing only in
// the name they report and in how the authorization server validates the
// presented certificate, so they share one implementation and differ only by the
// name field.
type mtls struct {
	name       string
	clientID   string
	cert       tls.Certificate
	serverName string // optional tls.Config.ServerName, set via WithRootCAName
}

// newMTLS builds the shared mTLS Method, applying any options.
func newMTLS(name, clientID string, cert tls.Certificate, opts []TLSOption) Method {
	m := &mtls{name: name, clientID: clientID, cert: cert}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// Name reports the RFC 7591 token_endpoint_auth_method identifier — either
// "tls_client_auth" (RFC 8705 §2.1) or "self_signed_tls_client_auth" (§2.2),
// fixed at construction.
func (m *mtls) Name() string { return m.name }

// RoundTripper returns an http.RoundTripper that presents the client certificate
// during TLS and adds client_id to the form body of every request it carries,
// then delegates to a clone of base configured with that certificate.
//
// When base is an *http.Transport it is cloned and its TLSClientConfig is cloned
// in turn so the client certificate is set without mutating either the original
// transport or the original TLS configuration; an existing TLSClientConfig is
// preserved field for field and only Certificates is overwritten. When base is
// any other RoundTripper a client certificate cannot be injected, so the
// returned transport fails every RoundTrip with a local error rather than send
// the request without the certificate it was meant to carry.
func (m *mtls) RoundTripper(base http.RoundTripper) http.RoundTripper {
	transport, ok := base.(*http.Transport)
	if !ok {
		err := fmt.Errorf("authn: %s requires an *http.Transport base to present "+
			"the client certificate, got %T", m.name, base)
		return roundTripperFunc(func(*http.Request) (*http.Response, error) {
			return nil, err
		})
	}

	configured := transport.Clone()
	configured.TLSClientConfig = m.tlsConfig(configured.TLSClientConfig)

	return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		augmented, err := augmentForm(req, func(v url.Values) {
			v.Set("client_id", m.clientID)
		})
		if err != nil {
			return nil, err
		}
		return configured.RoundTrip(augmented)
	})
}

// tlsConfig returns the TLS configuration the cloned transport should use:
// base's settings (MinVersion, RootCAs, ServerName, …) preserved, with only the
// client Certificates replaced by m.cert. A nil base yields a fresh config
// carrying the certificate and an explicit TLS 1.2 floor — the same minimum the
// crypto/tls default enforces, stated in source so the security posture does not
// depend on a caller supplying a base config. The WithRootCAName option fills in
// ServerName only when base left it empty, so a caller's explicit ServerName
// always wins; a non-empty base ServerName is never overridden.
func (m *mtls) tlsConfig(base *tls.Config) *tls.Config {
	var cfg *tls.Config
	if base != nil {
		cfg = base.Clone()
	} else {
		cfg = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	cfg.Certificates = []tls.Certificate{m.cert}
	if cfg.ServerName == "" && m.serverName != "" {
		cfg.ServerName = m.serverName
	}
	return cfg
}
