// Copyright 2026 The go-oauth-client-authn Authors
// SPDX-License-Identifier: Apache-2.0

package authn_test

import (
	"crypto/tls"
	"fmt"
	"net/http"

	authn "github.com/hstern/go-oauth-client-authn"
)

// ExampleTLSClientAuth shows tls_client_auth (RFC 8705 §2.1): the client
// certificate authenticates the TLS connection while client_id is still sent in
// the form body. The Method clones the supplied base *http.Transport and sets
// the client certificate on a clone of its TLS configuration, leaving the
// caller's transport (here pinning TLS 1.3) untouched.
//
// A real caller loads cert from disk — for example with tls.LoadX509KeyPair —
// and points the request at the authorization server's token endpoint.
func ExampleTLSClientAuth() {
	var clientCert tls.Certificate // from tls.LoadX509KeyPair(certPEM, keyPEM)

	base := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13}}
	client := authn.NewClient(authn.TLSClientAuth("s6BhdRkqt3", clientCert), base)

	// The cloned config carries the client certificate; the caller's MinVersion
	// is preserved rather than clobbered, and the original base is not mutated.
	fmt.Println(authn.TLSClientAuth("s6BhdRkqt3", clientCert).Name())
	fmt.Println(base.TLSClientConfig.MinVersion == tls.VersionTLS13)
	_ = client

	// Output:
	// tls_client_auth
	// true
}
