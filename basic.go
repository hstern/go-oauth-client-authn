// Copyright 2026 The go-oauth-client-authn Authors
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"encoding/base64"
	"net/http"
	"net/url"
)

// clientSecretBasic carries the credentials for the client_secret_basic method.
// It is unexported: callers hold it through the [Method] interface returned by
// [ClientSecretBasic], never as a concrete type.
type clientSecretBasic struct {
	clientID     string
	clientSecret string
}

// ClientSecretBasic returns the client_secret_basic [Method] (RFC 6749 §2.3.1):
// the client id and secret are sent in the HTTP Basic Authorization header of
// every request the decorated transport carries.
//
// Per RFC 6749 §2.3.1 the id and secret are each first encoded with the
// application/x-www-form-urlencoded algorithm, then joined with a single colon,
// then base64-encoded — not base64 of the raw "id:secret". The distinction is
// only observable when either value contains a character the form encoding
// touches (a colon, a space, "+", or any byte outside the unreserved set), but
// for those values the naive encoding produces a header an authorization server
// reading the spec literally will reject. Appendix B of RFC 6749 is explicit
// that this encoding applies even though many deployed servers are lax about it.
func ClientSecretBasic(clientID, clientSecret string) Method {
	return clientSecretBasic{clientID: clientID, clientSecret: clientSecret}
}

// Name reports the RFC 7591 token_endpoint_auth_method identifier.
func (m clientSecretBasic) Name() string { return "client_secret_basic" }

// RoundTripper returns a transport that sets the HTTP Basic Authorization header
// on a clone of each request and delegates to base. The caller's request is
// never modified, per the http.RoundTripper contract.
func (m clientSecretBasic) RoundTripper(base http.RoundTripper) http.RoundTripper {
	credential := m.authorizationHeader()
	return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		clone := req.Clone(req.Context())
		clone.Header.Set("Authorization", credential)
		return base.RoundTrip(clone)
	})
}

// authorizationHeader builds the "Basic <base64(...)>" credential. The id and
// secret are form-urlencoded (url.QueryEscape implements exactly the
// application/x-www-form-urlencoded algorithm RFC 6749 §2.3.1 calls for: space
// becomes "+", reserved bytes become percent-escapes) before being joined with a
// colon and base64-encoded.
func (m clientSecretBasic) authorizationHeader() string {
	raw := url.QueryEscape(m.clientID) + ":" + url.QueryEscape(m.clientSecret)
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(raw))
}
