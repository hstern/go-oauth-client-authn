// Copyright 2026 The go-oauth-client-authn Authors
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"net/http"
	"net/url"
)

// ClientSecretPost returns the client_secret_post client-authentication method
// (RFC 6749 §2.3.1). It authenticates by adding the client_id and client_secret
// form parameters to the token-endpoint request body, the alternative the spec
// permits to client_secret_basic for clients that cannot or prefer not to use
// the HTTP Basic authentication scheme.
//
// The request MUST be an application/x-www-form-urlencoded POST — which every
// token-family endpoint request is (token, pushed-authorization, introspection,
// revocation are all form POSTs per RFC 6749 §4 and the endpoints that reuse its
// request shape). The credentials are written into that form body alongside
// whatever it already carries (grant_type, code, subject_token, …); the existing
// parameters are preserved and the body is re-encoded with a corrected
// Content-Length. A request that does not carry a form body is passed through
// unchanged, so a caller that hands this method a non-form request gets an
// unauthenticated request rather than a fabricated body — see [augmentForm].
//
// client_id and client_secret are written with [url.Values.Set], not Add: RFC
// 6749 §2.3.1 treats client authentication as single-valued, so a pre-populated
// client_id in the body is replaced rather than duplicated.
//
// The secret is bearer-equivalent; like every Method here, the returned value
// holds it in memory and writes it only into the request body — it is never
// logged.
func ClientSecretPost(clientID, clientSecret string) Method {
	return clientSecretPost{clientID: clientID, clientSecret: clientSecret}
}

// clientSecretPost is the client_secret_post Method. It is a value type holding
// only the two credentials; it carries no per-request state, so the same value
// safely decorates any number of base transports.
type clientSecretPost struct {
	clientID     string
	clientSecret string
}

// Name reports the RFC 7591 token_endpoint_auth_method identifier,
// "client_secret_post".
func (clientSecretPost) Name() string { return "client_secret_post" }

// RoundTripper returns an http.RoundTripper that adds client_id and
// client_secret to the form body of every request it carries and then delegates
// to base. The caller's request is never mutated: augmentForm builds the
// augmented body on a clone (the http.RoundTripper contract). When the body
// cannot be re-encoded — a malformed form body, the only local failure — the
// error is returned with a nil response, matching the spec-reference "local
// failure" policy; the augmentation otherwise never fails.
func (m clientSecretPost) RoundTripper(base http.RoundTripper) http.RoundTripper {
	return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		augmented, err := augmentForm(req, func(v url.Values) {
			v.Set("client_id", m.clientID)
			v.Set("client_secret", m.clientSecret)
		})
		if err != nil {
			return nil, err
		}
		return base.RoundTrip(augmented)
	})
}
