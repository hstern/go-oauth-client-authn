// Copyright 2026 The go-oauth-client-authn Authors
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// SpecVersion identifies the OAuth 2.0 client-authentication specifications
// this library implements. It is informational: it names the documents the
// wire behavior is verified against, not a negotiated protocol version.
const SpecVersion = "RFC 6749 / 7523 / 8705"

// formContentType is the media type of an OAuth token-endpoint request body,
// per RFC 6749 §4.1.3 ("application/x-www-form-urlencoded").
const formContentType = "application/x-www-form-urlencoded"

// Method is a single OAuth 2.0 client-authentication method. It names itself
// using the RFC 7591 token_endpoint_auth_method identifier and decorates a base
// http.RoundTripper so that every request the decorated transport carries is
// authenticated according to that method.
//
// A Method is configuration, not transport: the same Method composes onto any
// base RoundTripper and authenticates requests to any token-family endpoint
// (token, pushed-authorization, introspection, revocation), because the wire
// effect is derived from each request rather than fixed at construction time.
type Method interface {
	// Name reports the RFC 7591 token_endpoint_auth_method identifier for the
	// method, for example "client_secret_basic" or "private_key_jwt". It is the
	// value a client would register or advertise; it never varies per request.
	Name() string

	// RoundTripper returns an http.RoundTripper that authenticates every request
	// it carries and delegates the actual transport to base. Implementations
	// must not mutate the requests they are given (the http.RoundTripper
	// contract); they clone before augmenting. A nil base is the caller's
	// responsibility — use [Transport], which substitutes http.DefaultTransport.
	RoundTripper(base http.RoundTripper) http.RoundTripper
}

// Transport returns an http.RoundTripper that applies m's client authentication
// on top of base. When base is nil it defaults to http.DefaultTransport, so a
// caller that only wants authentication need not also supply a transport.
//
// The result is the seam that token-family clients consume: it can be assigned
// to http.Client.Transport directly, or passed wherever an http.RoundTripper is
// expected.
func Transport(m Method, base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return m.RoundTripper(base)
}

// NewClient returns an *http.Client whose Transport authenticates every request
// using m. When base is nil the client authenticates over http.DefaultTransport.
//
// The returned client is exactly the value a token-family client (for example an
// RFC 8693 token-exchange client accepting a custom *http.Client) consumes: drop
// it in and every call it makes to the token endpoint carries client
// authentication.
func NewClient(m Method, base http.RoundTripper) *http.Client {
	return &http.Client{Transport: Transport(m, base)}
}

// roundTripperFunc adapts an ordinary function to http.RoundTripper, mirroring
// http.HandlerFunc. It lets the header- and form-augmenting methods express
// their per-request work as a closure over the base transport without each
// declaring its own named type.
type roundTripperFunc func(*http.Request) (*http.Response, error)

var _ http.RoundTripper = roundTripperFunc(nil)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// augmentForm returns a copy of req whose application/x-www-form-urlencoded body
// has been extended with the parameters add yields, re-encoded with a corrected
// Content-Length and a matching GetBody. It is the shared read-augment-encode
// helper behind client_secret_post and the RFC 7523 JWT-assertion methods, which
// all add parameters (client_id, client_assertion, …) to a body that may already
// carry grant_type, subject_token, and the like.
//
// The original req is never modified, satisfying the http.RoundTripper contract
// that a RoundTripper must not mutate the request it is given: the body is read
// through a clone and the caller's Body is restored so the request remains
// reusable.
//
// Requests that do not carry a form body pass through unchanged — a nil body, an
// empty body, or a Content-Type that is not application/x-www-form-urlencoded is
// not an OAuth token-endpoint request this helper is meant to touch. A non-nil
// error is returned only for a genuinely unreadable or malformed form body,
// matching the spec-reference "local failure" policy.
func augmentForm(req *http.Request, add func(url.Values)) (*http.Request, error) {
	if !hasFormBody(req) {
		return req, nil
	}

	body, err := drainAndRestore(req)
	if err != nil {
		return nil, err
	}

	values, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, fmt.Errorf("authn: parse form body: %w", err)
	}
	add(values)

	clone := req.Clone(req.Context())
	setFormBody(clone, values.Encode())
	return clone, nil
}

// hasFormBody reports whether req carries an application/x-www-form-urlencoded
// body worth augmenting. A nil body or a Content-Type whose media type is not
// the form type is reported as false so such requests pass through untouched.
func hasFormBody(req *http.Request) bool {
	if req.Body == nil || req.Body == http.NoBody {
		return false
	}
	ct := req.Header.Get("Content-Type")
	if ct == "" {
		return false
	}
	mediaType, _, _ := strings.Cut(ct, ";")
	return strings.EqualFold(strings.TrimSpace(mediaType), formContentType)
}

// drainAndRestore reads req.Body to completion, then restores a fresh reader
// over the same bytes onto req so the caller's request stays reusable. The
// http.RoundTripper contract forbids consuming the request we were handed; the
// augmented body is built on a clone, and the original is left intact.
func drainAndRestore(req *http.Request) ([]byte, error) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		_ = req.Body.Close()
		return nil, fmt.Errorf("authn: read form body: %w", err)
	}
	if err := req.Body.Close(); err != nil {
		return nil, fmt.Errorf("authn: close form body: %w", err)
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	return body, nil
}

// setFormBody installs encoded as clone's body, keeping Body, ContentLength, and
// GetBody consistent so redirects and retries (which the standard client drives
// through GetBody) re-send the augmented bytes rather than the originals.
func setFormBody(clone *http.Request, encoded string) {
	clone.Body = io.NopCloser(strings.NewReader(encoded))
	clone.ContentLength = int64(len(encoded))
	clone.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(encoded)), nil
	}
}
