// Copyright 2026 The go-oauth-client-authn Authors
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"context"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
)

// fakeMethod is a minimal Method used to exercise composition (Transport,
// NewClient) without depending on any concrete client-auth method, which land in
// later phases. It records the base it was handed and tags every carried request
// with a header so a test can observe that the decorator actually ran.
type fakeMethod struct {
	name       string
	gotBase    http.RoundTripper
	headerKey  string
	headerVal  string
	roundTrips int
}

func (m *fakeMethod) Name() string { return m.name }

func (m *fakeMethod) RoundTripper(base http.RoundTripper) http.RoundTripper {
	m.gotBase = base
	return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		m.roundTrips++
		req = req.Clone(req.Context())
		if m.headerKey != "" {
			req.Header.Set(m.headerKey, m.headerVal)
		}
		return base.RoundTrip(req)
	})
}

// recordingTransport captures the request it carries and returns a canned 200, so
// a test can assert on what the decorated transport actually sent on the wire.
type recordingTransport struct {
	got      *http.Request
	gotBody  string
	err      error
	requests int
}

func (t *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.requests++
	if t.err != nil {
		return nil, t.err
	}
	t.got = req
	if req.Body != nil {
		b, _ := io.ReadAll(req.Body)
		t.gotBody = string(b)
		_ = req.Body.Close()
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("")),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

func TestTransportNilBaseDefaultsToDefaultTransport(t *testing.T) {
	m := &fakeMethod{name: "fake"}

	Transport(m, nil)

	if m.gotBase != http.DefaultTransport {
		t.Fatalf("Transport(m, nil) handed base %#v, want http.DefaultTransport", m.gotBase)
	}
}

func TestTransportPassesExplicitBaseThrough(t *testing.T) {
	m := &fakeMethod{name: "fake"}
	base := &recordingTransport{}

	Transport(m, base)

	if m.gotBase != base {
		t.Fatalf("Transport(m, base) handed base %#v, want the explicit base", m.gotBase)
	}
}

func TestNewClientNilBaseDefaultsToDefaultTransport(t *testing.T) {
	m := &fakeMethod{name: "fake"}

	c := NewClient(m, nil)

	if c.Transport == nil {
		t.Fatal("NewClient produced a client with a nil Transport")
	}
	if m.gotBase != http.DefaultTransport {
		t.Fatalf("NewClient(m, nil) handed base %#v, want http.DefaultTransport", m.gotBase)
	}
}

func TestNewClientComposesMethodOntoBase(t *testing.T) {
	base := &recordingTransport{}
	m := &fakeMethod{name: "fake", headerKey: "X-Fake-Auth", headerVal: "1"}

	c := NewClient(m, base)
	if m.gotBase != base {
		t.Fatalf("NewClient handed base %#v, want the explicit base", m.gotBase)
	}

	req := httptest.NewRequest(http.MethodPost, "https://as.example/token", http.NoBody)
	resp, err := c.Transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	_ = resp.Body.Close()

	if m.roundTrips != 1 {
		t.Fatalf("method round-tripped %d times, want 1", m.roundTrips)
	}
	if got := base.got.Header.Get("X-Fake-Auth"); got != "1" {
		t.Fatalf("decorator header not seen by base transport: got %q, want %q", got, "1")
	}
	if base.got == req {
		t.Fatal("base transport saw the caller's *http.Request; the decorator must clone")
	}
	if req.Header.Get("X-Fake-Auth") != "" {
		t.Fatal("decorator mutated the caller's request header")
	}
}

func TestNameRoundTrips(t *testing.T) {
	m := &fakeMethod{name: "client_secret_basic"}
	if got := m.Name(); got != "client_secret_basic" {
		t.Fatalf("Name() = %q, want %q", got, "client_secret_basic")
	}
}

// formBodyFor builds a form-bodied POST whose body is the encoding of vals.
func formBodyFor(t *testing.T, vals url.Values) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		"https://as.example/token",
		strings.NewReader(vals.Encode()),
	)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", formContentType)
	return req
}

func TestAugmentForm(t *testing.T) {
	addClientID := func(v url.Values) { v.Set("client_id", "s6BhdRkqt3") }

	tests := []struct {
		name     string
		existing url.Values
		add      func(url.Values)
		want     url.Values
	}{
		{
			name:     "preserves existing params while adding new ones",
			existing: url.Values{"grant_type": {"authorization_code"}, "code": {"xyz"}},
			add:      addClientID,
			want: url.Values{
				"grant_type": {"authorization_code"},
				"code":       {"xyz"},
				"client_id":  {"s6BhdRkqt3"},
			},
		},
		{
			name:     "preserves token-exchange params",
			existing: url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "subject_token": {"tok"}},
			add:      addClientID,
			want: url.Values{
				"grant_type":    {"urn:ietf:params:oauth:grant-type:token-exchange"},
				"subject_token": {"tok"},
				"client_id":     {"s6BhdRkqt3"},
			},
		},
		{
			name:     "adds multiple params",
			existing: url.Values{"grant_type": {"client_credentials"}},
			add: func(v url.Values) {
				v.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
				v.Set("client_assertion", "ey.signed.jwt")
			},
			want: url.Values{
				"grant_type":            {"client_credentials"},
				"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
				"client_assertion":      {"ey.signed.jwt"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := formBodyFor(t, tc.existing)

			out, err := augmentForm(req, tc.add)
			if err != nil {
				t.Fatalf("augmentForm: %v", err)
			}

			gotBody := readBody(t, out)
			gotVals, err := url.ParseQuery(gotBody)
			if err != nil {
				t.Fatalf("parse augmented body %q: %v", gotBody, err)
			}
			if !valuesEqual(gotVals, tc.want) {
				t.Fatalf("augmented params = %v, want %v", gotVals, tc.want)
			}

			if out.ContentLength != int64(len(gotBody)) {
				t.Fatalf("ContentLength = %d, want %d (len of re-encoded body)", out.ContentLength, len(gotBody))
			}

			// The form Content-Type, method, and URL must survive onto the
			// clone — the JWT-assertion and post methods rely on the request
			// still being a recognisable form POST to the same endpoint.
			if ct := out.Header.Get("Content-Type"); ct != formContentType {
				t.Fatalf("Content-Type on augmented request = %q, want %q", ct, formContentType)
			}
			if out.Method != http.MethodPost {
				t.Fatalf("Method on augmented request = %q, want POST", out.Method)
			}
			if out.URL.String() != "https://as.example/token" {
				t.Fatalf("URL on augmented request = %q, want the original endpoint", out.URL)
			}
		})
	}
}

func TestAugmentFormDoesNotMutateInput(t *testing.T) {
	existing := url.Values{"grant_type": {"client_credentials"}}
	req := formBodyFor(t, existing)
	origBody := readBody(t, req) // also confirms the input body is re-readable afterwards
	origLen := req.ContentLength

	out, err := augmentForm(req, func(v url.Values) { v.Set("client_id", "abc") })
	if err != nil {
		t.Fatalf("augmentForm: %v", err)
	}
	if out == req {
		t.Fatal("augmentForm returned the same *http.Request; it must clone")
	}

	// The caller's request must still carry its original, un-augmented body and
	// Content-Length, and must still be readable (we cloned, not consumed).
	if got := readBody(t, req); got != origBody {
		t.Fatalf("input body changed: got %q, want %q", got, origBody)
	}
	if req.ContentLength != origLen {
		t.Fatalf("input ContentLength changed: got %d, want %d", req.ContentLength, origLen)
	}
	if strings.Contains(readBody(t, req), "client_id") {
		t.Fatal("augmentForm leaked the added param into the caller's request")
	}
}

func TestAugmentFormSetsGetBodyForRetries(t *testing.T) {
	req := formBodyFor(t, url.Values{"grant_type": {"client_credentials"}})

	out, err := augmentForm(req, func(v url.Values) { v.Set("client_id", "abc") })
	if err != nil {
		t.Fatalf("augmentForm: %v", err)
	}
	if out.GetBody == nil {
		t.Fatal("augmentForm did not set GetBody; redirects and retries would lose the body")
	}

	first := readBody(t, out)
	// GetBody must reproduce the augmented bytes, repeatedly.
	for i := range 3 {
		rc, err := out.GetBody()
		if err != nil {
			t.Fatalf("GetBody call %d: %v", i, err)
		}
		b, _ := io.ReadAll(rc)
		_ = rc.Close()
		if string(b) != first {
			t.Fatalf("GetBody call %d = %q, want %q", i, string(b), first)
		}
	}
}

func TestAugmentFormPassThrough(t *testing.T) {
	tests := []struct {
		name  string
		build func() *http.Request
	}{
		{
			name: "nil body",
			build: func() *http.Request {
				req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://as.example/token", nil)
				return req
			},
		},
		{
			name: "http.NoBody",
			build: func() *http.Request {
				return httptest.NewRequest(http.MethodPost, "https://as.example/token", http.NoBody)
			},
		},
		{
			name: "non-form content type",
			build: func() *http.Request {
				req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://as.example/token", strings.NewReader(`{"a":1}`))
				req.Header.Set("Content-Type", "application/json")
				return req
			},
		},
		{
			name: "form body but no content-type header",
			build: func() *http.Request {
				req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://as.example/token", strings.NewReader("grant_type=client_credentials"))
				return req
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := tc.build()
			called := false
			out, err := augmentForm(req, func(url.Values) { called = true })
			if err != nil {
				t.Fatalf("augmentForm: %v", err)
			}
			if out != req {
				t.Fatal("pass-through case returned a new request instead of the original")
			}
			if called {
				t.Fatal("add func was invoked on a request that should pass through untouched")
			}
		})
	}
}

func TestAugmentFormHonorsContentTypeWithCharset(t *testing.T) {
	req, _ := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		"https://as.example/token",
		strings.NewReader("grant_type=client_credentials"),
	)
	req.Header.Set("Content-Type", formContentType+"; charset=UTF-8")

	out, err := augmentForm(req, func(v url.Values) { v.Set("client_id", "abc") })
	if err != nil {
		t.Fatalf("augmentForm: %v", err)
	}
	if out == req {
		t.Fatal("a form body with a charset parameter should still be augmented")
	}
	if !strings.Contains(readBody(t, out), "client_id=abc") {
		t.Fatal("augmented body missing the added param")
	}
}

func TestAugmentFormMalformedBody(t *testing.T) {
	// A percent-escape that does not form a valid byte pair makes url.ParseQuery
	// fail; that is the one genuinely-malformed case the helper surfaces.
	req, _ := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		"https://as.example/token",
		strings.NewReader("grant_type=%zz"),
	)
	req.Header.Set("Content-Type", formContentType)

	out, err := augmentForm(req, func(url.Values) {})
	if err == nil {
		t.Fatal("augmentForm accepted a malformed form body, want an error")
	}
	if out != nil {
		t.Fatal("augmentForm returned a non-nil request alongside an error")
	}
}

func readBody(t *testing.T, req *http.Request) string {
	t.Helper()
	if req.Body == nil {
		return ""
	}
	b, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	_ = req.Body.Close()
	// Restore so a test can read again.
	req.Body = io.NopCloser(strings.NewReader(string(b)))
	return string(b)
}

func valuesEqual(a, b url.Values) bool {
	return maps.EqualFunc(a, b, slices.Equal)
}

// The malformed-body error must be namespaced and wrap the underlying url
// package error (via %w) so callers can inspect the cause with errors.Is/As.
func TestAugmentFormErrorIsWrapped(t *testing.T) {
	t.Parallel()
	req, _ := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		"https://as.example/token",
		strings.NewReader("%zz=1"),
	)
	req.Header.Set("Content-Type", formContentType)

	_, err := augmentForm(req, func(url.Values) {})
	if err == nil {
		t.Fatal("want error for malformed body")
	}
	if !strings.Contains(err.Error(), "authn:") {
		t.Fatalf("error %q is not namespaced with the package prefix", err)
	}
	if errors.Unwrap(err) == nil {
		t.Fatal("error does not wrap an underlying cause; %w was not used")
	}
}
