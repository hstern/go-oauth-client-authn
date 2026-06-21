// Copyright 2026 The go-oauth-client-authn Authors
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestClientSecretPostName(t *testing.T) {
	t.Parallel()
	m := ClientSecretPost("s6BhdRkqt3", "secret")
	if got := m.Name(); got != "client_secret_post" {
		t.Fatalf("Name() = %q, want %q", got, "client_secret_post")
	}
}

// TestClientSecretPostAugmentsBody covers the core wire effect: the credentials
// land in the form body, the parameters the body already carried survive, every
// client-auth param is single-valued, and the Content-Length tracks the
// re-encoded body.
func TestClientSecretPostAugmentsBody(t *testing.T) {
	tests := []struct {
		name     string
		existing url.Values
		want     url.Values
	}{
		{
			name:     "adds credentials to a body that already carries grant_type",
			existing: url.Values{"grant_type": {"authorization_code"}, "code": {"xyz"}},
			want: url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {"xyz"},
				"client_id":     {"s6BhdRkqt3"},
				"client_secret": {"7Fjfp0ZBr1KtDRbnfVdmIw"},
			},
		},
		{
			name:     "preserves token-exchange params",
			existing: url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "subject_token": {"tok"}},
			want: url.Values{
				"grant_type":    {"urn:ietf:params:oauth:grant-type:token-exchange"},
				"subject_token": {"tok"},
				"client_id":     {"s6BhdRkqt3"},
				"client_secret": {"7Fjfp0ZBr1KtDRbnfVdmIw"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			base := &recordingTransport{}
			rt := ClientSecretPost("s6BhdRkqt3", "7Fjfp0ZBr1KtDRbnfVdmIw").RoundTripper(base)
			req := formBodyFor(t, tc.existing)

			resp, err := rt.RoundTrip(req)
			if err != nil {
				t.Fatalf("RoundTrip: %v", err)
			}
			_ = resp.Body.Close()

			gotVals, err := url.ParseQuery(base.gotBody)
			if err != nil {
				t.Fatalf("parse sent body %q: %v", base.gotBody, err)
			}
			if !valuesEqual(gotVals, tc.want) {
				t.Fatalf("sent params = %v, want %v", gotVals, tc.want)
			}

			if base.got.ContentLength != int64(len(base.gotBody)) {
				t.Fatalf("ContentLength = %d, want %d (len of re-encoded body)", base.got.ContentLength, len(base.gotBody))
			}
		})
	}
}

// TestClientSecretPostUsesSetNotAdd pins the RFC 6749 §2.3.1 single-valued
// requirement: a body that already carries a client_id (or client_secret) must
// have it replaced, not duplicated, by the method's credentials.
func TestClientSecretPostUsesSetNotAdd(t *testing.T) {
	t.Parallel()
	base := &recordingTransport{}
	rt := ClientSecretPost("real-id", "real-secret").RoundTripper(base)

	req := formBodyFor(t, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"stale-id"},
		"client_secret": {"stale-secret"},
	})

	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	_ = resp.Body.Close()

	gotVals, err := url.ParseQuery(base.gotBody)
	if err != nil {
		t.Fatalf("parse sent body %q: %v", base.gotBody, err)
	}
	if got := gotVals["client_id"]; len(got) != 1 || got[0] != "real-id" {
		t.Fatalf("client_id = %v, want exactly [real-id] (Set must replace, not Add)", got)
	}
	if got := gotVals["client_secret"]; len(got) != 1 || got[0] != "real-secret" {
		t.Fatalf("client_secret = %v, want exactly [real-secret] (Set must replace, not Add)", got)
	}
}

// TestClientSecretPostDoesNotMutateInput asserts the http.RoundTripper contract:
// the caller's request keeps its original, un-augmented body, and the credentials
// never leak back into it.
func TestClientSecretPostDoesNotMutateInput(t *testing.T) {
	t.Parallel()
	base := &recordingTransport{}
	rt := ClientSecretPost("real-id", "real-secret").RoundTripper(base)

	req := formBodyFor(t, url.Values{"grant_type": {"client_credentials"}})
	origBody := readBody(t, req)
	origLen := req.ContentLength

	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	_ = resp.Body.Close()

	if got := readBody(t, req); got != origBody {
		t.Fatalf("input body changed: got %q, want %q", got, origBody)
	}
	if req.ContentLength != origLen {
		t.Fatalf("input ContentLength changed: got %d, want %d", req.ContentLength, origLen)
	}
	if strings.Contains(origBody, "client_secret") {
		t.Fatal("input body unexpectedly contained client_secret before the call")
	}
	if strings.Contains(readBody(t, req), "client_secret") {
		t.Fatal("method leaked client_secret into the caller's request")
	}
}

// TestClientSecretPostAgainstServer drives the method through a real httptest
// server that parses the posted form, proving the credentials arrive on the wire
// in a way an authorization server would actually read them.
func TestClientSecretPostAgainstServer(t *testing.T) {
	t.Parallel()
	var gotID, gotSecret, gotGrant string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("server ParseForm: %v", err)
		}
		gotID = r.PostForm.Get("client_id")
		gotSecret = r.PostForm.Get("client_secret")
		gotGrant = r.PostForm.Get("grant_type")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := NewClient(ClientSecretPost("s6BhdRkqt3", "7Fjfp0ZBr1KtDRbnfVdmIw"), nil)

	body := strings.NewReader(url.Values{"grant_type": {"client_credentials"}}.Encode())
	req, err := http.NewRequest(http.MethodPost, srv.URL, body)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", formContentType)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	if gotID != "s6BhdRkqt3" {
		t.Errorf("server saw client_id = %q, want %q", gotID, "s6BhdRkqt3")
	}
	if gotSecret != "7Fjfp0ZBr1KtDRbnfVdmIw" {
		t.Errorf("server saw client_secret = %q, want %q", gotSecret, "7Fjfp0ZBr1KtDRbnfVdmIw")
	}
	if gotGrant != "client_credentials" {
		t.Errorf("server saw grant_type = %q, want the preserved %q", gotGrant, "client_credentials")
	}
}

// TestClientSecretPostPropagatesAugmentError confirms a malformed form body is
// surfaced as a local failure (nil response, non-nil error) without the request
// ever reaching the base transport.
func TestClientSecretPostPropagatesAugmentError(t *testing.T) {
	t.Parallel()
	base := &recordingTransport{}
	rt := ClientSecretPost("id", "secret").RoundTripper(base)

	req, err := http.NewRequest(http.MethodPost, "https://as.example/token", strings.NewReader("grant_type=%zz"))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", formContentType)

	resp, err := rt.RoundTrip(req)
	if resp != nil {
		_ = resp.Body.Close()
		t.Fatal("RoundTrip returned a non-nil response alongside an error")
	}
	if err == nil {
		t.Fatal("RoundTrip accepted a malformed form body, want an error")
	}
	if base.requests != 0 {
		t.Fatalf("base transport was called %d times on a local failure, want 0", base.requests)
	}
}
