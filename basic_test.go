// Copyright 2026 The go-oauth-client-authn Authors
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestClientSecretBasicName(t *testing.T) {
	m := ClientSecretBasic("id", "secret")
	if got := m.Name(); got != "client_secret_basic" {
		t.Fatalf("Name() = %q, want %q", got, "client_secret_basic")
	}
}

// TestClientSecretBasicHeaderBytes pins the exact Authorization header for inputs
// that exercise the application/x-www-form-urlencoded step required by RFC 6749
// §2.3.1: a colon, a space, a "+", and a non-ASCII rune. A naive
// base64("id:secret") would differ for every row but the first; these golden
// bytes guard against that regression.
func TestClientSecretBasicHeaderBytes(t *testing.T) {
	tests := []struct {
		name   string
		id     string
		secret string
		want   string
	}{
		{
			name:   "plain ascii",
			id:     "s6BhdRkqt3",
			secret: "7Fjfp0ZBr1KtDRbnfVdmIw",
			want:   "Basic czZCaGRSa3F0Mzo3RmpmcDBaQnIxS3REUmJuZlZkbUl3",
		},
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
			name:   "plus in both",
			id:     "a+b",
			secret: "c+d",
			want:   "Basic YSUyQmI6YyUyQmQ=",
		},
		{
			name:   "colon in both",
			id:     "id:colon",
			secret: "sec:ret",
			want:   "Basic aWQlM0Fjb2xvbjpzZWMlM0FyZXQ=",
		},
		{
			name:   "empty id and secret",
			id:     "",
			secret: "",
			want:   "Basic Og==",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			base := &recordingTransport{}
			rt := ClientSecretBasic(tt.id, tt.secret).RoundTripper(base)

			req := httptest.NewRequest(http.MethodPost, "https://as.example/token", http.NoBody)
			resp, err := rt.RoundTrip(req)
			if err != nil {
				t.Fatalf("RoundTrip: %v", err)
			}
			_ = resp.Body.Close()

			got := base.got.Header.Get("Authorization")
			if got != tt.want {
				t.Fatalf("Authorization header\n got = %q\nwant = %q", got, tt.want)
			}

			assertHeaderDecodes(t, got, tt.id, tt.secret)
		})
	}
}

// assertHeaderDecodes confirms the Basic credential base64-decodes to a single
// colon-joined pair whose halves url.QueryUnescape back to the original id and
// secret — the inverse of the construction, so the round-trip is lossless even
// when the secret itself contains a colon.
func assertHeaderDecodes(t *testing.T, header, wantID, wantSecret string) {
	t.Helper()

	encoded, ok := strings.CutPrefix(header, "Basic ")
	if !ok {
		t.Fatalf("header %q is not a Basic credential", header)
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("base64 decode %q: %v", encoded, err)
	}

	escID, escSecret, ok := strings.Cut(string(decoded), ":")
	if !ok {
		t.Fatalf("decoded credential %q has no colon separator", decoded)
	}

	gotID, err := url.QueryUnescape(escID)
	if err != nil {
		t.Fatalf("QueryUnescape id %q: %v", escID, err)
	}
	gotSecret, err := url.QueryUnescape(escSecret)
	if err != nil {
		t.Fatalf("QueryUnescape secret %q: %v", escSecret, err)
	}

	if gotID != wantID {
		t.Errorf("decoded id = %q, want %q", gotID, wantID)
	}
	if gotSecret != wantSecret {
		t.Errorf("decoded secret = %q, want %q", gotSecret, wantSecret)
	}
}

// TestClientSecretBasicDoesNotMutateRequest verifies the http.RoundTripper
// contract: the caller's request is cloned, so an Authorization header it did not
// set must not appear on it after the round trip.
func TestClientSecretBasicDoesNotMutateRequest(t *testing.T) {
	base := &recordingTransport{}
	rt := ClientSecretBasic("client", "secret").RoundTripper(base)

	req := httptest.NewRequest(http.MethodPost, "https://as.example/token", http.NoBody)
	if got := req.Header.Get("Authorization"); got != "" {
		t.Fatalf("precondition: caller request already carries Authorization %q", got)
	}

	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	_ = resp.Body.Close()

	if got := req.Header.Get("Authorization"); got != "" {
		t.Fatalf("caller request was mutated: Authorization = %q, want empty", got)
	}
	if got := base.got.Header.Get("Authorization"); got == "" {
		t.Fatal("decorated transport saw no Authorization header")
	}
	if base.got == req {
		t.Fatal("decorated transport received the caller's request, not a clone")
	}
}
