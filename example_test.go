// Copyright 2026 The go-oauth-client-authn Authors
// SPDX-License-Identifier: Apache-2.0

package authn_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"

	authn "github.com/hstern/go-oauth-client-authn"
)

// headerMethod is a stand-in Method that authenticates by setting a fixed header.
// The library's concrete methods (client_secret_basic, private_key_jwt, …) land
// in later phases; this minimal one shows how any Method composes.
type headerMethod struct{}

func (headerMethod) Name() string { return "example_static_header" }

func (headerMethod) RoundTripper(base http.RoundTripper) http.RoundTripper {
	return roundTripper(func(req *http.Request) (*http.Response, error) {
		// Clone first — a RoundTripper must not mutate the request it is given.
		req = req.Clone(req.Context())
		req.Header.Set("Authorization", "Bearer example")
		return base.RoundTrip(req)
	})
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// ExampleNewClient shows the composition seam: a Method plus an optional base
// transport produce an *http.Client whose every request is authenticated. The
// same client is what a token-family client (e.g. an RFC 8693 token-exchange
// client) accepts as its HTTP client.
func ExampleNewClient() {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "saw %s", r.Header.Get("Authorization"))
	}))
	defer srv.Close()

	// nil base => the client authenticates over http.DefaultTransport.
	client := authn.NewClient(headerMethod{}, nil)

	resp, err := client.Get(srv.URL)
	if err != nil {
		panic(err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	fmt.Println(string(body))
	// Output: saw Bearer example
}
