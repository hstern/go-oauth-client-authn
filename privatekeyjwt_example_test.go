// Copyright 2026 The go-oauth-client-authn Authors
// SPDX-License-Identifier: Apache-2.0

package authn_test

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"

	authn "github.com/hstern/go-oauth-client-authn"
)

// ExamplePrivateKeyJWT shows private_key_jwt authenticating a token request: the
// client signs a short-lived JWT assertion with its private key, and the library
// posts it as client_assertion. Here the key is an in-memory *rsa.PrivateKey,
// but any crypto.Signer works — including an HSM- or KMS-backed key whose private
// material never leaves the device.
func ExamplePrivateKeyJWT() {
	// In production this is the client's registered key (often an HSM/KMS
	// crypto.Signer). A throwaway key keeps the example self-contained.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	// A stand-in token endpoint that echoes which auth method it saw.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		_, _ = fmt.Fprintf(w, "client_assertion_type=%s assertion_present=%t",
			r.PostForm.Get("client_assertion_type"),
			r.PostForm.Get("client_assertion") != "")
	}))
	defer srv.Close()

	client := authn.NewClient(authn.PrivateKeyJWT("s6BhdRkqt3", key), nil)

	resp, err := client.PostForm(srv.URL, url.Values{"grant_type": {"client_credentials"}})
	if err != nil {
		panic(err)
	}
	defer func() { _ = resp.Body.Close() }()

	var buf [256]byte
	n, _ := resp.Body.Read(buf[:])
	fmt.Println(string(buf[:n]))
	// Output: client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer assertion_present=true
}
