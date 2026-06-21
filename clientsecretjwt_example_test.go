// Copyright 2026 The go-oauth-client-authn Authors
// SPDX-License-Identifier: Apache-2.0

package authn_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	authn "github.com/hstern/go-oauth-client-authn"
)

// ExampleClientSecretJWT shows client_secret_jwt (RFC 7523 §2.2): the
// constructed Method signs a short-lived JWT assertion with HMAC-SHA-256 keyed
// on the client secret and posts it as client_assertion, alongside the fixed
// client_assertion_type URN. The authorization server verifies the assertion
// with the same shared secret. Here the example server plays that role and
// reports the claims it recovers.
func ExampleClientSecretJWT() {
	const (
		clientID = "s6BhdRkqt3"
		// HS256 needs a key at least as long as its 256-bit output (RFC 7518
		// §3.2); use a 32-byte secret. Real deployments use a high-entropy one.
		clientSecret = "0123456789abcdef0123456789abcdef"
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()

		tok, err := jwt.ParseSigned(
			r.PostForm.Get("client_assertion"),
			[]jose.SignatureAlgorithm{jose.HS256},
		)
		if err != nil {
			http.Error(w, "bad assertion", http.StatusBadRequest)
			return
		}
		var claims jwt.Claims
		if err := tok.Claims([]byte(clientSecret), &claims); err != nil {
			http.Error(w, "assertion does not verify", http.StatusUnauthorized)
			return
		}

		fmt.Printf("type=%s iss=%s sub=%s\n",
			r.PostForm.Get("client_assertion_type"),
			claims.Issuer,
			claims.Subject,
		)
	}))
	defer srv.Close()

	client := authn.NewClient(authn.ClientSecretJWT(clientID, clientSecret), nil)

	body := strings.NewReader(url.Values{"grant_type": {"client_credentials"}}.Encode())
	req, err := http.NewRequest(http.MethodPost, srv.URL, body)
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Output: type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer iss=s6BhdRkqt3 sub=s6BhdRkqt3
}
