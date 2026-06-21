// Copyright 2026 The go-oauth-client-authn Authors
// SPDX-License-Identifier: Apache-2.0

package authn_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	authn "github.com/hstern/go-oauth-client-authn"
)

// ExampleWithAudience shows the WithAudience assertion option. By default a JWT
// client-authentication method (client_secret_jwt, private_key_jwt) derives the
// assertion's aud claim from the request URL, so one configured Method binds
// correctly at the token, PAR, introspection, and revocation endpoints. Some
// authorization servers instead require their issuer identifier as the audience;
// WithAudience supplies that value verbatim, and it is used unchanged regardless
// of which endpoint the request targets.
func ExampleWithAudience() {
	const (
		clientID     = "s6BhdRkqt3"
		clientSecret = "0123456789abcdef0123456789abcdef" // 32 bytes: HS256 floor.
		issuer       = "https://issuer.example.com"
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

		// The aud is the configured issuer, not the request URL.
		fmt.Printf("aud=%s\n", claims.Audience[0])
	}))
	defer srv.Close()

	method := authn.ClientSecretJWT(clientID, clientSecret, authn.WithAudience(issuer))
	client := authn.NewClient(method, nil)

	resp, err := client.PostForm(srv.URL, url.Values{"grant_type": {"client_credentials"}})
	if err != nil {
		panic(err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Output: aud=https://issuer.example.com
}
