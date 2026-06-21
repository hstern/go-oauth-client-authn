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

	authn "github.com/hstern/go-oauth-client-authn"
)

// ExampleClientSecretPost shows client_secret_post (RFC 6749 §2.3.1): the
// constructed Method adds client_id and client_secret to the form body of every
// token-endpoint request the client carries, preserving the parameters the body
// already holds (here grant_type).
func ExampleClientSecretPost() {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		fmt.Printf("grant_type=%s client_id=%s client_secret=%s\n",
			r.PostForm.Get("grant_type"),
			r.PostForm.Get("client_id"),
			r.PostForm.Get("client_secret"),
		)
	}))
	defer srv.Close()

	client := authn.NewClient(authn.ClientSecretPost("s6BhdRkqt3", "7Fjfp0ZBr1KtDRbnfVdmIw"), nil)

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

	// Output: grant_type=client_credentials client_id=s6BhdRkqt3 client_secret=7Fjfp0ZBr1KtDRbnfVdmIw
}
