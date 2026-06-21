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

// ExampleClientSecretBasic shows client_secret_basic on the wire: the resulting
// client sends the credentials in an HTTP Basic Authorization header on every
// request. The id and secret are form-urlencoded before being base64-encoded
// (RFC 6749 §2.3.1), which only becomes visible when either value contains a
// character the form encoding touches.
func ExampleClientSecretBasic() {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "saw %s", r.Header.Get("Authorization"))
	}))
	defer srv.Close()

	client := authn.NewClient(authn.ClientSecretBasic("s6BhdRkqt3", "7Fjfp0ZBr1KtDRbnfVdmIw"), nil)

	resp, err := client.Get(srv.URL)
	if err != nil {
		panic(err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	fmt.Println(string(body))
	// Output: saw Basic czZCaGRSa3F0Mzo3RmpmcDBaQnIxS3REUmJuZlZkbUl3
}
