// Copyright 2026 The go-oauth-client-authn Authors
// SPDX-License-Identifier: Apache-2.0

package authn_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	tokenexchange "github.com/hstern/go-token-exchange"

	authn "github.com/hstern/go-oauth-client-authn"
)

// TestComposition is the headline interop proof: that authn.NewClient(method,
// nil) produces exactly the *http.Client an RFC 8693 token-exchange client
// consumes through its WithHTTPClient seam, and that client authentication and
// the token-exchange grant share one form body without clobbering each other.
//
// The flow under test is end-to-end through a real consumer:
//
//	hc := authn.NewClient(method, nil)
//	c  := tokenexchange.NewClient(endpoint, tokenexchange.WithHTTPClient(hc))
//	resp, err := c.Exchange(ctx, req)
//
// An httptest server plays the token-exchange token endpoint. For every method
// it parses the form with tokenexchange.ParseTokenExchangeRequest, asserts the
// RFC 8693 §2.1 grant (grant_type, subject_token, subject_token_type), then runs
// a per-method check of the client authentication the transport added — proving
// the seam is method-agnostic. On success it returns a minimal valid RFC 8693
// §2.2 JSON response so the go-token-exchange client's Exchange succeeds.
//
// The table covers the three credential shapes that exercise distinct seams:
//
//   - client_secret_basic — credentials in the Authorization header, leaving the
//     form body the token-exchange client built untouched.
//   - client_secret_post — credentials written into the same form body as the
//     grant params, proving augmentForm preserves the pre-existing parameters.
//   - private_key_jwt — a signed assertion written into that same body, proving
//     the same preservation for the JWT methods and that the assertion verifies.
func TestComposition(t *testing.T) {
	t.Parallel()

	const (
		compositionClientID     = "s6BhdRkqt3"
		compositionClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw"
		compositionSubjectToken = "eyJhbGciOiJFUzI1NiIsImtpZCI6IjE2In0.subject.sig"
	)

	// One RSA key drives the private_key_jwt row; its public half verifies the
	// assertion the server receives.
	rsaKey := compositionRSAKey(t)

	tests := []struct {
		name string
		// method is the client-authentication method under test.
		method authn.Method
		// wantAuthMethod is the RFC 7591 token_endpoint_auth_method the row
		// exercises, asserted via method.Name to guard against table drift.
		wantAuthMethod string
		// checkAuth asserts, server-side, that the request carried the client
		// authentication this method is supposed to add. The form is already
		// parsed (r.Form / r.PostForm populated) when checkAuth runs.
		checkAuth func(t *testing.T, r *http.Request)
	}{
		{
			name:           "client_secret_basic",
			method:         authn.ClientSecretBasic(compositionClientID, compositionClientSecret),
			wantAuthMethod: "client_secret_basic",
			checkAuth: func(t *testing.T, r *http.Request) {
				t.Helper()
				gotID, gotSecret, ok := r.BasicAuth()
				if !ok {
					// checkAuth runs on the httptest server goroutine, so it must
					// not call t.Fatal* (FailNow from a non-test goroutine is
					// disallowed): report and stop this check, not the goroutine.
					t.Errorf("Authorization: want HTTP Basic credentials, got %q", r.Header.Get("Authorization"))
					return
				}
				if gotID != compositionClientID || gotSecret != compositionClientSecret {
					t.Errorf("Basic credentials = (%q, %q), want (%q, %q)",
						gotID, gotSecret, compositionClientID, compositionClientSecret)
				}
				// Basic auth must NOT leak the credentials into the form body.
				if v := r.PostForm.Get("client_secret"); v != "" {
					t.Errorf("client_secret_basic leaked client_secret into form body: %q", v)
				}
			},
		},
		{
			name:           "client_secret_post",
			method:         authn.ClientSecretPost(compositionClientID, compositionClientSecret),
			wantAuthMethod: "client_secret_post",
			checkAuth: func(t *testing.T, r *http.Request) {
				t.Helper()
				if got := r.PostForm.Get("client_id"); got != compositionClientID {
					t.Errorf("form client_id = %q, want %q", got, compositionClientID)
				}
				if got := r.PostForm.Get("client_secret"); got != compositionClientSecret {
					t.Errorf("form client_secret = %q, want %q", got, compositionClientSecret)
				}
				// The credentials coexist with the grant params in the one body.
				compositionAssertNoGrantClobber(t, r)
				// No Authorization header for the post variant.
				if h := r.Header.Get("Authorization"); h != "" {
					t.Errorf("client_secret_post set an Authorization header: %q", h)
				}
			},
		},
		{
			name:           "private_key_jwt",
			method:         authn.PrivateKeyJWT(compositionClientID, rsaKey),
			wantAuthMethod: "private_key_jwt",
			checkAuth: func(t *testing.T, r *http.Request) {
				t.Helper()
				if got := r.PostForm.Get("client_assertion_type"); got != compositionAssertionType {
					t.Errorf("client_assertion_type = %q, want %q", got, compositionAssertionType)
				}
				assertion := r.PostForm.Get("client_assertion")
				if assertion == "" {
					t.Error("client_assertion is missing from the form body")
					return
				}
				claims, ok := compositionVerifyRS256(t, assertion, &rsaKey.PublicKey)
				if !ok {
					return
				}
				if claims.Issuer != compositionClientID || claims.Subject != compositionClientID {
					t.Errorf("assertion iss/sub = (%q, %q), want both %q",
						claims.Issuer, claims.Subject, compositionClientID)
				}
				if len(claims.Audience) == 0 {
					t.Error("assertion has no aud claim")
				}
				// The assertion coexists with the grant params in the one body.
				compositionAssertNoGrantClobber(t, r)
				if h := r.Header.Get("Authorization"); h != "" {
					t.Errorf("private_key_jwt set an Authorization header: %q", h)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.method.Name(); got != tt.wantAuthMethod {
				t.Fatalf("method.Name() = %q, want %q", got, tt.wantAuthMethod)
			}

			srv := httptest.NewServer(compositionEndpoint(t, compositionSubjectToken, tt.checkAuth))
			t.Cleanup(srv.Close)

			// The seam under test: the token-exchange client consumes the
			// authenticating *http.Client verbatim through WithHTTPClient.
			hc := authn.NewClient(tt.method, nil)
			client := tokenexchange.NewClient(srv.URL, tokenexchange.WithHTTPClient(hc))

			resp, err := client.Exchange(t.Context(), &tokenexchange.TokenExchangeRequest{
				GrantType:        tokenexchange.GrantTypeTokenExchange,
				SubjectToken:     compositionSubjectToken,
				SubjectTokenType: tokenexchange.TokenTypeAccessToken,
			})
			if err != nil {
				t.Fatalf("Exchange: unexpected error: %v", err)
			}
			if resp.AccessToken != compositionIssuedToken {
				t.Errorf("AccessToken = %q, want %q", resp.AccessToken, compositionIssuedToken)
			}
			if resp.IssuedTokenType != tokenexchange.TokenTypeAccessToken {
				t.Errorf("IssuedTokenType = %q, want %q", resp.IssuedTokenType, tokenexchange.TokenTypeAccessToken)
			}
			if resp.TokenType != "Bearer" {
				t.Errorf("TokenType = %q, want %q", resp.TokenType, "Bearer")
			}
		})
	}
}

// compositionAssertionType is the RFC 7523 §2.2 client_assertion_type URN both
// JWT client-authentication methods send. Pinned here so the composition test
// asserts the on-the-wire value independent of the library's own constant.
const compositionAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// compositionIssuedToken is the access_token the stub endpoint returns on a
// successful exchange, asserted by the client side.
const compositionIssuedToken = "issued-access-token"

// compositionEndpoint returns the httptest handler that plays the token-exchange
// token endpoint. It parses the form with the real go-token-exchange parser,
// asserts the RFC 8693 §2.1 grant, runs the per-method client-authentication
// check, and on success writes a minimal valid RFC 8693 §2.2 JSON response.
func compositionEndpoint(t *testing.T, wantSubjectToken string, checkAuth func(*testing.T, *http.Request)) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		// ParseTokenExchangeRequest calls r.ParseForm, populating r.Form and
		// r.PostForm so both the grant params (via the typed request) and the
		// client-authentication params (read directly below) are available.
		parsed, err := tokenexchange.ParseTokenExchangeRequest(r)
		if err != nil {
			t.Errorf("server: parse token-exchange request: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		if parsed.GrantType != tokenexchange.GrantTypeTokenExchange {
			t.Errorf("server: grant_type = %q, want %q", parsed.GrantType, tokenexchange.GrantTypeTokenExchange)
		}
		if parsed.SubjectToken != wantSubjectToken {
			t.Errorf("server: subject_token = %q, want %q", parsed.SubjectToken, wantSubjectToken)
		}
		if parsed.SubjectTokenType != tokenexchange.TokenTypeAccessToken {
			t.Errorf("server: subject_token_type = %q, want %q", parsed.SubjectTokenType, tokenexchange.TokenTypeAccessToken)
		}

		checkAuth(t, r)

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(tokenexchange.TokenExchangeResponse{
			AccessToken:     compositionIssuedToken,
			IssuedTokenType: tokenexchange.TokenTypeAccessToken,
			TokenType:       "Bearer",
		}); err != nil {
			t.Errorf("server: encode response: %v", err)
		}
	}
}

// compositionRSAKey generates a 2048-bit RSA signing key for the private_key_jwt
// table row. 2048 bits is the smallest modulus RFC 7518 permits for RS256 and
// keeps the test fast.
func compositionRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return key
}

// compositionVerifyRS256 parses raw as an RS256-signed JWT, verifies the
// signature against pub, and returns the registered claims. A signature or
// algorithm mismatch fails the test: the assertion the AS receives must verify
// against the client's published key for the exchange to be trustworthy.
//
// It reports failures with t.Errorf and signals them through the bool return
// rather than t.Fatal: it is called from the httptest server goroutine, where
// FailNow (and thus t.Fatal) is disallowed by the testing package.
func compositionVerifyRS256(t *testing.T, raw string, pub crypto.PublicKey) (jwt.Claims, bool) {
	t.Helper()
	parsed, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Errorf("parse client_assertion: %v", err)
		return jwt.Claims{}, false
	}
	var claims jwt.Claims
	if err := parsed.Claims(pub, &claims); err != nil {
		t.Errorf("verify client_assertion signature: %v", err)
		return jwt.Claims{}, false
	}
	return claims, true
}

// compositionAssertNoGrantClobber is a guard used by the post and JWT rows: the
// client-authentication parameters must coexist with the grant parameters in the
// shared form body. It reports any grant parameter the authentication step
// dropped. It is defined separately so a future row can reuse it.
func compositionAssertNoGrantClobber(t *testing.T, r *http.Request) {
	t.Helper()
	for _, p := range []string{"grant_type", "subject_token", "subject_token_type"} {
		if r.PostForm.Get(p) == "" {
			t.Errorf("client authentication clobbered grant parameter %q", p)
		}
	}
}
