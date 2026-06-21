// Copyright 2026 The go-oauth-client-authn Authors
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"
)

// keyEqualer is the comparison method crypto public keys expose since Go 1.15
// (*rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey all have it). The
// round-trip tests assert the parsed signer's public key against the original
// through this method rather than reflect.DeepEqual, which is the
// crypto-idiomatic identity check.
type keyEqualer interface {
	Equal(x crypto.PublicKey) bool
}

func samePublic(t *testing.T, got crypto.PublicKey, want crypto.PublicKey) {
	t.Helper()
	eq, ok := want.(keyEqualer)
	if !ok {
		t.Fatalf("public key of type %T has no Equal method", want)
	}
	if !eq.Equal(got) {
		t.Fatalf("parsed public key does not equal the original")
	}
}

// genKeys returns one private key per supported algorithm family, each as a
// crypto.Signer so the round-trip table can treat them uniformly.
func genKeys(t *testing.T) map[string]crypto.Signer {
	t.Helper()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	return map[string]crypto.Signer{
		"RSA":     rsaKey,
		"ECDSA":   ecKey,
		"Ed25519": edKey,
	}
}

func pkcs8PEM(tb testing.TB, key crypto.Signer) []byte {
	tb.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		tb.Fatalf("marshal PKCS#8: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func jwkJSON(tb testing.TB, key crypto.Signer) []byte {
	tb.Helper()
	jwk := jose.JSONWebKey{Key: key}
	data, err := jwk.MarshalJSON()
	if err != nil {
		tb.Fatalf("marshal JWK: %v", err)
	}
	return data
}

// TestSignerFromPEMPKCS8 round-trips each key family through PKCS#8 PEM (the
// universal encoding) and asserts the parsed signer's public key equals the
// original.
func TestSignerFromPEMPKCS8(t *testing.T) {
	t.Parallel()
	for name, key := range genKeys(t) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			signer, err := SignerFromPEM(pkcs8PEM(t, key))
			if err != nil {
				t.Fatalf("SignerFromPEM: %v", err)
			}
			samePublic(t, signer.Public(), key.Public())
		})
	}
}

// TestSignerFromPEMPKCS1 covers the RSA-only PKCS#1 ("RSA PRIVATE KEY") encoding.
func TestSignerFromPEMPKCS1(t *testing.T) {
	t.Parallel()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
	})

	signer, err := SignerFromPEM(pemBytes)
	if err != nil {
		t.Fatalf("SignerFromPEM: %v", err)
	}
	samePublic(t, signer.Public(), rsaKey.Public())
}

// TestSignerFromPEMSEC1 covers the EC-only SEC 1 ("EC PRIVATE KEY") encoding.
func TestSignerFromPEMSEC1(t *testing.T) {
	t.Parallel()
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatalf("marshal SEC 1: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	signer, err := SignerFromPEM(pemBytes)
	if err != nil {
		t.Fatalf("SignerFromPEM: %v", err)
	}
	samePublic(t, signer.Public(), ecKey.Public())
}

// TestSignerFromJWK round-trips each key family through its JWK encoding.
func TestSignerFromJWK(t *testing.T) {
	t.Parallel()
	for name, key := range genKeys(t) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			signer, err := SignerFromJWK(jwkJSON(t, key))
			if err != nil {
				t.Fatalf("SignerFromJWK: %v", err)
			}
			samePublic(t, signer.Public(), key.Public())
		})
	}
}

// TestSignerSignsVerifiableAssertion is the helpers' reason to exist: a signer
// parsed from PEM or JWK must be usable to sign a JWS that verifies under the
// original public key. It signs through cryptosigner.Opaque — the same wrapper
// PrivateKeyJWT uses to drive a crypto.Signer — so the test proves the parsed
// key works end-to-end for assertion signing without coupling to the
// private_key_jwt method (which lands in a separate change).
func TestSignerSignsVerifiableAssertion(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	cases := map[string][]byte{
		"PEM": pkcs8PEM(t, rsaKey),
		"JWK": jwkJSON(t, rsaKey),
	}
	for name, encoded := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var (
				signer crypto.Signer
				err    error
			)
			if name == "PEM" {
				signer, err = SignerFromPEM(encoded)
			} else {
				signer, err = SignerFromJWK(encoded)
			}
			if err != nil {
				t.Fatalf("parse signer: %v", err)
			}

			js, err := jose.NewSigner(
				jose.SigningKey{Algorithm: jose.RS256, Key: cryptosigner.Opaque(signer)},
				(&jose.SignerOptions{}).WithType("JWT"),
			)
			if err != nil {
				t.Fatalf("new signer: %v", err)
			}
			payload := []byte(`{"iss":"client","sub":"client"}`)
			signed, err := js.Sign(payload)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			compact, err := signed.CompactSerialize()
			if err != nil {
				t.Fatalf("serialize: %v", err)
			}

			parsed, err := jose.ParseSigned(compact, []jose.SignatureAlgorithm{jose.RS256})
			if err != nil {
				t.Fatalf("parse signed: %v", err)
			}
			verified, err := parsed.Verify(rsaKey.Public())
			if err != nil {
				t.Fatalf("verify under original public key: %v", err)
			}
			if string(verified) != string(payload) {
				t.Fatalf("verified payload = %q, want %q", verified, payload)
			}
		})
	}
}

func TestSignerFromPEMErrors(t *testing.T) {
	t.Parallel()

	encKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	// A legacy encrypted PEM block: marshalled plaintext DER plus the
	// Proc-Type: 4,ENCRYPTED header SignerFromPEM keys off. The body need not be
	// genuinely ciphertext — detection is by header, before any parse.
	encryptedPEM := pem.EncodeToMemory(&pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-256-CBC,0000"},
		Bytes:   x509.MarshalPKCS1PrivateKey(encKey),
	})
	encryptedPKCS8 := pem.EncodeToMemory(&pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: []byte("not really encrypted but the type says so"),
	})
	pubOnlyPEM := func() []byte {
		der, err := x509.MarshalPKIXPublicKey(encKey.Public())
		if err != nil {
			t.Fatalf("marshal public key: %v", err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	}()

	tests := []struct {
		name      string
		input     []byte
		wantInErr string
	}{
		{"empty input", nil, "no PEM block"},
		{"non-PEM bytes", []byte("this is not a PEM file at all"), "no PEM block"},
		{"encrypted legacy", encryptedPEM, "encrypted PEM keys are not supported"},
		{"encrypted pkcs8", encryptedPKCS8, "encrypted PEM keys are not supported"},
		{"unsupported block type", pubOnlyPEM, "unsupported PEM block type"},
		{"garbage in PKCS#8 block", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("garbage")}), "parse PKCS#8"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := SignerFromPEM(tc.input)
			if err == nil {
				t.Fatalf("SignerFromPEM(%s) = nil error, want error", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantInErr) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tc.wantInErr)
			}
			assertNoKeyLeak(t, err, tc.input)
		})
	}
}

func TestSignerFromJWKErrors(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	publicJWK := func() []byte {
		jwk := jose.JSONWebKey{Key: rsaKey.Public()}
		data, err := jwk.MarshalJSON()
		if err != nil {
			t.Fatalf("marshal public JWK: %v", err)
		}
		return data
	}()

	tests := []struct {
		name      string
		input     []byte
		wantInErr string
	}{
		{"empty input", nil, "parse JWK"},
		{"non-JSON bytes", []byte("not json"), "parse JWK"},
		{"public-only JWK", publicJWK, "only public-key material"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := SignerFromJWK(tc.input)
			if err == nil {
				t.Fatalf("SignerFromJWK(%s) = nil error, want error", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantInErr) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tc.wantInErr)
			}
			assertNoKeyLeak(t, err, tc.input)
		})
	}
}

// assertNoKeyLeak guards the security contract: a parse error never embeds the
// input key bytes. It checks that no non-trivial run of the input appears in the
// error text (short runs would false-positive on incidental byte overlap).
func assertNoKeyLeak(t *testing.T, err error, input []byte) {
	t.Helper()
	if len(input) < 16 {
		return
	}
	msg := err.Error()
	for i := 0; i+16 <= len(input); i += 16 {
		if strings.Contains(msg, string(input[i:i+16])) {
			t.Fatalf("error text leaks input key material: %q", msg)
		}
	}
}

// FuzzSignerFromPEM checks the parser's robustness invariant on arbitrary input:
// it must return cleanly with either a signer or an error, never panic. The seed
// corpus carries a well-formed key and a few structurally-suggestive but invalid
// inputs so the fuzzer starts from the parse paths that matter.
func FuzzSignerFromPEM(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate EC key: %v", err)
	}
	f.Add(pkcs8PEM(f, key))
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\nZ\n-----END PRIVATE KEY-----\n"))
	f.Add([]byte("not pem at all"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		signer, err := SignerFromPEM(data)
		if err == nil && signer == nil {
			t.Fatal("SignerFromPEM returned nil signer and nil error")
		}
	})
}

// FuzzSignerFromJWK is the JWK counterpart to FuzzSignerFromPEM: the go-jose
// UnmarshalJSON path must also never panic on malformed input.
func FuzzSignerFromJWK(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate EC key: %v", err)
	}
	f.Add(jwkJSON(f, key))
	f.Add([]byte(`{"kty":"EC","crv":"P-256"}`))
	f.Add([]byte(`{`))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		signer, err := SignerFromJWK(data)
		if err == nil && signer == nil {
			t.Fatal("SignerFromJWK returned nil signer and nil error")
		}
	})
}

// TestSignerFromPEMOnlyFirstBlock documents that SignerFromPEM reads the first
// PEM block and ignores trailing blocks, matching pem.Decode's single-block
// contract. A concatenated public block after the private one does not change
// the result.
func TestSignerFromPEMOnlyFirstBlock(t *testing.T) {
	t.Parallel()
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	priv := pkcs8PEM(t, ecKey)
	pubDER, err := x509.MarshalPKIXPublicKey(ecKey.Public())
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	signer, err := SignerFromPEM(append(priv, pub...))
	if err != nil {
		t.Fatalf("SignerFromPEM: %v", err)
	}
	samePublic(t, signer.Public(), ecKey.Public())
}
