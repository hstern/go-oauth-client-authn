// Copyright 2026 The go-oauth-client-authn Authors
// SPDX-License-Identifier: Apache-2.0

package authn_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	authn "github.com/hstern/go-oauth-client-authn"
)

// ExampleSignerFromPEM loads a private key from a PEM file into a crypto.Signer.
// The resulting signer is the canonical key input for the asymmetric JWT
// client-authentication method: pass it straight to private_key_jwt without
// hand-rolling crypto/x509 parsing.
//
// A SEC 1 ("EC PRIVATE KEY"), PKCS#1 ("RSA PRIVATE KEY"), or PKCS#8
// ("PRIVATE KEY") block all load the same way; this example uses an EC key.
func ExampleSignerFromPEM() {
	// In real code, pemBytes is os.ReadFile("client-key.pem"). Generated inline
	// here so the example is self-contained and deterministic.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	signer, err := authn.SignerFromPEM(pemBytes)
	if err != nil {
		panic(err)
	}

	// signer.Public() is the verification key the authorization server registers
	// for this client; the private half never leaves the signer.
	fmt.Printf("%T\n", signer.Public())
	// Output: *ecdsa.PublicKey
}

// ExampleSignerFromJWK loads a private key from its JSON Web Key (RFC 7517)
// encoding, the form an OAuth client registration response or a JWKS file
// carries. A JWK that holds only public-key material is rejected, since a key
// used to sign assertions must be private.
func ExampleSignerFromJWK() {
	privateJWK := []byte(`{
		"kty": "OKP",
		"crv": "Ed25519",
		"x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
		"d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
	}`)

	signer, err := authn.SignerFromJWK(privateJWK)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%T\n", signer.Public())

	publicOnly := []byte(`{
		"kty": "OKP",
		"crv": "Ed25519",
		"x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
	}`)
	if _, err := authn.SignerFromJWK(publicOnly); err != nil {
		fmt.Println("public-only JWK rejected")
	}
	// Output:
	// ed25519.PublicKey
	// public-only JWK rejected
}
