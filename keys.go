// Copyright 2026 The go-oauth-client-authn Authors
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	jose "github.com/go-jose/go-jose/v4"
)

// design §4 fixes crypto.Signer as the canonical private-key input for the JWT
// client-authentication methods (client_secret_jwt is symmetric and takes a
// secret; private_key_jwt is asymmetric and takes a signer). A crypto.Signer is
// what an HSM- or KMS-backed key satisfies without the raw key material ever
// leaving the device, so the methods accept exactly that and nothing wider.
//
// Most callers, however, hold a key in a serialized form — a PEM file on disk,
// or a JWK from a registration response — not as a live crypto.Signer. The
// helpers here close that gap: they parse the common encodings into a
// crypto.Signer the methods can consume directly, so callers do not hand-roll
// crypto/x509 or JWK parsing at every call site.
//
// Security: a private key is bearer-equivalent. None of these helpers logs key
// material, and no error they return embeds the input bytes, the PEM body, or
// any parsed key parameter — only the structural reason the parse failed.

// SignerFromPEM decodes a single PEM block and parses the private key it
// carries, returning it as a [crypto.Signer]. It accepts the three PEM
// encodings an OAuth client key is realistically distributed in:
//
//   - PKCS#8, "PRIVATE KEY" — any key type, via [x509.ParsePKCS8PrivateKey]
//   - PKCS#1, "RSA PRIVATE KEY" — RSA only, via [x509.ParsePKCS1PrivateKey]
//   - SEC 1, "EC PRIVATE KEY" — ECDSA only, via [x509.ParseECPrivateKey]
//
// The parsed key is returned as a [crypto.Signer]; *rsa.PrivateKey,
// *ecdsa.PrivateKey, and ed25519.PrivateKey all satisfy the interface, so RSA,
// ECDSA, and (via PKCS#8) Ed25519 keys all load. The result is ready to pass to
// [PrivateKeyJWT].
//
// Errors are returned, never the key: an input with no PEM block, an
// unrecognized or encrypted block type, a parse failure, or a parsed key that is
// not a signer each produce a distinct error whose text names the structural
// cause but never the key bytes. Encrypted PEM (a legacy "Proc-Type: 4,ENCRYPTED"
// header, or a PKCS#8 "ENCRYPTED PRIVATE KEY" block) is rejected with a clear
// error rather than mis-parsed; decrypting passphrase-protected keys is out of
// scope (the caller decrypts first, then passes the plaintext PEM).
func SignerFromPEM(pemBytes []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("authn: no PEM block found in input")
	}

	// Reject encrypted keys before parsing: a legacy encrypted block carries the
	// "Proc-Type: 4,ENCRYPTED" header, and PKCS#8 encrypted keys use a distinct
	// block type. Either would otherwise fail parsing with an opaque ASN.1 error;
	// a named error tells the caller to decrypt first.
	if _, encrypted := block.Headers["Proc-Type"]; encrypted {
		return nil, errors.New("authn: encrypted PEM keys are not supported; decrypt the key first")
	}
	if block.Type == "ENCRYPTED PRIVATE KEY" {
		return nil, errors.New("authn: encrypted PEM keys are not supported; decrypt the key first")
	}

	key, err := parsePEMKey(block)
	if err != nil {
		return nil, err
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("authn: parsed key of type %T is not a crypto.Signer", key)
	}
	return signer, nil
}

// parsePEMKey parses a non-encrypted private-key PEM block by its type, dividing
// the supported encodings across the three crypto/x509 parsers. An unrecognized
// block type is reported by name (the type is a public PEM label, never key
// material), and a parse failure is wrapped without the key bytes.
func parsePEMKey(block *pem.Block) (any, error) {
	switch block.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("authn: parse PKCS#8 private key: %w", err)
		}
		return key, nil
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("authn: parse PKCS#1 RSA private key: %w", err)
		}
		return key, nil
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("authn: parse SEC 1 EC private key: %w", err)
		}
		return key, nil
	default:
		return nil, fmt.Errorf("authn: unsupported PEM block type %q", block.Type)
	}
}

// SignerFromJWK parses a single JSON Web Key (RFC 7517) carrying private-key
// material and returns it as a [crypto.Signer], ready to pass to [PrivateKeyJWT].
// It accepts the asymmetric key types RFC 7518 §6 defines for signing — RSA
// (kty "RSA"), EC (kty "EC"), and OKP Ed25519 (kty "OKP", crv "Ed25519") — since
// each parses to a Go key (*rsa.PrivateKey, *ecdsa.PrivateKey,
// ed25519.PrivateKey) that satisfies [crypto.Signer].
//
// A JWK that carries only public-key material is rejected: handing a public key
// to a method that must sign is a misuse worth catching at parse time rather
// than surfacing as an obscure failure when the first assertion cannot be
// signed. A structurally invalid JWK, or one whose parsed key is symmetric
// (kty "oct", which has no signer), is likewise rejected.
//
// As with [SignerFromPEM], no error embeds the key: the JWK bytes and every
// parsed parameter stay out of the returned error text.
func SignerFromJWK(jwkJSON []byte) (crypto.Signer, error) {
	var jwk jose.JSONWebKey
	if err := jwk.UnmarshalJSON(jwkJSON); err != nil {
		return nil, fmt.Errorf("authn: parse JWK: %w", err)
	}
	if !jwk.Valid() {
		return nil, errors.New("authn: JWK is not a valid key")
	}
	if jwk.IsPublic() {
		return nil, errors.New("authn: JWK carries only public-key material; a private key is required to sign")
	}

	signer, ok := jwk.Key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("authn: JWK key of type %T is not a crypto.Signer", jwk.Key)
	}
	return signer, nil
}
