// Copyright 2023 Board of Trustees of the University of Illinois.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/golang-jwt/jwt"
	"github.com/rokwire/core-auth-library-go/v2/authutils"
)

const (
	errUnsupportedAlg   string = "unsupported algorithm"
	errMismatchedKeyAlg string = "key type does not match algorithm"
)

// -------------------- PrivKey --------------------

// PrivKey represents a private key object including the key and related metadata
type PrivKey struct {
	Key    interface{} `json:"-" bson:"-"`
	KeyPem string      `json:"key_pem" bson:"key_pem" validate:"required"`
	Alg    string      `json:"alg" bson:"alg" validate:"required"`
}

// Decode sets the "Key" by decoding "KeyPem"
func (p *PrivKey) Decode() error {
	if p == nil {
		return fmt.Errorf("privkey is nil")
	}

	var err error
	switch authutils.KeyTypeFromAlg(p.Alg) {
	case "RSA":
		p.Key, err = jwt.ParseRSAPrivateKeyFromPEM([]byte(p.KeyPem))
	case "EC":
		p.Key, err = jwt.ParseECPrivateKeyFromPEM([]byte(p.KeyPem))
	case "Ed":
		p.Key, err = jwt.ParseEdPrivateKeyFromPEM([]byte(p.KeyPem))
	default:
		return errors.New(errUnsupportedAlg)
	}
	if err != nil {
		return fmt.Errorf("error parsing key string: %v", err)
	}

	return nil
}

// Encode sets the "KeyPem" by encoding "Key" in PEM form
func (p *PrivKey) Encode() error {
	if p == nil {
		return fmt.Errorf("privkey is nil")
	}

	var privASN1 []byte
	var err error
	switch authutils.KeyTypeFromAlg(p.Alg) {
	case "RSA":
		key, ok := p.Key.(*rsa.PrivateKey)
		if !ok {
			return errors.New(errMismatchedKeyAlg)
		}
		privASN1 = x509.MarshalPKCS1PrivateKey(key)
	case "EC", "Ed":
		privASN1, err = x509.MarshalPKCS8PrivateKey(p.Key)
		if err != nil {
			return fmt.Errorf("error marshalling private key: %v", err)
		}
	default:
		return errors.New(errUnsupportedAlg)
	}

	p.KeyPem = string(pem.EncodeToMemory(
		&pem.Block{
			Type:  fmt.Sprintf("%s PRIVATE KEY", authutils.KeyTypeFromAlg(p.Alg)),
			Bytes: privASN1,
		},
	))

	return nil
}

// Decrypt decrypts data using "Key"
func (p *PrivKey) Decrypt(data []byte, label []byte) (string, error) {
	if p == nil {
		return "", fmt.Errorf("privkey is nil")
	}

	switch authutils.KeyTypeFromAlg(p.Alg) {
	case "RSA":
		key, ok := p.Key.(*rsa.PrivateKey)
		if !ok {
			return "", errors.New(errMismatchedKeyAlg)
		}

		hash := authutils.HashFromAlg(p.Alg)
		if hash == 0 {
			return "", fmt.Errorf("unsupported hashing method %s", p.Alg)
		}
		cipherText, err := rsa.DecryptOAEP(hash.New(), rand.Reader, key, data, label)
		if err != nil {
			return "", fmt.Errorf("error decrypting data with RSA private key: %v", err)
		}
		return string(cipherText), nil
	}

	return "", errors.New("decryption is unsupported for algorithm " + p.Alg)
}

// Sign uses "Key" to sign message
func (p *PrivKey) Sign(message []byte) (string, error) {
	if p == nil {
		return "", fmt.Errorf("privkey is nil")
	}

	sigMethod := jwt.GetSigningMethod(p.Alg)
	if sigMethod == nil {
		return "", errors.New(errUnsupportedAlg)
	}
	signature, err := sigMethod.Sign(string(message), p.Key)
	if err != nil {
		return "", fmt.Errorf("error signing message: %v", err)
	}

	return base64.StdEncoding.EncodeToString([]byte(signature)), nil
}

// PubKey returns the public key representation corresponding to the private key
func (p *PrivKey) PubKey() (*PubKey, error) {
	if p == nil {
		return nil, fmt.Errorf("privkey is nil")
	}

	var key privateKey
	var ok bool
	public := PubKey{Alg: p.Alg}
	switch authutils.KeyTypeFromAlg(p.Alg) {
	case "RSA":
		key, ok = p.Key.(*rsa.PrivateKey)
	case "EC":
		key, ok = p.Key.(*ecdsa.PrivateKey)
	case "Ed":
		key, ok = p.Key.(ed25519.PrivateKey)
	default:
		return nil, errors.New(errUnsupportedAlg)
	}
	if !ok {
		return nil, errors.New(errMismatchedKeyAlg)
	}
	public.Key = key.Public()

	err := public.Encode()
	if err != nil {
		return nil, fmt.Errorf("error encoding public key in PEM form: %v", err)
	}
	err = public.SetKeyFingerprint()
	if err != nil {
		return nil, fmt.Errorf("error setting public key fingerprint: %v", err)
	}

	return &public, nil
}

// Equal determines whether the privkey is equivalent to other
func (p *PrivKey) Equal(other *PrivKey) bool {
	if p == nil || other == nil {
		return p == other
	}

	key, ok := p.Key.(privateKey)
	if !ok {
		return false
	}
	otherKey, ok := other.Key.(privateKey)
	if !ok {
		return false
	}
	return key.Equal(otherKey) && p.Alg == other.Alg
}

// -------------------- PubKey --------------------

// PubKey represents a public key object including the key and related metadata
type PubKey struct {
	Key    interface{} `json:"-" bson:"-"`
	KeyPem string      `json:"key_pem" bson:"key_pem" validate:"required"`
	Alg    string      `json:"alg" bson:"alg" validate:"required"`
	KeyID  string      `json:"-" bson:"-"`
}

// Decode sets the "Key" by decoding "KeyPem" and sets the "KeyID"
func (p *PubKey) Decode() error {
	if p == nil {
		return fmt.Errorf("pubkey is nil")
	}

	var err error
	switch authutils.KeyTypeFromAlg(p.Alg) {
	case "RSA":
		p.Key, err = jwt.ParseRSAPublicKeyFromPEM([]byte(p.KeyPem))
	case "EC":
		p.Key, err = jwt.ParseECPublicKeyFromPEM([]byte(p.KeyPem))
	case "Ed":
		p.Key, err = jwt.ParseEdPublicKeyFromPEM([]byte(p.KeyPem))
	default:
		return errors.New(errUnsupportedAlg)
	}
	if err != nil {
		return fmt.Errorf("error parsing key string: %v", err)
	}

	err = p.SetKeyFingerprint()
	if err != nil {
		return fmt.Errorf("error setting key fingerprint: %v", err)
	}

	return nil
}

// Encode sets the "KeyPem" by encoding "Key" in PEM form
func (p *PubKey) Encode() error {
	if p == nil {
		return fmt.Errorf("pubkey is nil")
	}

	pubASN1, err := x509.MarshalPKIXPublicKey(p.Key)
	if err != nil {
		return fmt.Errorf("error marshalling public key: %v", err)
	}

	p.KeyPem = string(pem.EncodeToMemory(
		&pem.Block{
			Type:  fmt.Sprintf("%s PUBLIC KEY", authutils.KeyTypeFromAlg(p.Alg)),
			Bytes: pubASN1,
		},
	))

	return nil
}

// Encrypt uses "Key" to encrypt data
func (p *PubKey) Encrypt(data []byte, label []byte) (string, error) {
	if p == nil {
		return "", fmt.Errorf("pubkey is nil")
	}

	switch authutils.KeyTypeFromAlg(p.Alg) {
	case "RSA":
		key, ok := p.Key.(*rsa.PublicKey)
		if !ok {
			return "", errors.New(errMismatchedKeyAlg)
		}

		hash := authutils.HashFromAlg(p.Alg)
		if hash == 0 {
			return "", fmt.Errorf("unsupported hashing method %s", p.Alg)
		}
		cipherText, err := rsa.EncryptOAEP(hash.New(), rand.Reader, key, data, label)
		if err != nil {
			return "", fmt.Errorf("error encrypting data with RSA public key: %v", err)
		}
		return string(cipherText), nil
	}

	return "", errors.New("encryption is unsupported for algorithm " + p.Alg)
}

// Verify verifies that signature matches message by using "Key"
func (p *PubKey) Verify(message []byte, signature []byte) error {
	if p == nil {
		return fmt.Errorf("pubkey is nil")
	}

	sigMethod := jwt.GetSigningMethod(p.Alg)
	if sigMethod == nil {
		return errors.New(errUnsupportedAlg)
	}
	err := sigMethod.Verify(string(message), string(signature), p.Key)
	if err != nil {
		return fmt.Errorf("error verifying signature: %v", err)
	}

	return nil
}

// SetKeyFingerprint sets the "KeyID"
func (p *PubKey) SetKeyFingerprint() error {
	if p == nil {
		return fmt.Errorf("pubkey is nil")
	}

	var pubASN1 []byte
	var err error
	switch authutils.KeyTypeFromAlg(p.Alg) {
	case "RSA":
		rsaKey, ok := p.Key.(*rsa.PublicKey)
		if !ok {
			return errors.New(errMismatchedKeyAlg)
		}
		pubASN1 = x509.MarshalPKCS1PublicKey(rsaKey)
	case "EC", "Ed":
		pubASN1, err = x509.MarshalPKIXPublicKey(p.Key)
		if err != nil {
			return fmt.Errorf("error marshalling public key: %v", err)
		}
	default:
		return errors.New(errUnsupportedAlg)
	}

	hash, err := authutils.Hash(pubASN1, p.Alg)
	if err != nil {
		return fmt.Errorf("error hashing key: %v", err)
	}

	p.KeyID = fmt.Sprintf("%s:%s", strings.ReplaceAll(authutils.HashFromAlg(p.Alg).String(), "-", ""), base64.StdEncoding.EncodeToString(hash))
	return nil
}

// Equal determines whether the pubkey is equivalent to other
func (p *PubKey) Equal(other *PubKey) bool {
	if p == nil || other == nil {
		return p == other
	}

	switch authutils.KeyTypeFromAlg(p.Alg) {
	case "RSA", "EC", "Ed":
		key, ok := p.Key.(publicKey)
		if !ok {
			return false
		}
		otherKey, ok := other.Key.(publicKey)
		if !ok {
			return false
		}
		return key.Equal(otherKey) && p.Alg == other.Alg && p.KeyID == other.KeyID
	}

	return false
}

// -------------------------- Helper Functions --------------------------

// NewAsymmetricKeyPair returns a new keypair for the type of the given algorithm
//
// bits is only used when generating RSA keys
func NewAsymmetricKeyPair(alg string, bits int) (*PrivKey, *PubKey, error) {
	var private PrivKey
	var public PubKey
	var err error

	switch authutils.KeyTypeFromAlg(alg) {
	case "RSA":
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, nil, fmt.Errorf("error generating RSA private key: %v", err)
		}
		private.Key = key
		public.Key = key.PublicKey
	case "EC":
		key, err := ecdsa.GenerateKey(authutils.EllipticCurveFromAlg(alg), rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("error generating EC private key: %v", err)
		}
		private.Key = key
		public.Key = key.PublicKey
	case "EdDSA":
		public.Key, private.Key, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("error generating EdDSA private key: %v", err)
		}
	default:
		return nil, nil, errors.New("unrecognized key type")
	}

	private.Alg = alg
	public.Alg = alg

	return &private, &public, nil
}

type privateKey interface {
	Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)
	Public() crypto.PublicKey
	Equal(x crypto.PrivateKey) bool
}

type publicKey interface {
	Equal(x crypto.PublicKey) bool
}
