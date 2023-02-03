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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	"github.com/golang-jwt/jwt"
	"github.com/rokwire/core-auth-library-go/v2/authutils"
)

const (
	// RS256 represents a RSA key with SHA-256 signing method
	RS256 string = "RS256"
	// RS384 represents a RSA key with SHA-384 signing method
	RS384 string = "RS384"
	// RS512 represents a RSA key with SHA-512 signing method
	RS512 string = "RS512"
	// PS256 represents a RSA-PSS key with SHA-256 signing method
	PS256 string = "PS256"
	// PS384 represents a RSA-PSS key with SHA-384 signing method
	PS384 string = "PS384"
	// PS512 represents a RSA-PSS key with SHA-512 signing method
	PS512 string = "PS512"
	// ES256 represents an Elliptic Curve with SHA-256 signing method
	ES256 string = "ES256"
	// ES384 represents an Elliptic Curve with SHA-384 signing method
	ES384 string = "ES384"
	// ES512 represents an Elliptic Curve with SHA-512 signing method
	ES512 string = "ES512"
	// EdDSA represents an Edwards Curve signing method
	EdDSA string = "EdDSA"

	// KeyTypeRSA represents the RSA key type
	KeyTypeRSA string = "RSA"
	// KeyTypeEC represents the EC key type
	KeyTypeEC string = "EC"
	// KeyTypeEdDSA represents the EdDSA key type
	KeyTypeEdDSA string = "EdDSA"

	errUnsupportedAlg   string = "unsupported algorithm"
	errMismatchedKeyAlg string = "key type does not match algorithm"
)

// -------------------- PrivKey --------------------

// PrivKey represents a private key object including the key and related metadata
type PrivKey struct {
	Key    interface{} `json:"-" bson:"-"`
	KeyPem string      `json:"key_pem" bson:"key_pem" validate:"required"`
	Alg    string      `json:"alg" bson:"alg" validate:"required"`
	PubKey *PubKey     `json:"-" bson:"-"`
}

// Decrypt decrypts data using "key"
func (p *PrivKey) Decrypt(data []byte, label []byte) (string, error) {
	if p == nil {
		return "", fmt.Errorf("privkey is nil")
	}

	switch keyTypeFromAlg(p.Alg) {
	case KeyTypeRSA:
		key, ok := p.Key.(*rsa.PrivateKey)
		if !ok {
			return "", errors.New(errMismatchedKeyAlg)
		}

		hash := hashFromAlg(p.Alg)
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

// Sign uses "key" to sign message
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

	return signature, nil
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

// Decode sets the "Key" by decoding "KeyPem"
func (p *PrivKey) Decode() error {
	if p == nil {
		return fmt.Errorf("privkey is nil")
	}

	var err error
	switch keyTypeFromAlg(p.Alg) {
	case KeyTypeRSA:
		p.Key, err = jwt.ParseRSAPrivateKeyFromPEM([]byte(p.KeyPem))
	case KeyTypeEC:
		p.Key, err = jwt.ParseECPrivateKeyFromPEM([]byte(p.KeyPem))
	case KeyTypeEdDSA:
		p.Key, err = jwt.ParseEdPrivateKeyFromPEM([]byte(p.KeyPem))
	default:
		return errors.New(errUnsupportedAlg)
	}
	if err != nil {
		return fmt.Errorf("error parsing key string: %v", err)
	}

	err = p.ComputePubKey()
	if err != nil {
		return fmt.Errorf("error computing pubkey: %v", err)
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
	switch keyTypeFromAlg(p.Alg) {
	case KeyTypeRSA:
		key, ok := p.Key.(*rsa.PrivateKey)
		if !ok {
			return errors.New(errMismatchedKeyAlg)
		}
		privASN1 = x509.MarshalPKCS1PrivateKey(key)
	case KeyTypeEC, KeyTypeEdDSA:
		privASN1, err = x509.MarshalPKCS8PrivateKey(p.Key)
		if err != nil {
			return fmt.Errorf("error marshalling private key: %v", err)
		}
	default:
		return errors.New(errUnsupportedAlg)
	}

	p.KeyPem = string(pem.EncodeToMemory(
		&pem.Block{
			Type:  fmt.Sprintf("%s PRIVATE KEY", keyTypeFromAlg(p.Alg)),
			Bytes: privASN1,
		},
	))

	err = p.ComputePubKey()
	if err != nil {
		return fmt.Errorf("error computing pubkey: %v", err)
	}

	return nil
}

// computePubKey computes and sets the public key representation corresponding to the private key
func (p *PrivKey) ComputePubKey() error {
	if p == nil {
		return fmt.Errorf("privkey is nil")
	}

	var key privateKey
	var ok bool
	public := PubKey{Alg: p.Alg}
	switch keyTypeFromAlg(p.Alg) {
	case KeyTypeRSA:
		key, ok = p.Key.(*rsa.PrivateKey)
	case KeyTypeEC:
		key, ok = p.Key.(*ecdsa.PrivateKey)
	case KeyTypeEdDSA:
		key, ok = p.Key.(ed25519.PrivateKey)
	default:
		return errors.New(errUnsupportedAlg)
	}
	if !ok {
		return errors.New(errMismatchedKeyAlg)
	}
	public.Key = key.Public()

	err := public.Encode()
	if err != nil {
		return fmt.Errorf("error encoding public key in PEM form: %v", err)
	}

	p.PubKey = &public
	return nil
}

// NewPubKey creates a new PubKey with the provided algorithm and PEM
func NewPrivKey(alg string, keyPEM string) (*PrivKey, error) {
	key := PrivKey{Alg: alg, KeyPem: keyPEM}
	err := key.Decode()
	if err != nil {
		return nil, err
	}
	return &key, nil
}

// -------------------- PubKey --------------------

// PubKey represents a public key object including the key and related metadata
type PubKey struct {
	Key    interface{} `json:"-" bson:"-"`
	KeyPem string      `json:"key_pem" bson:"key_pem" validate:"required"`
	Alg    string      `json:"alg" bson:"alg" validate:"required"`
	KeyID  string      `json:"-" bson:"-"`
}

// Encrypt uses "Key" to encrypt data
func (p *PubKey) Encrypt(data []byte, label []byte) ([]byte, error) {
	if p == nil {
		return nil, fmt.Errorf("pubkey is nil")
	}

	switch keyTypeFromAlg(p.Alg) {
	case KeyTypeRSA:
		key, ok := p.Key.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New(errMismatchedKeyAlg)
		}

		hash := hashFromAlg(p.Alg)
		if hash == 0 {
			return nil, fmt.Errorf("unsupported hashing method %s", p.Alg)
		}
		cipherText, err := rsa.EncryptOAEP(hash.New(), rand.Reader, key, data, label)
		if err != nil {
			return nil, fmt.Errorf("error encrypting data with RSA public key: %v", err)
		}
		return cipherText, nil
	}

	return nil, errors.New("encryption is unsupported for algorithm " + p.Alg)
}

// Verify verifies that signature matches message by using "Key"
func (p *PubKey) Verify(message []byte, signature string) error {
	if p == nil {
		return fmt.Errorf("pubkey is nil")
	}

	sigMethod := jwt.GetSigningMethod(p.Alg)
	if sigMethod == nil {
		return errors.New(errUnsupportedAlg)
	}
	err := sigMethod.Verify(string(message), signature, p.Key)
	if err != nil {
		return fmt.Errorf("error verifying signature: %v", err)
	}

	return nil
}

// Equal determines whether the pubkey is equivalent to other
func (p *PubKey) Equal(other *PubKey) bool {
	if p == nil || other == nil {
		return p == other
	}

	switch keyTypeFromAlg(p.Alg) {
	case KeyTypeRSA, KeyTypeEC, KeyTypeEdDSA:
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

// Decode sets the "Key" by decoding "KeyPem" and sets the "KeyID"
func (p *PubKey) Decode() error {
	if p == nil {
		return fmt.Errorf("pubkey is nil")
	}

	var err error
	switch keyTypeFromAlg(p.Alg) {
	case KeyTypeRSA:
		p.Key, err = jwt.ParseRSAPublicKeyFromPEM([]byte(p.KeyPem))
	case KeyTypeEC:
		p.Key, err = jwt.ParseECPublicKeyFromPEM([]byte(p.KeyPem))
	case KeyTypeEdDSA:
		p.Key, err = jwt.ParseEdPublicKeyFromPEM([]byte(p.KeyPem))
	default:
		return errors.New(errUnsupportedAlg)
	}
	if err != nil {
		return fmt.Errorf("error parsing key string: %v", err)
	}

	err = p.ComputeKeyFingerprint()
	if err != nil {
		return fmt.Errorf("error computing key fingerprint: %v", err)
	}

	return nil
}

// Encode sets the "KeyPem" by encoding "Key" in PEM form and sets the "KeyID"
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
			Type:  fmt.Sprintf("%s PUBLIC KEY", keyTypeFromAlg(p.Alg)),
			Bytes: pubASN1,
		},
	))

	err = p.ComputeKeyFingerprint()
	if err != nil {
		return fmt.Errorf("error computing key fingerprint: %v", err)
	}

	return nil
}

// ComputeKeyFingerprint computes and sets the "KeyID"
func (p *PubKey) ComputeKeyFingerprint() error {
	if p == nil {
		return fmt.Errorf("pubkey is nil")
	}

	var pubASN1 []byte
	var err error
	switch keyTypeFromAlg(p.Alg) {
	case KeyTypeRSA:
		rsaKey, ok := p.Key.(*rsa.PublicKey)
		if !ok {
			return errors.New(errMismatchedKeyAlg)
		}
		pubASN1 = x509.MarshalPKCS1PublicKey(rsaKey)
	case KeyTypeEC, KeyTypeEdDSA:
		pubASN1, err = x509.MarshalPKIXPublicKey(p.Key)
		if err != nil {
			return fmt.Errorf("error marshalling public key: %v", err)
		}
	default:
		return errors.New(errUnsupportedAlg)
	}

	hash, err := authutils.HashSha256(pubASN1)
	if err != nil {
		return fmt.Errorf("error hashing key: %v", err)
	}

	p.KeyID = fmt.Sprintf("SHA256:%s", base64.StdEncoding.EncodeToString(hash))
	return nil
}

// NewPubKey creates a new PubKey with the provided algorithm and PEM
func NewPubKey(alg string, keyPEM string) (*PubKey, error) {
	key := PubKey{Alg: alg, KeyPem: keyPEM}
	err := key.Decode()
	if err != nil {
		return nil, err
	}
	return &key, nil
}

// -------------------------- Helper Functions --------------------------

// NewAsymmetricKeyPair returns a new keypair for the type of the given algorithm
//
// bits is only used when generating RSA keys
func NewAsymmetricKeyPair(alg string, bits int) (*PrivKey, *PubKey, error) {
	private := PrivKey{Alg: alg}

	var err error

	switch keyTypeFromAlg(alg) {
	case KeyTypeRSA:
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, nil, fmt.Errorf("error generating RSA private key: %v", err)
		}
		private.Key = key
	case KeyTypeEC:
		key, err := ecdsa.GenerateKey(ellipticCurveFromAlg(alg), rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("error generating EC private key: %v", err)
		}
		private.Key = key
	case KeyTypeEdDSA:
		_, private.Key, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("error generating EdDSA private key: %v", err)
		}
	default:
		return nil, nil, errors.New("unrecognized key type")
	}

	err = private.Encode()
	if err != nil {
		return nil, nil, fmt.Errorf("error encoding priv key: %v", err)
	}

	return &private, private.PubKey, nil
}

// keyTypeFromAlg returns a string indicating the key type associated with Alg
func keyTypeFromAlg(alg string) string {
	switch alg {
	case RS256, RS384, RS512, PS256, PS384, PS512:
		return KeyTypeRSA
	case ES256, ES384, ES512:
		return KeyTypeEC
	case EdDSA:
		return KeyTypeEdDSA
	default:
		return ""
	}
}

// hashFromAlg returns a string indicating the hash function associated with alg
func hashFromAlg(alg string) crypto.Hash {
	switch alg {
	case RS256, PS256, ES256:
		return crypto.SHA256
	case RS384, PS384, ES384:
		return crypto.SHA384
	case RS512, PS512, ES512:
		return crypto.SHA512
	default:
		return 0
	}
}

// ellipticCurveFromAlg returns the elliptic curve associated with alg
func ellipticCurveFromAlg(alg string) elliptic.Curve {
	switch alg {
	case ES256:
		return elliptic.P256()
	case ES384:
		return elliptic.P384()
	case ES512:
		return elliptic.P521()
	default:
		return nil
	}
}

type privateKey interface {
	Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)
	Public() crypto.PublicKey
	Equal(x crypto.PrivateKey) bool
}

type publicKey interface {
	Equal(x crypto.PublicKey) bool
}
