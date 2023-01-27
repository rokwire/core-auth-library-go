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

	"github.com/golang-jwt/jwt"
	"github.com/rokwire/core-auth-library-go/v2/authutils"
)

const (
	// RSA represents the RSA keypair type
	RSA string = "RS256"
	// ECDSA represents the Elliptic Curve keypair type
	ECDSA string = "ECDSA256"
	// EDDSA represents the Edwards Curve keypair type
	EDDSA string = "EDDSA"
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
	switch p.Alg {
	case RSA:
		p.Key, err = jwt.ParseRSAPrivateKeyFromPEM([]byte(p.KeyPem))
	case ECDSA:
		p.Key, err = jwt.ParseECPrivateKeyFromPEM([]byte(p.KeyPem))
	case EDDSA:
		p.Key, err = jwt.ParseEdPrivateKeyFromPEM([]byte(p.KeyPem))
	default:
		return errors.New("unsupported algorithm")
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

	privASN1, err := x509.MarshalPKCS8PrivateKey(p.Key)
	if err != nil {
		return fmt.Errorf("error marshalling private key: %v", err)
	}

	p.KeyPem = string(pem.EncodeToMemory(
		&pem.Block{
			Type:  fmt.Sprintf("%s PRIVATE KEY", p.Alg),
			Bytes: privASN1,
		},
	))

	return nil
}

// Decrypt decrypts data using "Key"
func (p *PrivKey) Decrypt(data []byte) (string, error) {
	if p == nil {
		return "", fmt.Errorf("privkey is nil")
	}

	switch p.Alg {
	case RSA:
		key, ok := p.Key.(*rsa.PrivateKey)
		if !ok {
			return "", errors.New("key type does not match algorithm")
		}
		cipherText, err := rsa.DecryptPKCS1v15(rand.Reader, key, data)
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

	var signature []byte
	var err error
	switch p.Alg {
	case RSA:
		message, err = authutils.HashSha256(message)
		if err != nil {
			return "", fmt.Errorf("error hashing message: %v", err)
		}
		key, ok := p.Key.(*rsa.PrivateKey)
		if !ok {
			return "", errors.New("key type does not match algorithm")
		}
		signature, err = key.Sign(rand.Reader, message, &rsa.PSSOptions{Hash: crypto.SHA256})
	case ECDSA:
		message, err = authutils.HashSha256(message)
		if err != nil {
			return "", fmt.Errorf("error hashing message: %v", err)
		}
		key, ok := p.Key.(*ecdsa.PrivateKey)
		if !ok {
			return "", errors.New("key type does not match algorithm")
		}
		signature, err = key.Sign(rand.Reader, message, &rsa.PSSOptions{Hash: crypto.SHA256})
	case EDDSA:
		// edwards curve does not handle hashed messages
		key, ok := p.Key.(ed25519.PrivateKey)
		if !ok {
			return "", errors.New("key type does not match algorithm")
		}
		signature, err = key.Sign(rand.Reader, message, &rsa.PSSOptions{Hash: 0})
	default:
		err = errors.New("unsupported algorithm")
	}
	if err != nil {
		return "", fmt.Errorf("error signing message: %v", err)
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

// PubKey returns the public key representation corresponding to the private key
func (p *PrivKey) PubKey() (*PubKey, error) {
	if p == nil {
		return nil, fmt.Errorf("privkey is nil")
	}

	public := PubKey{Alg: p.Alg}
	switch p.Alg {
	case RSA:
		key, ok := p.Key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("key type does not match algorithm")
		}
		public.Key = key.PublicKey
	case ECDSA:
		key, ok := p.Key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("key type does not match algorithm")
		}
		public.Key = key.PublicKey
	case EDDSA:
		// edwards curve does not handle hashed messages
		key, ok := p.Key.(ed25519.PrivateKey)
		if !ok {
			return nil, errors.New("key type does not match algorithm")
		}
		public.Key = key.Public()
	}

	err := public.Encode()
	if err != nil {
		return nil, fmt.Errorf("error encoding public key in PEM form: %v", err)
	}
	public.SetKeyFingerprint()
	if err != nil {
		return nil, fmt.Errorf("error setting public key fingerprint: %v", err)
	}

	return &public, nil
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
	switch p.Alg {
	case RSA:
		p.Key, err = jwt.ParseRSAPublicKeyFromPEM([]byte(p.KeyPem))
	case ECDSA:
		p.Key, err = jwt.ParseECPublicKeyFromPEM([]byte(p.KeyPem))
	case EDDSA:
		p.Key, err = jwt.ParseEdPublicKeyFromPEM([]byte(p.KeyPem))
	default:
		return errors.New("unsupported algorithm")
	}
	if err != nil {
		return fmt.Errorf("error parsing key string: %v", err)
	}

	err = p.SetKeyFingerprint()
	if err != nil {
		return fmt.Errorf("error getting key fingerprint: %v", err)
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
			Type:  fmt.Sprintf("%s PUBLIC KEY", p.Alg),
			Bytes: pubASN1,
		},
	))

	return nil
}

// Encrypt uses "Key" to encrypt data
func (p *PubKey) Encrypt(data []byte) (string, error) {
	if p == nil {
		return "", fmt.Errorf("pubkey is nil")
	}

	switch p.Alg {
	case RSA:
		key, ok := p.Key.(*rsa.PublicKey)
		if !ok {
			return "", errors.New("key type does not match algorithm")
		}
		cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, key, data)
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

	var err error
	valid := true
	switch p.Alg {
	case RSA:
		message, err = authutils.HashSha256(message)
		if err != nil {
			return fmt.Errorf("error hashing message: %v", err)
		}
		key, ok := p.Key.(*rsa.PublicKey)
		if !ok {
			return errors.New("key type does not match algorithm")
		}
		err = rsa.VerifyPSS(key, crypto.SHA256, message, signature, nil)
	case ECDSA:
		message, err = authutils.HashSha256(message)
		if err != nil {
			return fmt.Errorf("error hashing message: %v", err)
		}
		key, ok := p.Key.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("key type does not match algorithm")
		}
		valid = ecdsa.VerifyASN1(key, message, signature)
	case EDDSA:
		// edwards curve does not handle hashed messages
		key, ok := p.Key.(ed25519.PublicKey)
		if !ok {
			return errors.New("key type does not match algorithm")
		}
		valid = ed25519.Verify(key, message, signature)
	default:
		valid = false
	}

	if err != nil {
		return fmt.Errorf("error verifying signature: %v", err)
	}
	if !valid {
		return fmt.Errorf("invalid signature")
	}

	return nil
}

// SetKeyFingerprint sets the "KeyID"
func (p *PubKey) SetKeyFingerprint() error {
	if p == nil {
		return fmt.Errorf("pubkey is nil")
	}

	pubASN1, err := x509.MarshalPKIXPublicKey(p.Key)
	if err != nil {
		return fmt.Errorf("error marshalling public key: %v", err)
	}

	hash, err := authutils.HashSha256(pubASN1)
	if err != nil {
		return fmt.Errorf("error hashing key: %v", err)
	}

	p.KeyID = "SHA256:" + base64.StdEncoding.EncodeToString(hash)
	return nil
}

// NewAsymmetricKeyPair returns a new keypair of the given keyType
//
//	param expected type:
//	RSA: int (number of bits)
//	ECDSA: elliptic.Curve
func NewAsymmetricKeyPair(algorithm string, param interface{}) (*PrivKey, *PubKey, error) {
	var private PrivKey
	var public PubKey
	var err error

	switch algorithm {
	case RSA:
		bits, ok := param.(int)
		if !ok {
			return nil, nil, errors.New("param has invalid type: expected int")
		}

		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, nil, fmt.Errorf("error generating rsa private key: %v", err)
		}
		private.Key = key
		public.Key = key.PublicKey
	case ECDSA:
		curve, ok := param.(elliptic.Curve)
		if !ok {
			return nil, nil, errors.New("param has invalid type: expected elliptic.Curve")
		}
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("error generating ecdsa private key: %v", err)
		}
		private.Key = key
		public.Key = key.PublicKey
	case EDDSA:
		public.Key, private.Key, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("error generating eddsa private key: %v", err)
		}
	default:
		return nil, nil, errors.New("unrecognized key type")
	}

	private.Alg = algorithm
	public.Alg = algorithm

	return &private, &public, nil
}
