// Copyright 2021 Board of Trustees of the University of Illinois.
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

package authutils

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
)

const (
	//AllApps indicates that all apps may be accessed
	AllApps string = "all"
	//AllOrgs indicates that all orgs may be accessed
	AllOrgs string = "all"
	// RSA represents the RSA keypair type
	RSA string = "RSA"
	// ECDSA represents the Elliptic Curve keypair type
	ECDSA string = "ECDSA"
	// EDDSA represents the Edwards Curve keypair type
	EDDSA string = "EDDSA"
)

// ContainsString returns true if the provided value is in the provided slice
func ContainsString(slice []string, val string) bool {
	for _, v := range slice {
		if val == v {
			return true
		}
	}
	return false
}

// RemoveString removes the provided value from the provided slice
//
//	Returns modified slice. If val is not found returns unmodified slice
func RemoveString(slice []string, val string) ([]string, bool) {
	for i, other := range slice {
		if other == val {
			return append(slice[:i], slice[i+1:]...), true
		}
	}
	return slice, false
}

// GetPrivKeyPem encodes returns the PEM encoding for a private key
func GetPrivKeyPem(key PrivateKey) (string, error) {
	if key == nil {
		return "", fmt.Errorf("private key is nil")
	}

	var keyType string
	switch key.(type) {
	case *rsa.PrivateKey:
		keyType = RSA
	case *ecdsa.PrivateKey:
		keyType = ECDSA
	case ed25519.PrivateKey:
		keyType = EDDSA
	default:
		return "", errors.New("unrecognized private key type")
	}

	privASN1, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("error marshalling private key: %v", err)
	}

	pemData := pem.EncodeToMemory(
		&pem.Block{
			Type:  fmt.Sprintf("%s PRIVATE KEY", keyType),
			Bytes: privASN1,
		},
	)

	return string(pemData), nil
}

// GetPubKeyPem returns the PEM encoding for a public key
func GetPubKeyPem(key PublicKey) (string, error) {
	if key == nil {
		return "", fmt.Errorf("public key is nil")
	}

	var keyType string
	switch key.(type) {
	case *rsa.PublicKey:
		keyType = RSA
	case *ecdsa.PublicKey:
		keyType = ECDSA
	case ed25519.PublicKey:
		keyType = EDDSA
	default:
		return "", errors.New("unrecognized public key type")
	}

	pubASN1, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", fmt.Errorf("error marshalling public key: %v", err)
	}

	pemData := pem.EncodeToMemory(
		&pem.Block{
			Type:  fmt.Sprintf("%s PUBLIC KEY", keyType),
			Bytes: pubASN1,
		},
	)

	return string(pemData), nil
}

// GetKeyFingerprint returns the fingerprint for key
func GetKeyFingerprint(key PublicKey) (string, error) {
	if key == nil {
		return "", fmt.Errorf("public key is nil")
	}

	pubASN1, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", fmt.Errorf("error marshalling public key: %v", err)
	}

	hash, err := HashSha256(pubASN1)
	if err != nil {
		return "", fmt.Errorf("error hashing key: %v", err)
	}

	return "SHA256:" + base64.StdEncoding.EncodeToString(hash), nil
}

// HashSha256 returns the SHA256 hash of the input
func HashSha256(data []byte) ([]byte, error) {
	if data == nil {
		return nil, fmt.Errorf("cannot hash nil data")
	}

	hasher := sha256.New()
	_, err := hasher.Write(data)
	if err != nil {
		return nil, fmt.Errorf("error writing data: %v", err)
	}
	return hasher.Sum(nil), nil
}

// ReadResponseBody reads the body of a http.Response and returns it
func ReadResponseBody(resp *http.Response) ([]byte, error) {
	if resp == nil {
		return nil, errors.New("response is nil")
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	if resp.StatusCode != 200 {
		return body, fmt.Errorf("%s - %s", resp.Status, string(body))
	}

	return body, nil
}

// NewAsymmetricKeyPair returns a new keypair of the given keyType
//
//	param expected type:
//	authservice.RSA: int (number of bits)
//	authservice.ECDSA: elliptic.Curve
func NewAsymmetricKeyPair(keyType string, param interface{}) (PrivateKey, PublicKey, error) {
	var private PrivateKey
	var public PublicKey
	var err error

	switch keyType {
	case RSA:
		bits, ok := param.(int)
		if !ok {
			return nil, nil, errors.New("param has invalid type: expected int")
		}

		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, nil, fmt.Errorf("error generating rsa private key: %v", err)
		}
		private = key
		public = &key.PublicKey
	case ECDSA:
		curve, ok := param.(elliptic.Curve)
		if !ok {
			return nil, nil, errors.New("param has invalid type: expected elliptic.Curve")
		}
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("error generating ecdsa private key: %v", err)
		}
		private = key
		public = &key.PublicKey
	case EDDSA:
		public, private, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("error generating eddsa private key: %v", err)
		}
	default:
		return nil, nil, errors.New("unrecognized key type")
	}

	return private, public, nil
}

// PrivateKey represents a set of functions implemented by common private key types
type PrivateKey interface {
	Public() crypto.PublicKey
	Equal(x crypto.PrivateKey) bool
	Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error)
}

// PublicKey represents a set of functions implemented by common public key types
type PublicKey interface {
	Equal(x crypto.PublicKey) bool
}

// GenerateRandomBytes returns securely generated random bytes
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// GenerateRandomString returns a URL-safe, base64 encoded securely generated random string
func GenerateRandomString(s int) (string, error) {
	b, err := GenerateRandomBytes(s)
	return base64.RawURLEncoding.EncodeToString(b), err
}
