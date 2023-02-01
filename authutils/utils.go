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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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

// GenerateRandomBytes returns securely generated random bytes
func GenerateRandomBytes(n int) ([]byte, error) {
	if n < 0 {
		return nil, errors.New("number of bytes cannot be negative")
	}

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

// KeyTypeFromAlg returns a string indicating the key type associated with alg
func KeyTypeFromAlg(alg string) string {
	switch alg {
	case RS256, RS384, RS512, PS256, PS384, PS512:
		return "RSA"
	case ES256, ES384, ES512:
		return "EC"
	case EdDSA:
		return "EdDSA"
	default:
		return ""
	}
}

// HashFromAlg returns a string indicating the hash function associated with alg
func HashFromAlg(alg string) crypto.Hash {
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

// EllipticCurveFromAlg returns the elliptic curve associated with alg
func EllipticCurveFromAlg(alg string) elliptic.Curve {
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
