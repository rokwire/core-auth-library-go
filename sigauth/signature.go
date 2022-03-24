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

package sigauth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/rokwire/core-auth-library-go/authservice"
	"github.com/rokwire/core-auth-library-go/authutils"
	"gopkg.in/go-playground/validator.v9"
)

// SignatureAuth contains configurations and helper functions required to validate signatures
type SignatureAuth struct {
	authService *authservice.AuthService

	serviceAccountID string
	serviceKey       *rsa.PrivateKey
}

// BuildAccessTokenRequest builds a signed request to get an access token from an auth service
func (s *SignatureAuth) BuildAccessTokenRequest(host string, path string) (*http.Request, error) {
	params := map[string]interface{}{
		"auth_type": "signature",
		"creds": map[string]string{
			"id": s.serviceAccountID,
		},
	}
	data, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("error marshaling body for get access token: %v", err)
	}

	r, err := http.NewRequest(http.MethodPost, host+path, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("error creating request for get access token: %v", err)
	}

	r.Header.Set("Content-Type", "application/json")

	err = s.SignRequest(r, data)
	if err != nil {
		return nil, fmt.Errorf("error signing request for get access token: %v", err)
	}

	return r, nil
}

// Sign generates and returns a signature for the provided message
func (s *SignatureAuth) Sign(message []byte) (string, error) {
	hash, err := authutils.HashSha256(message)
	if err != nil {
		return "", fmt.Errorf("error hashing message: %v", err)
	}

	signature, err := rsa.SignPSS(rand.Reader, s.serviceKey, crypto.SHA256, hash, nil)
	if err != nil {
		return "", fmt.Errorf("error signing message: %v", err)
	}

	sigB64 := base64.StdEncoding.EncodeToString(signature)

	return sigB64, nil
}

// CheckServiceSignature validates the provided message signature from the given service
func (s *SignatureAuth) CheckServiceSignature(serviceID string, message []byte, signature string) error {
	serviceReg, err := s.authService.GetServiceRegWithPubKey(serviceID)
	if err != nil {
		return fmt.Errorf("failed to retrieve service pub key: %v", err)
	}

	return s.CheckSignature(serviceReg.PubKey.Key, message, signature)
}

// CheckSignature validates the provided message signature from the given public key
func (s *SignatureAuth) CheckSignature(pubKey *rsa.PublicKey, message []byte, signature string) error {
	if pubKey == nil {
		return errors.New("public key is nil")
	}

	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("error decoding signature: %v", err)
	}

	hash, err := authutils.HashSha256(message)
	if err != nil {
		return fmt.Errorf("error hashing message: %v", err)
	}

	err = rsa.VerifyPSS(pubKey, crypto.SHA256, hash, sigBytes, nil)
	if err != nil {
		return fmt.Errorf("error verifying signature: %v", err)
	}

	return nil
}

// SignRequest signs and modifies the provided request with the necessary signature parameters
func (s *SignatureAuth) SignRequest(r *http.Request, body []byte) error {
	if r == nil {
		return errors.New("request is nil")
	}

	digest, length, err := GetRequestDigest(body)
	if err != nil {
		return fmt.Errorf("unable to build request digest: %v", err)
	}
	if digest != "" {
		r.Header.Set("Digest", digest)
	}

	r.Header.Set("Content-Length", strconv.Itoa(length))

	headers := []string{"request-line", "host", "date", "digest", "content-length"}

	sigAuthHeader := SignatureAuthHeader{KeyId: s.authService.GetServiceID(), Algorithm: "rsa-sha256", Headers: headers}

	sigString, err := BuildSignatureString(r, headers)
	if err != nil {
		return fmt.Errorf("error building signature string: %v", err)
	}

	sig, err := s.Sign([]byte(sigString))
	if err != nil {
		return fmt.Errorf("error signing signature string: %v", err)
	}

	sigAuthHeader.Signature = sig

	authHeader, err := sigAuthHeader.Build()
	if err != nil {
		return fmt.Errorf("error building authorization header: %v", err)
	}

	r.Header.Set("Authorization", authHeader)

	return nil
}

// CheckRequestServiceSignature validates the signature on the provided request
// 	The request must be signed by one of the services in requiredServiceIDs. If nil, any valid signature
//	from a subscribed service will be accepted
// 	Returns the service ID of the signing service
func (s *SignatureAuth) CheckRequestServiceSignature(r *http.Request, body []byte, requiredServiceIDs []string) (string, error) {
	if r == nil {
		return "", errors.New("request is nil")
	}

	sigString, sigAuthHeader, err := s.checkRequest(r, body)
	if err != nil {
		return "", err
	}

	if requiredServiceIDs != nil && !authutils.ContainsString(requiredServiceIDs, sigAuthHeader.KeyId) {
		return "", fmt.Errorf("request signer (%s) is not one of the required services %v", sigAuthHeader.KeyId, requiredServiceIDs)
	}

	err = s.CheckServiceSignature(sigAuthHeader.KeyId, []byte(sigString), sigAuthHeader.Signature)
	if err != nil {
		return "", fmt.Errorf("error validating signature: %v", err)
	}

	return sigAuthHeader.KeyId, nil
}

// CheckRequestSignature validates the signature on the provided request
// 	The request must be signed by the private key paired with the provided public key
func (s *SignatureAuth) CheckRequestSignature(r *http.Request, body []byte, pubKey *rsa.PublicKey) error {
	if r == nil {
		return errors.New("request is nil")
	}

	if pubKey == nil {
		return errors.New("public key is nil")
	}

	sigString, sigAuthHeader, err := s.checkRequest(r, body)
	if err != nil {
		return err
	}

	err = s.CheckSignature(pubKey, []byte(sigString), sigAuthHeader.Signature)
	if err != nil {
		return fmt.Errorf("error validating signature: %v", err)
	}

	return nil
}

func (s *SignatureAuth) checkRequest(r *http.Request, body []byte) (string, *SignatureAuthHeader, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", nil, errors.New("request missing authorization header")
	}

	digestHeader := r.Header.Get("Digest")

	digest, _, err := GetRequestDigest(body)
	if err != nil {
		return "", nil, fmt.Errorf("unable to build request digest: %v", err)
	}

	if digest != digestHeader {
		return "", nil, errors.New("message digest does not match digest header")
	}

	sigAuthHeader, err := ParseSignatureAuthHeader(authHeader)
	if err != nil {
		return "", nil, fmt.Errorf("error parsing signature authorization header: %v", err)
	}

	if sigAuthHeader.Algorithm != "rsa-sha256" {
		return "", nil, fmt.Errorf("signing algorithm (%s) does not match rsa-sha256", sigAuthHeader.Algorithm)
	}

	sigString, err := BuildSignatureString(r, sigAuthHeader.Headers)
	if err != nil {
		return "", nil, fmt.Errorf("error building signature string: %v", err)
	}

	return sigString, sigAuthHeader, nil
}

// NewSignatureAuth creates and configures a new SignatureAuth instance
func NewSignatureAuth(serviceKey *rsa.PrivateKey, authService *authservice.AuthService, serviceRegKey bool) (*SignatureAuth, error) {
	if serviceRegKey {
		err := authService.ValidateServiceRegistrationKey(serviceKey)
		if err != nil {
			return nil, fmt.Errorf("unable to validate service key registration: please contact the auth service system admin to register a public key for your service - %v", err)
		}
	}

	return &SignatureAuth{serviceKey: serviceKey, authService: authService}, nil
}

// BuildSignatureString builds the string to be signed for the provided request
// 	"headers" specify which headers to include in the signature string
func BuildSignatureString(r *http.Request, headers []string) (string, error) {
	sigString := ""
	for _, header := range headers {
		if sigString != "" {
			sigString += "\n"
		}

		val := ""
		if header == "request-line" {
			val = GetRequestLine(r)
		} else {
			val = header + ": " + r.Header.Get(header)
		}

		if val == "" {
			return "", fmt.Errorf("missing or empty header: %s", header)
		}

		sigString += val
	}

	return sigString, nil
}

// GetRequestLine returns the request line for the provided request
func GetRequestLine(r *http.Request) string {
	if r == nil {
		return ""
	}

	return fmt.Sprintf("%s %s %s", r.Method, r.URL.Path, r.Proto)
}

// GetRequestDigest returns the SHA256 digest and length of the provided request body
func GetRequestDigest(body []byte) (string, int, error) {
	if len(body) == 0 {
		return "", 0, nil
	}

	hash, err := authutils.HashSha256(body)
	if err != nil {
		return "", 0, fmt.Errorf("error hashing request body: %v", err)
	}

	return "SHA-256=" + base64.StdEncoding.EncodeToString(hash), len(body), nil
}

// -------------------- SignatureAuthHeader --------------------

//SignatureAuthHeader defines the structure of the Authorization header for signature authentication
type SignatureAuthHeader struct {
	KeyId      string   `json:"keyId" validate:"required"`
	Algorithm  string   `json:"algorithm" validate:"required"`
	Headers    []string `json:"headers,omitempty"`
	Extensions string   `json:"extensions,omitempty"`
	Signature  string   `json:"signature" validate:"required"`
}

// SetField sets the provided field to the provided value
func (s *SignatureAuthHeader) SetField(field string, value string) error {
	switch field {
	case "keyId":
		s.KeyId = value
	case "algorithm":
		s.Algorithm = value
	case "headers":
		s.Headers = strings.Split(value, " ")
	case "extensions":
		s.Extensions = value
	case "signature":
		s.Signature = value
	default:
		return fmt.Errorf("invalid field: %s", field)
	}

	return nil
}

// Build builds the signature Authorization header string
func (s *SignatureAuthHeader) Build() (string, error) {
	validate := validator.New()
	err := validate.Struct(s)
	if err != nil {
		return "", fmt.Errorf("error validating signature auth header: %v", err)
	}

	headers := ""
	if s.Headers != nil {
		headers = fmt.Sprintf("headers=\"%s\",", strings.Join(s.Headers, " "))
	}

	extensions := ""
	if s.Extensions != "" {
		extensions = fmt.Sprintf("extensions=\"%s\",", s.Extensions)
	}

	return fmt.Sprintf("Signature keyId=\"%s\",algorithm=\"%s\",%s%ssignature=\"%s\"", s.KeyId, s.Algorithm, headers, extensions, s.Signature), nil
}

// ParseSignatureAuthHeader parses a signature Authorization header string
func ParseSignatureAuthHeader(header string) (*SignatureAuthHeader, error) {
	if !strings.HasPrefix(header, "Signature ") {
		return nil, errors.New("invalid format: missing Signature prefix")
	}
	header = strings.TrimPrefix(header, "Signature ")

	sigHeader := SignatureAuthHeader{}

	for _, param := range strings.Split(header, ",") {
		parts := strings.SplitN(param, "=", 2)
		if len(parts[0]) == 0 || len(parts[1]) == 0 {
			return nil, fmt.Errorf("invalid format for param: %s", param)
		}

		key := parts[0]
		val := strings.ReplaceAll(parts[1], "\"", "")

		err := sigHeader.SetField(key, val)
		if err != nil {
			return nil, fmt.Errorf("unable to decode param: %v", err)
		}
	}

	return &sigHeader, nil
}
