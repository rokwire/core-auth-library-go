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
	"bytes"
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"github.com/rokwire/core-auth-library-go/v2/authservice"
	"github.com/rokwire/core-auth-library-go/v2/authutils"
	"github.com/rokwire/core-auth-library-go/v2/keys"
	"gopkg.in/go-playground/validator.v9"
)

const (
	// SHA256 represents a SHA256 hash
	SHA256 string = "SHA256"
	// SHA256Legacy represents a legacy SHA256 hash
	SHA256Legacy string = "SHA-256" // TODO: Remove once all dependents have been upgraded
)

// SignatureAuth contains configurations and helper functions required to validate signatures
type SignatureAuth struct {
	serviceRegManager *authservice.ServiceRegManager

	serviceKey    *keys.PrivKey
	servicePubKey *keys.PubKey

	supportLegacy bool // TODO: Remove once all dependents have been upgraded
}

// Sign generates and returns a signature for the provided message
func (s *SignatureAuth) Sign(message []byte) (string, error) {
	return s.serviceKey.Sign(message)
}

// CheckServiceSignature validates the provided message signature from the given service
func (s *SignatureAuth) CheckServiceSignature(serviceID string, message []byte, signature string) error {
	serviceReg, err := s.serviceRegManager.GetServiceRegWithPubKey(serviceID)
	if err != nil {
		return fmt.Errorf("failed to retrieve service pub key: %v", err)
	}

	return s.CheckSignature(serviceReg.PubKey, message, signature)
}

// CheckSignature validates the provided message signature from the given public key
func (s *SignatureAuth) CheckSignature(pubKey *keys.PubKey, message []byte, signature string) error {
	err := pubKey.Verify(message, signature)
	if err != nil && s.supportLegacy {
		return s.LegacyCheckSignature(pubKey, message, signature)
	}
	return err
}

// LegacyCheckSignature validates the provided message signature from the given public key
func (s *SignatureAuth) LegacyCheckSignature(pubKey *keys.PubKey, message []byte, signature string) error {
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

	key, ok := pubKey.Key.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("error casting pub key as rsa pub key: %v", err)
	}

	err = rsa.VerifyPSS(key, crypto.SHA256, hash, sigBytes, nil)
	if err != nil {
		return fmt.Errorf("error verifying signature: %v", err)
	}

	return nil
}

// SignRequest signs and modifies the provided request with the necessary signature parameters
func (s *SignatureAuth) SignRequest(r *http.Request) error {
	if r == nil {
		return errors.New("request is nil")
	}

	signedRequest, err := ParseHTTPRequest(r)
	if err != nil {
		return fmt.Errorf("error parsing http request: %v", err)
	}

	digest, length, err := GetRequestDigest(signedRequest.Body, SHA256)
	if err != nil {
		return fmt.Errorf("unable to build request digest: %v", err)
	}
	if digest != "" {
		r.Header.Set("Digest", digest)
	}

	r.Header.Set("Content-Length", strconv.Itoa(length))
	r.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))

	headers := []string{"request-line", "host", "date", "digest", "content-length"}

	if s.servicePubKey.KeyID == "" {
		err = s.servicePubKey.ComputeKeyFingerprint()
		if err != nil {
			return fmt.Errorf("error setting service key fingerprint: %v", err)
		}
	}

	sigAuthHeader := SignatureAuthHeader{KeyID: s.servicePubKey.KeyID, Algorithm: s.servicePubKey.Alg, Headers: headers}

	sigString, err := BuildSignatureString(signedRequest, headers)
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
//
//	The request must be signed by one of the services in requiredServiceIDs. If nil, any valid signature
//	from a subscribed service will be accepted
//	Returns the service ID of the signing service
func (s *SignatureAuth) CheckRequestServiceSignature(r *Request, requiredServiceIDs []string) (string, error) {
	if r == nil {
		return "", errors.New("request is nil")
	}

	sigString, sigAuthHeader, err := s.ParseRequestSignature(r)
	if err != nil {
		return "", err
	}

	if requiredServiceIDs == nil {
		requiredServiceIDs = s.serviceRegManager.SubscribedServices()
	}

	var serviceReg *authservice.ServiceReg
	found := false
	for _, serviceID := range requiredServiceIDs {
		serviceReg, err = s.serviceRegManager.GetServiceRegWithPubKey(serviceID)
		if err != nil {
			return "", fmt.Errorf("failed to retrieve service registration: %v", err)
		}

		if serviceReg.PubKey.KeyID == sigAuthHeader.KeyID {
			found = true
			break
		}
	}

	if !found {
		return "", fmt.Errorf("request signer fingerprint (%s) does not match any of the required services %v", sigAuthHeader.KeyID, requiredServiceIDs)
	}

	err = s.CheckSignature(serviceReg.PubKey, []byte(sigString), sigAuthHeader.Signature)
	if err != nil {
		return "", fmt.Errorf("error validating signature: %v", err)
	}

	return serviceReg.ServiceID, nil
}

// CheckRequestSignature validates the signature on the provided request
//
// The request must be signed by the private key paired with the provided public key
func (s *SignatureAuth) CheckRequestSignature(r *Request, key *keys.PubKey) error {
	if r == nil {
		return errors.New("request is nil")
	}

	sigString, sigAuthHeader, err := s.ParseRequestSignature(r)
	if err != nil {
		return err
	}

	return s.CheckParsedRequestSignature(sigString, sigAuthHeader, key)
}

// CheckParsedRequestSignature validates the signature on the provided parsed elements of a signed request
//
// The request must be signed by the private key paired with the provided public key
func (s *SignatureAuth) CheckParsedRequestSignature(sigString string, sigAuthHeader *SignatureAuthHeader, key *keys.PubKey) error {
	if sigAuthHeader == nil {
		return errors.New("signature auth header is nil")
	}

	if key == nil {
		return errors.New("pubkey is nil")
	}

	if sigAuthHeader.Algorithm != key.Alg && (!s.supportLegacy || sigAuthHeader.Algorithm != "rsa-sha256") {
		return fmt.Errorf("signing algorithm (%s) does not match %s", sigAuthHeader.Algorithm, s.servicePubKey.Alg)
	}

	err := s.CheckSignature(key, []byte(sigString), sigAuthHeader.Signature)
	if err != nil {
		return fmt.Errorf("error validating signature: %v", err)
	}

	return nil
}

// ParseRequestSignature checks the request's digest and returns its signature string and parsed header
func (s *SignatureAuth) ParseRequestSignature(r *Request) (string, *SignatureAuthHeader, error) {
	if r == nil {
		return "", nil, errors.New("request is nil")
	}

	authHeader := r.GetHeader("Authorization")
	if authHeader == "" {
		return "", nil, errors.New("request missing authorization header")
	}

	if len(r.Body) > 0 {
		digestHeader := r.GetHeader("Digest")
		digestHeaderParts := strings.SplitN(digestHeader, "=", 2)
		if len(digestHeaderParts) != 2 {
			return "", nil, errors.New("invalid request digest header")
		}

		digest, _, err := GetRequestDigest(r.Body, digestHeaderParts[0])
		if err != nil {
			return "", nil, fmt.Errorf("unable to build request digest: %v", err)
		}
		digestParts := strings.SplitN(digest, "=", 2)
		if len(digestParts) != 2 {
			return "", nil, errors.New("invalid request digest")
		}

		if digestParts[1] != digestHeaderParts[1] {
			return "", nil, errors.New("message digest does not match digest header")
		}
	}

	sigAuthHeader, err := ParseSignatureAuthHeader(authHeader)
	if err != nil {
		return "", nil, fmt.Errorf("error parsing signature authorization header: %v", err)
	}

	sigString, err := BuildSignatureString(r, sigAuthHeader.Headers)
	if err != nil {
		return "", nil, fmt.Errorf("error building signature string: %v", err)
	}

	return sigString, sigAuthHeader, nil
}

// Implement ServiceAuthRequests interface

// BuildRequestAuthBody returns a map containing the auth fields for static token auth request bodies
func (s *SignatureAuth) BuildRequestAuthBody() map[string]interface{} {
	return map[string]interface{}{
		"auth_type": "signature",
	}
}

// ModifyRequest signs the passed request to perform signature auth
func (s *SignatureAuth) ModifyRequest(req *http.Request) error {
	err := s.SignRequest(req)
	if err != nil {
		return fmt.Errorf("error signing request: %v", err)
	}
	return nil
}

// NewSignatureAuth creates and configures a new SignatureAuth instance
func NewSignatureAuth(serviceKey *keys.PrivKey, serviceRegManager *authservice.ServiceRegManager, serviceRegKey bool, supportLegacy bool) (*SignatureAuth, error) {
	if serviceKey == nil {
		return nil, errors.New("service key is missing")
	}
	if serviceRegManager == nil {
		return nil, errors.New("service registration manager is missing")
	}

	if serviceRegKey {
		err := serviceRegManager.ValidateServiceRegistrationKey(serviceKey)
		if err != nil {
			return nil, fmt.Errorf("unable to validate service key registration: please contact the auth service system admin to register a public key for your service - %v", err)
		}
	}

	if serviceKey.PubKey == nil {
		err := serviceKey.ComputePubKey()
		if err != nil {
			return nil, fmt.Errorf("error getting pubkey for service key: %v", err)
		}
	}

	return &SignatureAuth{serviceKey: serviceKey, servicePubKey: serviceKey.PubKey, serviceRegManager: serviceRegManager, supportLegacy: supportLegacy}, nil
}

// BuildSignatureString builds the string to be signed for the provided request
//
//	"headers" specify which headers to include in the signature string
func BuildSignatureString(r *Request, headers []string) (string, error) {
	sigString := ""
	for _, header := range headers {
		if sigString != "" {
			sigString += "\n"
		}

		val := ""
		if header == "request-line" {
			val = GetRequestLine(r)
		} else if header == "host" { // Go removes the "Host" header and moves it the request Host field
			val = header + ": " + r.Host
		} else {
			val = header + ": " + r.GetHeader(header)
		}

		if val == "" {
			return "", fmt.Errorf("missing or empty header: %s", header)
		}

		sigString += val
	}

	return sigString, nil
}

// GetRequestLine returns the request line for the provided request
func GetRequestLine(r *Request) string {
	if r == nil {
		return ""
	}

	return fmt.Sprintf("%s %s %s", r.Method, r.Path, r.Protocol)
}

// GetRequestDigest returns the digest and length of the provided request body using the specified algorithm
func GetRequestDigest(body []byte, alg string) (string, int, error) {
	if len(body) == 0 {
		return "", 0, nil
	}

	var hash []byte
	var err error
	switch alg {
	case SHA256, SHA256Legacy:
		hash, err = authutils.HashSha256(body)
		if err != nil {
			return "", 0, fmt.Errorf("error hashing request body: %v", err)
		}
	default:
		return "", 0, fmt.Errorf("unsupported digest alg: %s", alg)
	}

	return fmt.Sprintf("%s=%s", alg, base64.StdEncoding.EncodeToString(hash)), len(body), nil
}

// -------------------- Request --------------------

// Request defines the components of a signed request required for signature authentication
type Request struct {
	Headers map[string][]string
	Body    []byte

	Host     string
	Method   string
	Path     string
	Protocol string
}

// GetHeader gets the request header for a given key
func (s Request) GetHeader(key string) string {
	return textproto.MIMEHeader(s.Headers).Get(key)
}

// ParseHTTPRequest parses a http.Request into a Request
func ParseHTTPRequest(r *http.Request) (*Request, error) {
	if r == nil {
		return nil, nil
	}

	var body []byte
	var err error
	if r.Body != nil {
		body, err = io.ReadAll(r.Body)
		if err != nil {
			return nil, fmt.Errorf("error reading request body: %v", err)
		}
		r.Body.Close()

		r.Body = io.NopCloser(bytes.NewReader(body))
	}

	return &Request{Headers: r.Header, Body: body, Host: r.Host, Method: r.Method, Path: r.URL.Path, Protocol: r.Proto}, nil
}

// -------------------- SignatureAuthHeader --------------------

// SignatureAuthHeader defines the structure of the Authorization header for signature authentication
type SignatureAuthHeader struct {
	KeyID      string   `json:"keyId" validate:"required"`
	Algorithm  string   `json:"algorithm" validate:"required"`
	Headers    []string `json:"headers,omitempty"`
	Extensions string   `json:"extensions,omitempty"`
	Signature  string   `json:"signature" validate:"required"`
}

// SetField sets the provided field to the provided value
func (s *SignatureAuthHeader) SetField(field string, value string) error {
	switch field {
	case "keyId":
		s.KeyID = value
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

	return fmt.Sprintf("Signature keyId=\"%s\",algorithm=\"%s\",%s%ssignature=\"%s\"", s.KeyID, s.Algorithm, headers, extensions, s.Signature), nil
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
			return nil, errors.New("invalid format for signature header param")
		}

		key := parts[0]
		val := strings.ReplaceAll(parts[1], "\"", "")

		err := sigHeader.SetField(key, val)
		if err != nil {
			return nil, fmt.Errorf("unable to decode signature header param: %v", err)
		}
	}

	return &sigHeader, nil
}
