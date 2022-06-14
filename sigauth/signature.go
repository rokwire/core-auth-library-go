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
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"github.com/rokwire/core-auth-library-go/v2/authservice"
	"github.com/rokwire/core-auth-library-go/v2/authutils"
	"gopkg.in/go-playground/validator.v9"
)

// SignatureAuth contains configurations and helper functions required to validate signatures
type SignatureAuth struct {
	serviceRegManager *authservice.ServiceRegManager

	serviceKey *rsa.PrivateKey
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
	serviceReg, err := s.serviceRegManager.GetServiceRegWithPubKey(serviceID)
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
func (s *SignatureAuth) SignRequest(r *http.Request) error {
	if r == nil {
		return errors.New("request is nil")
	}

	signedRequest, err := ParseHTTPRequest(r)
	if err != nil {
		return fmt.Errorf("error parsing http request: %v", err)
	}

	digest, length, err := GetRequestDigest(signedRequest.Body)
	if err != nil {
		return fmt.Errorf("unable to build request digest: %v", err)
	}
	if digest != "" {
		r.Header.Set("Digest", digest)
	}

	r.Header.Set("Content-Length", strconv.Itoa(length))
	r.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))

	headers := []string{"request-line", "host", "date", "digest", "content-length"}

	serviceKeyFingerprint, err := authutils.GetKeyFingerprint(&s.serviceKey.PublicKey)
	if err != nil {
		return fmt.Errorf("error getting service key fingerprint: %v", err)
	}
	sigAuthHeader := SignatureAuthHeader{KeyID: serviceKeyFingerprint, Algorithm: "rsa-sha256", Headers: headers}

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
// 	The request must be signed by one of the services in requiredServiceIDs. If nil, any valid signature
//	from a subscribed service will be accepted
// 	Returns the service ID of the signing service
func (s *SignatureAuth) CheckRequestServiceSignature(r *Request, requiredServiceIDs []string) (string, error) {
	if r == nil {
		return "", errors.New("request is nil")
	}

	sigString, sigAuthHeader, err := s.checkRequest(r)
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

	err = s.CheckSignature(serviceReg.PubKey.Key, []byte(sigString), sigAuthHeader.Signature)
	if err != nil {
		return "", fmt.Errorf("error validating signature: %v", err)
	}

	return serviceReg.ServiceID, nil
}

// CheckRequestSignature validates the signature on the provided request
// 	The request must be signed by the private key paired with the provided public key
func (s *SignatureAuth) CheckRequestSignature(r *Request, pubKey *rsa.PublicKey) error {
	if r == nil {
		return errors.New("request is nil")
	}

	if pubKey == nil {
		return errors.New("public key is nil")
	}

	sigString, sigAuthHeader, err := s.checkRequest(r)
	if err != nil {
		return err
	}

	err = s.CheckSignature(pubKey, []byte(sigString), sigAuthHeader.Signature)
	if err != nil {
		return fmt.Errorf("error validating signature: %v", err)
	}

	return nil
}

func (s *SignatureAuth) checkRequest(r *Request) (string, *SignatureAuthHeader, error) {
	authHeader := r.getHeader("Authorization")
	if authHeader == "" {
		return "", nil, errors.New("request missing authorization header")
	}

	digestHeader := r.getHeader("Digest")

	digest, _, err := GetRequestDigest(r.Body)
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
func NewSignatureAuth(serviceKey *rsa.PrivateKey, serviceRegManager *authservice.ServiceRegManager, serviceRegKey bool) (*SignatureAuth, error) {
	if serviceRegManager == nil {
		return nil, errors.New("service registration manager is missing")
	}

	if serviceRegKey {
		err := serviceRegManager.ValidateServiceRegistrationKey(serviceKey)
		if err != nil {
			return nil, fmt.Errorf("unable to validate service key registration: please contact the auth service system admin to register a public key for your service - %v", err)
		}
	}

	return &SignatureAuth{serviceKey: serviceKey, serviceRegManager: serviceRegManager}, nil
}

// BuildSignatureString builds the string to be signed for the provided request
// 	"headers" specify which headers to include in the signature string
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
			val = header + ": " + r.getHeader(header)
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

// -------------------- Request --------------------

//Request defines the components of a signed request required for signature authentication
type Request struct {
	Headers map[string][]string
	Body    []byte

	Host     string
	Method   string
	Path     string
	Protocol string
}

func (s Request) getHeader(key string) string {
	return textproto.MIMEHeader(s.Headers).Get(key)
}

//ParseHTTPRequest parses a http.Request into a Request
func ParseHTTPRequest(r *http.Request) (*Request, error) {
	if r == nil {
		return nil, nil
	}

	var body []byte
	var err error
	if r.Body != nil {
		body, err = ioutil.ReadAll(r.Body)
		if err != nil {
			return nil, fmt.Errorf("error reading request body: %v", err)
		}
		r.Body.Close()

		r.Body = ioutil.NopCloser(bytes.NewReader(body))
	}

	return &Request{Headers: r.Header, Body: body, Host: r.Host, Method: r.Method, Path: r.URL.Path, Protocol: r.Proto}, nil
}

// -------------------- SignatureAuthHeader --------------------

//SignatureAuthHeader defines the structure of the Authorization header for signature authentication
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
