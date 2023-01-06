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

package sigauth_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"testing"

	"github.com/rokwire/core-auth-library-go/v2/authservice"
	"github.com/rokwire/core-auth-library-go/v2/authservice/mocks"
	"github.com/rokwire/core-auth-library-go/v2/authutils"
	"github.com/rokwire/core-auth-library-go/v2/internal/testutils"
	"github.com/rokwire/core-auth-library-go/v2/sigauth"
)

func setupTestSignatureAuth(authService *authservice.AuthService, mockLoader *mocks.ServiceRegLoader) (*sigauth.SignatureAuth, error) {
	privKey := testutils.GetSamplePrivKey()
	manager, err := testutils.SetupTestServiceRegManager(authService, mockLoader)
	if err != nil {
		return nil, fmt.Errorf("error setting up test auth service: %v", err)
	}
	return sigauth.NewSignatureAuth(privKey.Key, manager, true)
}

func setupTestSignatureAuthWithPrivKey(authService *authservice.AuthService, mockLoader *mocks.ServiceRegLoader, key authutils.PrivateKey) (*sigauth.SignatureAuth, error) {
	if key == nil {
		return nil, errors.New("private key is nil")
	}

	manager, err := testutils.SetupTestServiceRegManager(authService, mockLoader)
	if err != nil {
		return nil, fmt.Errorf("error setting up test auth service: %v", err)
	}
	return sigauth.NewSignatureAuth(key, manager, true)
}

func TestSignatureAuth_CheckServiceSignature(t *testing.T) {
	authService := testutils.SetupTestAuthService("test", "https://test.rokwire.com")
	testServiceReg := authservice.ServiceReg{ServiceID: authService.ServiceID, Host: authService.ServiceHost, PubKey: testutils.GetSamplePubKey()}
	serviceRegsValid := []authservice.ServiceReg{testServiceReg}

	mockLoader := testutils.SetupMockServiceRegLoader(authService, nil, serviceRegsValid, nil)
	s, err := setupTestSignatureAuth(authService, mockLoader)
	if err != nil || s == nil {
		t.Errorf("Error initializing test signature auth: %v", err)
		return
	}

	type args struct {
		serviceID string
		message   []byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "success", args: args{serviceID: "test", message: []byte("test_message")}, wantErr: false},
		{name: "bad_service_id", args: args{serviceID: "auth", message: []byte("test_message")}, wantErr: true},
		{name: "empty_message", args: args{serviceID: "test", message: make([]byte, 0)}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signature, err := s.Sign(tt.args.message)
			if err != nil && !tt.wantErr {
				t.Errorf("SignatureAuth.Sign() error = %v", err)
				return
			}
			if err := s.CheckServiceSignature(tt.args.serviceID, tt.args.message, signature); (err != nil) != tt.wantErr {
				t.Errorf("SignatureAuth.CheckSignature() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSignatureAuth_CheckSignature(t *testing.T) {
	authService := testutils.SetupTestAuthService("test", "https://test.rokwire.com")
	testServiceReg := authservice.ServiceReg{ServiceID: authService.ServiceID, Host: authService.ServiceHost, PubKey: testutils.GetSamplePubKey()}
	serviceRegsValid := []authservice.ServiceReg{testServiceReg}

	mockLoader := testutils.SetupMockServiceRegLoader(authService, nil, serviceRegsValid, nil)

	privKey := testutils.GetSamplePrivKey()
	pubKey, ok := privKey.Key.Public().(authutils.PublicKey)
	if !ok {
		t.Errorf("Error asserting public key type")
	}

	type args struct {
		privKey authutils.PrivateKey
		pubKey  authutils.PublicKey
		message []byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "success", args: args{privKey: privKey.Key, pubKey: pubKey, message: []byte("test_message")}, wantErr: false},
		{name: "nil_pub_key", args: args{privKey: privKey.Key, pubKey: nil, message: []byte("test_message")}, wantErr: true},
		{name: "empty_message", args: args{privKey: privKey.Key, pubKey: pubKey, message: make([]byte, 0)}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := setupTestSignatureAuthWithPrivKey(authService, mockLoader, tt.args.privKey)
			if err != nil || s == nil {
				t.Errorf("Error initializing test signature auth: %v", err)
				return
			}
			signature, err := s.Sign(tt.args.message)
			if err != nil && !tt.wantErr {
				t.Errorf("SignatureAuth.Sign() error = %v", err)
				return
			}
			if err := s.CheckSignature(tt.args.pubKey, tt.args.message, signature); (err != nil) != tt.wantErr {
				t.Errorf("SignatureAuth.CheckSignature() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSignatureAuth_CheckRequestServiceSignature(t *testing.T) {
	authService := testutils.SetupTestAuthService("test", "https://test.rokwire.com")
	testServiceReg := authservice.ServiceReg{ServiceID: authService.ServiceID, Host: authService.ServiceHost, PubKey: testutils.GetSamplePubKey()}
	serviceRegsValid := []authservice.ServiceReg{testServiceReg}

	mockLoader := testutils.SetupMockServiceRegLoader(authService, nil, serviceRegsValid, nil)
	s, err := setupTestSignatureAuth(authService, mockLoader)
	if err != nil || s == nil {
		t.Errorf("Error initializing test signature auth: %v", err)
		return
	}

	var nilReq *http.Request

	params := map[string]interface{}{
		"data": "test_data",
	}
	data, _ := json.Marshal(params)

	testReq, _ := http.NewRequest(http.MethodGet, "http://test.rokwire.com/test", bytes.NewReader(data))
	testReq.Header.Set("Content-Type", "application/json; charset=UTF-8")
	testReq.Header.Set("Content-Length", strconv.Itoa(len(data)))

	testEmptyBody, _ := http.NewRequest(http.MethodGet, "http://test.rokwire.com/test", nil)

	type args struct {
		r                  *http.Request
		requiredServiceIDs []string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{name: "nil_request", args: args{r: nilReq, requiredServiceIDs: []string{"test"}}, want: "test", wantErr: true},
		{name: "success", args: args{r: testReq, requiredServiceIDs: []string{"test"}}, want: "test", wantErr: false},
		{name: "bad_service_id", args: args{r: testReq, requiredServiceIDs: []string{"auth"}}, want: "auth", wantErr: true},
		{name: "any_subscribed_service", args: args{r: testReq, requiredServiceIDs: nil}, want: "test", wantErr: false},
		{name: "no_matching_services", args: args{r: testReq, requiredServiceIDs: []string{}}, want: "test", wantErr: true},
		{name: "empty_body", args: args{r: testEmptyBody, requiredServiceIDs: []string{"test"}}, want: "test", wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err = s.SignRequest(tt.args.r)
			if err != nil && !tt.wantErr {
				t.Errorf("SignatureAuth.SignRequest() error = %v", err)
				return
			}

			signedRequest, err := sigauth.ParseHTTPRequest(tt.args.r)
			if err != nil && !tt.wantErr {
				t.Errorf("sigauth.ParseHTTPRequest() error = %v", err)
			}

			got, err := s.CheckRequestServiceSignature(signedRequest, tt.args.requiredServiceIDs)
			if (err != nil) != tt.wantErr {
				t.Errorf("SignatureAuth.CheckRequestSignature() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if (got != tt.want) && !tt.wantErr {
				t.Errorf("SignatureAuth.CheckRequestSignature() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSignatureAuth_CheckRequestSignature(t *testing.T) {
	authService := testutils.SetupTestAuthService("test", "https://test.rokwire.com")
	testServiceReg := authservice.ServiceReg{ServiceID: authService.ServiceID, Host: authService.ServiceHost, PubKey: testutils.GetSamplePubKey()}
	serviceRegsValid := []authservice.ServiceReg{testServiceReg}

	mockLoader := testutils.SetupMockServiceRegLoader(authService, nil, serviceRegsValid, nil)

	privKey := testutils.GetSamplePrivKey()
	pubKey, ok := privKey.Key.Public().(authutils.PublicKey)
	if !ok {
		t.Errorf("Error asserting public key type")
	}

	var nilReq *http.Request

	params := map[string]interface{}{
		"data": "test_data",
	}
	data, _ := json.Marshal(params)

	testReq, _ := http.NewRequest(http.MethodPost, "http://test.rokwire.com/test", bytes.NewReader(data))
	testReq.Header.Set("Content-Type", "application/json; charset=UTF-8")
	testReq.Header.Set("Content-Length", strconv.Itoa(len(data)))

	testEmptyBody, _ := http.NewRequest(http.MethodGet, "http://test.rokwire.com/test", nil)

	type args struct {
		r       *http.Request
		privKey authutils.PrivateKey
		pubKey  authutils.PublicKey
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "sample_keypair", args: args{r: testReq, privKey: privKey.Key, pubKey: pubKey}, wantErr: false},
		{name: "nil_pub_key", args: args{r: testReq, privKey: privKey.Key, pubKey: nil}, wantErr: true},
		{name: "nil_request", args: args{r: nilReq, privKey: privKey.Key, pubKey: pubKey}, wantErr: true},
		{name: "empty_body", args: args{r: testEmptyBody, privKey: privKey.Key, pubKey: pubKey}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := setupTestSignatureAuthWithPrivKey(authService, mockLoader, tt.args.privKey)
			if err != nil || s == nil {
				t.Errorf("Error initializing test signature auth: %v", err)
				return
			}
			err = s.SignRequest(tt.args.r)
			if err != nil && !tt.wantErr {
				t.Errorf("SignatureAuth.SignRequest() error = %v", err)
				return
			}

			signedRequest, err := sigauth.ParseHTTPRequest(tt.args.r)
			if err != nil && !tt.wantErr {
				t.Errorf("sigauth.ParseHTTPRequest() error = %v", err)
			}

			err = s.CheckRequestSignature(signedRequest, tt.args.pubKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("SignatureAuth.CheckRequestSignature() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestBuildSignatureString(t *testing.T) {
	testReq, _ := http.NewRequest(http.MethodGet, "http://test.rokwire.com/test", nil)
	testReq.Header.Set("Content-Type", "text/plain")
	testReq.Header.Set("Content-Length", "1234")

	testReqSig := `GET /test HTTP/1.1
content-length: 1234
content-type: text/plain`

	type args struct {
		r       *http.Request
		headers []string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{name: "success", args: args{r: testReq, headers: []string{"request-line", "content-length", "content-type"}}, want: testReqSig, wantErr: false},
		{name: "no_headers", args: args{r: testReq, headers: nil}, want: "", wantErr: false},
		{name: "bad_header", args: args{r: nil, headers: []string{"request-line", "content-length", "content-type", "not-a-header"}}, want: "", wantErr: true},
		{name: "nil_request", args: args{r: nil, headers: []string{"request-line", "content-length", "content-type"}}, want: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signedRequest, err := sigauth.ParseHTTPRequest(tt.args.r)
			if err != nil && !tt.wantErr {
				t.Errorf("sigauth.ParseHTTPRequest() error = %v", err)
			}

			got, err := sigauth.BuildSignatureString(signedRequest, tt.args.headers)
			if (err != nil) != tt.wantErr {
				t.Errorf("BuildSignatureString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("BuildSignatureString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetRequestLine(t *testing.T) {
	testReq, _ := http.NewRequest(http.MethodGet, "http://test.rokwire.com/test", nil)

	type args struct {
		r *http.Request
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{name: "get_request", args: args{r: testReq}, want: "GET /test HTTP/1.1", wantErr: false},
		{name: "nil_request", args: args{r: nil}, want: "", wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signedRequest, err := sigauth.ParseHTTPRequest(tt.args.r)
			if err != nil && !tt.wantErr {
				t.Errorf("sigauth.ParseHTTPRequest() error = %v", err)
			}

			if got := sigauth.GetRequestLine(signedRequest); got != tt.want {
				t.Errorf("GetRequestLine() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetRequestDigest(t *testing.T) {
	params := map[string]interface{}{
		"data": "test_data",
		"map": map[string]int{
			"one": 1,
			"two": 2,
		},
	}
	data, _ := json.Marshal(params)

	type args struct {
		body []byte
	}
	tests := []struct {
		name       string
		args       args
		wantDigest string
		wantLength int
		wantErr    bool
	}{
		{name: "success", args: args{body: data}, wantDigest: "SHA-256=OEbyxI+bLFvC3nD0cs4BcWAabvZsLFUdK1GBQrbyrzk=", wantLength: len(data), wantErr: false},
		{name: "empty_body", args: args{body: make([]byte, 0)}, wantDigest: "", wantLength: 0, wantErr: false},
		{name: "nil_body", args: args{body: nil}, wantDigest: "", wantLength: 0, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDigest, gotLength, err := sigauth.GetRequestDigest(tt.args.body)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetRequestDigest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotDigest != tt.wantDigest || gotLength != tt.wantLength {
				t.Errorf("GetRequestDigest() = %v, %v, want %v, %v", gotDigest, gotLength, tt.wantDigest, tt.wantLength)
			}
		})
	}
}

func TestSignatureAuthHeader_SetField(t *testing.T) {
	type args struct {
		field string
		value string
	}
	tests := []struct {
		name    string
		s       *sigauth.SignatureAuthHeader
		args    args
		wantErr bool
	}{
		{name: "set_algorithm", s: &sigauth.SignatureAuthHeader{}, args: args{field: "algorithm", value: "rsa-sha256"}, wantErr: false},
		{name: "set_fail", s: &sigauth.SignatureAuthHeader{}, args: args{field: "will_fail", value: "test_value"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.s.SetField(tt.args.field, tt.args.value); (err != nil) != tt.wantErr {
				t.Errorf("SignatureAuthHeader.SetField() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSignatureAuthHeader_Build(t *testing.T) {
	headers := []string{"request-line", "host", "date", "digest", "content-length"}
	sampleFingerprint := testutils.GetSamplePubKeyFingerprint()
	sigAuthHeader := sigauth.SignatureAuthHeader{KeyID: sampleFingerprint, Algorithm: "rsa-sha256", Headers: headers, Signature: "test_signature"}
	headerWithExtension := sigauth.SignatureAuthHeader{KeyID: sampleFingerprint, Algorithm: "rsa-sha256", Extensions: "test_extensions", Signature: "test_signature"}

	tests := []struct {
		name    string
		s       *sigauth.SignatureAuthHeader
		want    string
		wantErr bool
	}{
		{name: "success", s: &sigAuthHeader, want: fmt.Sprintf(`Signature keyId="%s",algorithm="rsa-sha256",headers="request-line host date digest content-length",signature="test_signature"`, sampleFingerprint), wantErr: false},
		{name: "missing_fields", s: &sigauth.SignatureAuthHeader{KeyID: sampleFingerprint, Signature: "test_aignature"}, want: "", wantErr: true},
		{name: "use_extensions", s: &headerWithExtension, want: fmt.Sprintf(`Signature keyId="%s",algorithm="rsa-sha256",extensions="test_extensions",signature="test_signature"`, sampleFingerprint), wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.s.Build()
			if (err != nil) != tt.wantErr {
				t.Errorf("SignatureAuthHeader.Build() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("SignatureAuthHeader.Build() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseSignatureAuthHeader(t *testing.T) {
	headers := []string{"request-line", "host", "date", "digest", "content-length"}
	sampleFingerprint := testutils.GetSamplePubKeyFingerprint()
	sigAuthHeader := sigauth.SignatureAuthHeader{KeyID: sampleFingerprint, Algorithm: "rsa-sha256", Headers: headers, Signature: "test_signature=="}

	type args struct {
		header string
	}
	tests := []struct {
		name    string
		args    args
		want    *sigauth.SignatureAuthHeader
		wantErr bool
	}{
		{name: "success", args: args{header: fmt.Sprintf(`Signature keyId="%s",algorithm="rsa-sha256",headers="request-line host date digest content-length",signature="test_signature=="`, sampleFingerprint)}, want: &sigAuthHeader, wantErr: false},
		{name: "invalid_format", args: args{header: fmt.Sprintf(`keyId="%s",algorithm="rsa-sha256",headers="request-line host date digest content-length",signature="test_signature"`, sampleFingerprint)}, want: nil, wantErr: true},
		{name: "invalid_param_format", args: args{header: `Signature keyId=,algorithm="rsa-sha256",extensions=="test_extensions",signature="test_signature"`}, want: nil, wantErr: true},
		{name: "extra_field", args: args{header: fmt.Sprintf(`Signature keyId="%s",extraHeader="test",algorithm="rsa-sha256",headers="request-line host date digest content-length",signature="test_signature"`, sampleFingerprint)}, want: nil, wantErr: true},
		{name: "multiple_comma", args: args{header: fmt.Sprintf(`Signature keyId="%s",,algorithm="rsa-sha256",,headers="request-line host date digest content-length",signature="test_signature"`, sampleFingerprint)}, want: nil, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sigauth.ParseSignatureAuthHeader(tt.args.header)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSignatureAuthHeader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseSignatureAuthHeader() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseHTTPRequest(t *testing.T) {
	var nilReq *http.Request

	params := map[string]interface{}{
		"data": "test_data",
	}
	data, _ := json.Marshal(params)

	testReq, _ := http.NewRequest(http.MethodPost, "http://test.rokwire.com/test", bytes.NewReader(data))
	testReq.Header.Set("Content-Type", "application/json; charset=UTF-8")
	testReq.Header.Set("Content-Length", strconv.Itoa(len(data)))
	headerMap := map[string][]string{
		"Content-Type":   {"application/json; charset=UTF-8"},
		"Content-Length": {strconv.Itoa(len(data))},
	}

	testEmpty, _ := http.NewRequest(http.MethodGet, "http://test.rokwire.com/test", nil)

	type args struct {
		r *http.Request
	}
	tests := []struct {
		name            string
		args            args
		want            *sigauth.Request
		wantRequestBody []byte
		wantErr         bool
	}{
		{name: "nil_request", args: args{r: nilReq}, want: nil, wantRequestBody: nil, wantErr: false},
		{name: "success", args: args{r: testReq}, want: &sigauth.Request{Headers: headerMap, Body: data, Host: "test.rokwire.com", Method: "POST", Path: "/test", Protocol: "HTTP/1.1"}, wantRequestBody: data, wantErr: false},
		{name: "empty", args: args{r: testEmpty}, want: &sigauth.Request{Headers: make(map[string][]string), Body: nil, Host: "test.rokwire.com", Method: "GET", Path: "/test", Protocol: "HTTP/1.1"}, wantRequestBody: nil, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sigauth.ParseHTTPRequest(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseHTTPRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseHTTPRequest() = %v, want %v", got, tt.want)
			}

			if tt.args.r != nil && tt.args.r.Body != nil {
				requestBody, _ := io.ReadAll(tt.args.r.Body)
				if !reflect.DeepEqual(requestBody, tt.wantRequestBody) {
					t.Errorf("ParseHTTPRequest() original request body = %v, wantRequestBody %v", requestBody, tt.wantRequestBody)
				}
			}
		})
	}
}
