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
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"
	"strconv"
	"testing"

	"github.com/rokwire/core-auth-library-go/authservice"
	"github.com/rokwire/core-auth-library-go/authservice/mocks"
	"github.com/rokwire/core-auth-library-go/internal/testutils"
	"github.com/rokwire/core-auth-library-go/sigauth"
)

func setupTestSignatureAuth(mockLoader *mocks.ServiceRegLoader) (*sigauth.SignatureAuth, error) {
	auth, err := testutils.SetupTestAuthService(mockLoader)
	if err != nil {
		return nil, fmt.Errorf("error setting up test auth service: %v", err)
	}
	return sigauth.NewSignatureAuth(testutils.GetSamplePrivKey(), auth)
}

func TestSignatureAuth_CheckSignature(t *testing.T) {
	testServiceReg := authservice.ServiceReg{ServiceID: "test", Host: "https://test.rokwire.com", PubKey: testutils.GetSamplePubKey()}
	authServiceReg := authservice.ServiceReg{ServiceID: "auth", Host: "https://auth.rokwire.com", PubKey: testutils.GetSamplePubKey()}
	serviceRegsValid := []authservice.ServiceReg{authServiceReg, testServiceReg}
	subscribed := []string{"auth"}

	type args struct {
		serviceID string
		message   []byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "test_one", args: args{serviceID: "auth", message: []byte("test_message")}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockLoader := testutils.SetupMockServiceLoader(subscribed, serviceRegsValid, nil)
			s, err := setupTestSignatureAuth(mockLoader)
			if err != nil || s == nil {
				t.Errorf("Error initializing test signature auth: %v", err)
				return
			}
			signature, err := s.Sign(tt.args.message)
			if (err != nil) != tt.wantErr {
				t.Errorf("SignatureAuth.Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err := s.CheckSignature(tt.args.serviceID, tt.args.message, signature); (err != nil) != tt.wantErr {
				t.Errorf("SignatureAuth.CheckSignature() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSignatureAuth_CheckRequestSignature(t *testing.T) {
	testServiceReg := authservice.ServiceReg{ServiceID: "test", Host: "https://test.rokwire.com", PubKey: testutils.GetSamplePubKey()}
	authServiceReg := authservice.ServiceReg{ServiceID: "auth", Host: "https://auth.rokwire.com", PubKey: testutils.GetSamplePubKey()}
	serviceRegsValid := []authservice.ServiceReg{authServiceReg, testServiceReg}
	subscribed := []string{"auth"}

	var nil_req *http.Request
	var test_req *http.Request

	params := map[string]interface{}{
		"data": "test_data",
	}
	data, err := json.Marshal(params)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	test_req, err = http.NewRequest(http.MethodGet, "http://test.rokwire.com/test", bytes.NewReader(data))
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	test_req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	test_req.Header.Set("Content-Length", strconv.Itoa(len(data)))

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
		// TODO: Add test cases.
		{name: "test_one", args: args{r: nil_req, requiredServiceIDs: []string{"auth"}}, want: "auth", wantErr: true},
		{name: "test_two", args: args{r: test_req, requiredServiceIDs: []string{"auth"}}, want: "auth", wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockLoader := testutils.SetupMockServiceLoader(subscribed, serviceRegsValid, nil)
			s, err := setupTestSignatureAuth(mockLoader)
			if err != nil || s == nil {
				t.Errorf("Error initializing test signature auth: %v", err)
				return
			}
			err = s.SignRequest(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("SignatureAuth.SignRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			test_req.Body = ioutil.NopCloser(bytes.NewReader(data))

			got, err := s.CheckRequestSignature(tt.args.r, tt.args.requiredServiceIDs)
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

func TestBuildSignatureString(t *testing.T) {
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
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sigauth.BuildSignatureString(tt.args.r, tt.args.headers)
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
	type args struct {
		r *http.Request
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sigauth.GetRequestLine(tt.args.r); got != tt.want {
				t.Errorf("GetRequestLine() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetRequestDigest(t *testing.T) {
	type args struct {
		r *http.Request
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sigauth.GetRequestDigest(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetRequestDigest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetRequestDigest() = %v, want %v", got, tt.want)
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
		// TODO: Add test cases.
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
	tests := []struct {
		name    string
		s       *sigauth.SignatureAuthHeader
		want    string
		wantErr bool
	}{
		// TODO: Add test cases.
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
	type args struct {
		header string
	}
	tests := []struct {
		name    string
		args    args
		want    *sigauth.SignatureAuthHeader
		wantErr bool
	}{
		// TODO: Add test cases.
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
