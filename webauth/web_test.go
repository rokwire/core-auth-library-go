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

package webauth_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/rokwire/core-auth-library-go/v2/webauth"
)

func TestCheckOrigin(t *testing.T) {
	type args struct {
		r              *http.Request
		requiredOrigin string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"missing origin", args{&http.Request{Header: http.Header{"Referer": {"http://localhost:5000"}}}, "http://localhost:5000"}, false},
		{"missing origin and referer", args{&http.Request{Header: http.Header{}}, "http://localhost:5000"}, true},
		{"mismatching origin", args{&http.Request{Header: http.Header{"Origin": {"http://localhost:5000"}}}, "https://example.test.com"}, true},
		{"nil request", args{nil, "https://example.test.com"}, true},
		{"success", args{&http.Request{Header: http.Header{"Origin": {"https://example.test.com"}}}, "https://example.test.com"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := webauth.CheckOrigin(tt.args.r, tt.args.requiredOrigin)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckOrigin() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGetRefreshToken(t *testing.T) {
	type args struct {
		r               *http.Request
		csrfTokenLength int
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"missing csrf cookie", args{&http.Request{Header: http.Header{"Cookie": {"__Host-rokwire-refresh-token=example_refresh_token"}, "Rokwire-Csrf-Token": {"example_csrf_token"}}}, 32}, "", true},
		{"missing csrf cookie value", args{&http.Request{Header: http.Header{"Cookie": {"__Host-rokwire-refresh-token=example_refresh_token; __Host-rokwire-csrf-token="}, "Rokwire-Csrf-Token": {"example_csrf_token"}}}, 32}, "", true},
		{"missing csrf header", args{&http.Request{Header: http.Header{"Cookie": {"__Host-rokwire-refresh-token=example_refresh_token; __Host-rokwire-csrf-token=example_csrf_token"}}}, 32}, "", true},
		{"mismatching csrf tokens", args{&http.Request{Header: http.Header{"Cookie": {"__Host-rokwire-refresh-token=example_refresh_token; __Host-rokwire-csrf-token=example_csrf_token"}, "Rokwire-Csrf-Token": {"bad_csrf_token"}}}, 32}, "", true},
		{"missing refresh cookie", args{&http.Request{Header: http.Header{"Cookie": {"__Host-rokwire-csrf-token=example_csrf_token"}, "Rokwire-Csrf-Token": {"example_csrf_token"}}}, 32}, "", true},
		{"missing refresh cookie value", args{&http.Request{Header: http.Header{"Cookie": {"__Host-rokwire-refresh-token=; __Host-rokwire-csrf-token=example_csrf_token"}, "Rokwire-Csrf-Token": {"example_csrf_token"}}}, 32}, "", true},
		{"nil request", args{nil, 32}, "", true},
		{"success", args{&http.Request{Header: http.Header{"Cookie": {"__Host-rokwire-refresh-token=example_refresh_token; __Host-rokwire-csrf-token=example_csrf_token"}, "Rokwire-Csrf-Token": {"example_csrf_token"}}}, 32}, "example_refresh_token", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, csrfCookie, err := webauth.GetRefreshToken(tt.args.r, tt.args.csrfTokenLength)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetRefreshToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetRefreshToken() got = %v, want %v", got, tt.want)
			}
			if csrfCookie.Value == "" {
				t.Error("GetRefreshToken() missing csrf cookie value")
			}
		})
	}
}

func TestNewRefreshCookie(t *testing.T) {
	type args struct {
		token    string
		lifetime time.Duration
		delete   bool
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"missing token", args{"", 5 * time.Minute, false}, true},
		{"delete success", args{"", 5 * time.Minute, true}, false},
		{"success", args{"example_refresh_token", 5 * time.Minute, false}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cookie, err := webauth.NewRefreshCookie(tt.args.token, tt.args.lifetime, tt.args.delete)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewRefreshCookie() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if cookie != nil && cookie.Value != tt.args.token {
				t.Error("NewRefreshCookie() mismatching cookie value")
				return
			}
			if tt.args.delete && (cookie == nil || cookie.MaxAge != -1) {
				t.Error("NewRefreshCookie() deleted cookie does not have MaxAge: -1")
			}
		})
	}
}
