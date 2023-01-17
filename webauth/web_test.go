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

	"github.com/rokwire/core-auth-library-go/v2/webauth"
)

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
		// TODO: Add test cases.
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
