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

package webauth

import (
	"errors"
	"fmt"
	"net/http"
)

const (
	hostPrefix       string = "__Host-"
	refreshTokenName string = "rokwire-refresh-token"
	csrfTokenName    string = "rokwire-csrf-token"
)

// -------------------------- Helper Functions --------------------------

// GetRequestTokens retrieves tokens from the request headers and/or cookies
// Mobile Clients/Secure Servers: Access tokens must be provided as a Bearer token
//
//	in the "Authorization" header
//
// Web Clients: Access tokens must be provided in the "rokwire-access-token" cookie
//
//	and CSRF tokens must be provided in the "CSRF" header
func GetRefreshToken(r *http.Request) (string, error) {
	refreshCookie, err := r.Cookie(hostPrefix + refreshTokenName)
	if err != nil {
		return "", fmt.Errorf("error reading refresh token cookie: %v", err)
	}
	if refreshCookie == nil || refreshCookie.Value == "" {
		return "", errors.New("missing refresh token")
	}

	csrfCookie, err := r.Cookie(hostPrefix + csrfTokenName)
	if err != nil {
		return "", fmt.Errorf("error reading csrf token cookie: %v", err)
	}
	if csrfCookie == nil || csrfCookie.Value == "" {
		return "", errors.New("missing csrf token")
	}

	csrfToken := r.Header.Get(csrfTokenName)
	if csrfToken == "" {
		return "", errors.New("csrf header")
	}
	if csrfCookie.Value != csrfToken {
		return "", 
	}

	return refreshCookie.Value, nil
}
