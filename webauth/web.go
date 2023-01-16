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
	"time"

	"github.com/rs/cors"
)

const (
	hostPrefix       string = "__Host-"
	refreshTokenName string = "rokwire-refresh-token"
	csrfTokenName    string = "rokwire-csrf-token"

	originHeader string = "Origin"
)

// SetupCORS sets up a new CORS handler for router using the given allowedOrigins and customHeaders. Used by building blocks for CSRF protection.
// TODO: pass in more CORS option params?
func SetupCORS(allowedOrigins []string, customHeaders []string, router http.Handler) http.Handler {
	c := cors.New(cors.Options{
		AllowedOrigins:   allowedOrigins,
		AllowCredentials: true,
		AllowedMethods:   []string{"GET", "DELETE", "POST", "PUT"},
		AllowedHeaders:   append([]string{"X-Requested-With", "Content-Type", "Authorization"}, customHeaders...),
		ExposedHeaders:   []string{"Content-Type"},
		MaxAge:           300,
	})

	return c.Handler(router)
}

// CheckOrigin verifies that the "Origin" header in r matches requiredOrigin. Used by web applications for CSRF protection.
func CheckOrigin(r *http.Request, requiredOrigin string) (bool, error) {
	origin := r.Header.Get(originHeader)
	if origin == "" {
		return false, errors.New("missing origin header")
	}

	return origin == requiredOrigin, nil
}

// GetRefreshToken retrieves refresh and CSRF tokens from the request headers and/or cookies. The refresh token is returned if the CSRF tokens match.
//
// Refresh tokens must be provided in the "__Host-rokwire-refresh-token" cookie and CSRF tokens must be provided in the "__Host-rokwire-csrf-token" cookie and "Rokwire-Csrf-Token" header
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
		return "", errors.New("missing csrf cookie token")
	}

	csrfToken := r.Header.Get(csrfTokenName)
	if csrfToken == "" {
		return "", errors.New("csrf header")
	}
	if csrfCookie.Value != csrfToken {
		return "", errors.New("csrf cookie token does not match csrf header")
	}

	return refreshCookie.Value, nil
}

// NewRefreshCookie returns a new "__Host-rokwire-refresh-token" cookie with the given lifetime and the given token as its value
// This should be used by web applications to send refresh tokens to a browser
func NewRefreshCookie(token string, lifetime time.Duration) (*http.Cookie, error) {
	if token == "" {
		return nil, errors.New("token is missing")
	}
	return &http.Cookie{
		Name:     hostPrefix + refreshTokenName,
		Value:    token,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		Expires:  time.Now().Add(lifetime),
	}, nil
}

// NewCSRFCookie returns a new "__Host-rokwire-csrf-token" session cookie with the given token as its value
// This should be used by web applications to send CSRF tokens to a browser
func NewCSRFCookie(token string) (*http.Cookie, error) {
	if token == "" {
		return nil, errors.New("token is missing")
	}
	//Session cookie because MaxAge and Expires are unspecified
	return &http.Cookie{
		Name:     hostPrefix + csrfTokenName,
		Value:    token,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	}, nil
}
