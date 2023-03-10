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
	"net/url"
	"time"

	"github.com/rokwire/core-auth-library-go/v3/authutils"
	"github.com/rs/cors"
)

const (
	hostPrefix       string = "__Host-"
	refreshTokenName string = "rokwire-refresh-token"
	csrfTokenName    string = "rokwire-csrf-token"

	originHeader string = "Origin"
)

// NOTE: any explicitly set cookie domain must match the calling application's host or be a valid superdomain of that host

// SetupCORS sets up a new CORS handler for router using the given allowedOrigins and customHeaders.
// Used by building blocks to disallow requests from not allowed origins in web browsers.
//
// "X-Requested-With", "Content-Type", "Authorization", and "Origin" headers are allowed for cross domain requests by default.
func SetupCORS(allowedOrigins []string, customHeaders []string, router http.Handler) http.Handler {
	c := cors.New(cors.Options{
		AllowedOrigins:   allowedOrigins,
		AllowCredentials: true,
		AllowedMethods:   []string{"GET", "DELETE", "POST", "PUT"},
		AllowedHeaders:   append([]string{"X-Requested-With", "Content-Type", "Authorization", "Referer"}, customHeaders...),
		ExposedHeaders:   []string{"Content-Type"},
		MaxAge:           300,
	})

	return c.Handler(router)
}

// CheckOrigin verifies that the "Origin" header in r matches requiredOrigin. Used by web applications for CSRF protection.
//
// requiredOrigin should be the full origin of the calling application (i.e., <scheme>://<hostname>:<port>).
// <port> is optional, but the default port for the requested service is used if not given.
func CheckOrigin(r *http.Request, requiredOrigin string) error {
	if r == nil {
		return errors.New("missing request")
	}

	origin := r.Header.Get(originHeader)
	if origin == "" {
		if r.Referer() == "" {
			return errors.New("missing origin and referer headers")
		}

		parsedReferer, err := url.Parse(r.Referer())
		if err != nil {
			return fmt.Errorf("error parsing referer: %v", err)
		}

		origin = fmt.Sprintf("%s://%s", parsedReferer.Scheme, parsedReferer.Host)
	}
	if origin != requiredOrigin {
		return errors.New("required origin unsatisfied")
	}

	return nil
}

// GetRefreshToken retrieves refresh and CSRF tokens from the request headers and/or cookies.
// The refresh token is returned if the CSRF tokens match. A new CSRF cookie is returned if generation is successful.
// Refresh tokens must be provided in the "__Host-rokwire-refresh-token" cookie.
func GetRefreshToken(r *http.Request, newCSRFTokenLength int) (string, http.Cookie, error) {
	newCSRFCookie, err := CheckCSRFToken(r, newCSRFTokenLength)
	if err != nil {
		return "", newCSRFCookie, fmt.Errorf("error checking csrf token: %v", err)
	}

	refreshCookie, err := r.Cookie(hostPrefix + refreshTokenName)
	if err != nil {
		return "", newCSRFCookie, fmt.Errorf("error reading refresh token cookie: %v", err)
	}
	if refreshCookie == nil || refreshCookie.Value == "" {
		return "", newCSRFCookie, errors.New("missing refresh token")
	}

	return refreshCookie.Value, newCSRFCookie, nil
}

// CheckCSRFToken compares the value of the CSRF cookie against the value of the CSRF header and returns an error if there is a mismatch.
// A new CSRF cookie is returned if generation is successful.
// CSRF tokens must be provided in the "__Host-rokwire-csrf-token" cookie and "Rokwire-Csrf-Token" header.
func CheckCSRFToken(r *http.Request, newTokenLength int) (http.Cookie, error) {
	newCookie, err := NewCSRFCookie(newTokenLength)
	if err != nil {
		return newCookie, fmt.Errorf("error creating new csrf cookie: %v", err)
	}

	if r == nil {
		return newCookie, errors.New("missing request")
	}

	csrfCookie, err := r.Cookie(hostPrefix + csrfTokenName)
	if err != nil {
		return newCookie, fmt.Errorf("error reading csrf token cookie: %v", err)
	}
	if csrfCookie == nil || csrfCookie.Value == "" {
		return newCookie, errors.New("missing csrf cookie token")
	}

	csrfToken := r.Header.Get(csrfTokenName)
	if csrfToken == "" {
		return newCookie, errors.New("missing csrf header")
	}
	if csrfCookie.Value != csrfToken {
		return newCookie, errors.New("csrf cookie token does not match csrf header")
	}

	return newCookie, nil
}

// NewRefreshCookie returns a new "__Host-rokwire-refresh-token" cookie with the given lifetime and the given token as its value.
// The cookie is set to be immediately deleted if delete is true.
// This should be used by web applications to send refresh tokens to a browser.
func NewRefreshCookie(token string, lifetime time.Duration, delete bool) (*http.Cookie, error) {
	maxAge := 0
	if delete {
		maxAge = -1
	} else if token == "" {
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
		MaxAge:   maxAge,
	}, nil
}

// NewCSRFCookie returns a new "__Host-rokwire-csrf-token" session cookie.
// This should be used by web applications to send CSRF tokens to a browser.
func NewCSRFCookie(tokenLength int) (http.Cookie, error) {
	newToken, err := authutils.GenerateRandomString(tokenLength)
	// this is a session cookie because MaxAge and Expires are unspecified
	newCookie := http.Cookie{
		Name:     hostPrefix + csrfTokenName,
		Value:    newToken,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	}
	if err != nil {
		// failed to generate new token for some reason, so set cookie to be deleted
		newCookie.MaxAge = -1
		return newCookie, fmt.Errorf("error generating new csrf token: %v", err)
	}

	return newCookie, nil
}
