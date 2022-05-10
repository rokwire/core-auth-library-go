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

package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/rokwire/core-auth-library-go/authorization"
	"github.com/rokwire/core-auth-library-go/authservice"
	"github.com/rokwire/core-auth-library-go/tokenauth"
	"github.com/rokwire/logging-library-go/logs"
)

// WebAdapter is the web adapter for token auth
type WebAdapter struct {
	tokenAuth *tokenauth.TokenAuth
}

func (we WebAdapter) Start() {
	http.HandleFunc("/test", we.tokenAuthWrapFunc(we.test))
	http.HandleFunc("/admin/test", we.adminTokenWrapFunc(we.adminTest))

	http.ListenAndServe(":5000", nil)
}

// test endpoint tests user authentication
func (we WebAdapter) test(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Access granted"))
}

// adminTest endpoint tests user authentication and admin authorization
func (we WebAdapter) adminTest(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Admin access granted"))
}

// tokenAuthWrapFunc provides a standard wrapper that performs token auth
func (we WebAdapter) tokenAuthWrapFunc(handler http.HandlerFunc) http.HandlerFunc {
	// Receive request with tokens generated by auth service
	return func(w http.ResponseWriter, req *http.Request) {
		// Authenticate token
		claims, err := we.tokenAuth.CheckRequestTokens(req)
		if err != nil {
			log.Printf("Authentication error: %v\n", err)
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		err = we.tokenAuth.AuthorizeRequestScope(claims, req)
		if err != nil {
			log.Printf("Scope error: %v\n", err)
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}

		log.Printf("Authentication successful for user: %v", claims)
		handler(w, req)
	}
}

// adminTokenWrapFunc
func (we WebAdapter) adminTokenWrapFunc(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		// Authenticate token
		claims, err := we.tokenAuth.CheckRequestTokens(req)
		if err != nil {
			log.Printf("Authentication error: %v\n", err)
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		err = we.tokenAuth.AuthorizeRequestPermissions(claims, req)
		if err != nil {
			log.Printf("Permission error: %v\n", err)
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}

		log.Printf("Authentication successful for user: %v", claims)
		handler(w, req)
	}
}

func printDeletedAccountIDs(accountIDs []string) error {
	log.Printf("Deleted account IDs: %v\n", accountIDs)
	return nil
}

// NewWebAdapter creates new WebAdapter instance
func NewWebAdapter(tokenAuth *tokenauth.TokenAuth) WebAdapter {
	return WebAdapter{tokenAuth: tokenAuth}
}

func main() {
	serviceID := "sample"

	staticTokenAuth, err := authservice.NewStaticTokenServiceAuth("sample_token")
	if err != nil {
		log.Fatalf("Error initializing static token auth: %v", err)
	}

	// Instantiate a remote AuthDataLoader to load auth service registration record from auth service
	config := authservice.RemoteAuthDataLoaderConfig{
		AuthServicesHost:        "https://auth.rokwire.com/services",
		DeletedAccountsCallback: printDeletedAccountIDs,
		ServiceAuthRequests:     staticTokenAuth,
	}
	logger := logs.NewLogger("example", nil)
	dataLoader, err := authservice.NewRemoteAuthDataLoader(&config, nil, true, logger)
	if err != nil {
		log.Fatalf("Error initializing remote data loader: %v", err)
	}

	// Instantiate AuthService instance
	authService, err := authservice.NewAuthService(serviceID, "https://sample.rokwire.com", dataLoader)
	if err != nil {
		log.Fatalf("Error initializing auth service: %v", err)
	}

	permissionAuth := authorization.NewCasbinStringAuthorization("./permissions_authorization_policy.csv")
	scopeAuth := authorization.NewCasbinScopeAuthorization("./scope_authorization_policy.csv", serviceID)
	// Instantiate TokenAuth instance to perform token validation
	tokenAuth, err := tokenauth.NewTokenAuth(true, authService, permissionAuth, scopeAuth)
	if err != nil {
		log.Fatalf("Error intitializing token auth: %v", err)
	}
	fmt.Println("Setup complete")

	// Instantiate and start a new WebAdapter
	adapter := NewWebAdapter(tokenAuth)
	adapter.Start()
}
