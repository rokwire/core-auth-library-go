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

	"github.com/rokwire/core-auth-library-go/v2/authorization"
	"github.com/rokwire/core-auth-library-go/v2/authservice"
	"github.com/rokwire/core-auth-library-go/v2/tokenauth"
)

// WebAdapter is the web adapter for token auth
type WebAdapter struct {
	handlers tokenauth.Handlers
}

// Start starts the web adapter for token auth
func (we WebAdapter) Start() {
	http.HandleFunc("/test", we.tokenAuthWrapFunc(we.test, we.handlers.Standard))
	http.HandleFunc("/admin/test", we.tokenAuthWrapFunc(we.adminTest, we.handlers.Permissions))

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
func (we WebAdapter) tokenAuthWrapFunc(handler http.HandlerFunc, authorization tokenauth.Handler) http.HandlerFunc {
	// Receive request with tokens generated by auth service
	return func(w http.ResponseWriter, req *http.Request) {
		if authorization != nil {
			responseStatus, claims, err := authorization.Check(req)
			if err != nil {
				log.Printf("authorization error: %v\n", err)
				http.Error(w, err.Error(), responseStatus)
				return
			}
			log.Printf("Authorization successful for user: %v", claims)
		}
		handler(w, req)
	}
}

// NewWebAdapter creates new WebAdapter instance
func NewWebAdapter(handlers tokenauth.Handlers) WebAdapter {
	return WebAdapter{handlers: handlers}
}

func main() {
	// Instantiate an AuthService to maintain basic auth data
	authService := authservice.AuthService{
		ServiceID:   "example",
		ServiceHost: "http://localhost:5000",
		FirstParty:  true,
		AuthBaseURL: "http://localhost/core",
	}

	// Instantiate a remote ServiceRegLoader to load auth service registration record from auth service
	serviceRegLoader, err := authservice.NewRemoteServiceRegLoader(&authService, []string{"auth"})
	if err != nil {
		log.Fatalf("Error initializing remote service registration loader: %v", err)
	}

	// Instantiate a ServiceRegManager to manage service registration records
	serviceRegManager, err := authservice.NewServiceRegManager(&authService, serviceRegLoader)
	if err != nil {
		log.Fatalf("Error initializing service registration manager: %v", err)
	}

	permissionAuth := authorization.NewCasbinStringAuthorization("./permissions_authorization_policy.csv")
	scopeAuth := authorization.NewCasbinScopeAuthorization("./scope_authorization_policy.csv", authService.ServiceID)
	// Instantiate TokenAuth instance to perform token validation
	tokenAuth, err := tokenauth.NewTokenAuth(true, serviceRegManager, permissionAuth, scopeAuth)
	if err != nil || tokenAuth == nil {
		log.Fatalf("Error initializing token auth: %v", err)
	}
	authHandlers := tokenauth.NewHandlers(tokenauth.NewScopeHandler(*tokenAuth, nil))

	fmt.Println("Setup complete")

	// Instantiate and start a new WebAdapter
	adapter := NewWebAdapter(authHandlers)
	adapter.Start()
}
