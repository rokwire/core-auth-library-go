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
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/rokwire/core-auth-library-go/authservice"
	"github.com/rokwire/core-auth-library-go/internal/testutils"
	"github.com/rokwire/core-auth-library-go/sigauth"
	"github.com/rokwire/logging-library-go/logs"
)

// WebAdapter is the web adapter for signature auth
type WebAdapter struct {
	signatureAuth *sigauth.SignatureAuth
}

// Start starts the web adapter for signature auth
func (we WebAdapter) Start() {
	// Empty service IDs indicates that all subscribed services may access this resource
	http.HandleFunc("/test", we.signatureAuthWrapFunction(we.testHandler, []string{}))

	// Service IDs indicate only the "example2" service can access this endpoint
	http.HandleFunc("/example2/test", we.signatureAuthWrapFunction(we.example2TestHandler, []string{"example2"}))

	http.ListenAndServe(":5000", nil)
}

// test endpoint tests service authentication
func (we WebAdapter) testHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Access granted"))
}

// example2Test endpoint tests service authentication for the example2 service only
func (we WebAdapter) example2TestHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Access granted: example2"))
}

func (we WebAdapter) sampleSignedRequest(url string, param string, body string) (string, error) {
	client := &http.Client{}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(body)))
	if err != nil {
		return "", fmt.Errorf("error formatting sample request: %v", err)
	}

	// q := req.URL.Query()
	// q.Add("param", param)
	// req.URL.RawQuery = q.Encode()
	req.Header.Set("Content-Type", "application/json")

	err = we.signatureAuth.SignRequest(req)
	if err != nil {
		return "", fmt.Errorf("error signing sample request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error making sample request: %v", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("error from sample request: %d - %s", resp.StatusCode, resp.Body)
	}

	response, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading body of sample response: %v", err)
	}

	return string(response), err
}

// tokenAuthWrapFunc provides a standard wrapper that performs token auth
func (we WebAdapter) signatureAuthWrapFunction(handler http.HandlerFunc, services []string) http.HandlerFunc {
	// Receive request with tokens generated by auth service
	return func(w http.ResponseWriter, req *http.Request) {
		// Authenticate token
		serviceID, err := we.signatureAuth.CheckRequestServiceSignature(req, services)
		if err != nil {
			log.Printf("Authentication error: %v\n", err)
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		log.Printf("Authentication successful for service: %s", serviceID)
		handler(w, req)
	}
}

func printDeletedAccountIDs(accountIDs []string) error {
	log.Printf("Deleted account IDs: %v\n", accountIDs)
	return nil
}

// NewWebAdapter creates new WebAdapter instance
func NewWebAdapter(signatureAuth *sigauth.SignatureAuth) WebAdapter {
	return WebAdapter{signatureAuth: signatureAuth}
}

func main() {
	// Define list of services to load public keys for. For signature auth, this includes all services
	// 	that this service will receive signed requests from.
	services := []string{}
	// Instantiate a remote AuthDataLoader to load service registration records from auth service
	config := authservice.RemoteAuthDataLoaderConfig{
		AuthServicesHost: "http://localhost/core",
		// ServiceToken:     "sample_token",
		// DeletedAccountsCallback: printDeletedAccountIDs,
	}
	logger := logs.NewLogger("example", nil)
	dataLoader, err := authservice.NewRemoteAuthDataLoader(config, services, logger)
	if err != nil {
		log.Fatalf("Error initializing remote data loader: %v", err)
	}

	// Instantiate AuthService instance
	authService, err := authservice.NewAuthService("example", "http://localhost:8080", dataLoader)
	if err != nil {
		log.Fatalf("Error initializing auth service: %v", err)
	}

	privKey := testutils.GetSamplePrivKey()

	// TODO: Load service private key

	// Instantiate SignatureAuth instance to perform token validation
	signatureAuth, err := sigauth.NewSignatureAuth(privKey, authService, true)
	if err != nil {
		log.Fatalf("Error initializing signature auth: %v", err)
	}

	// Instantiate and start a new WebAdapter
	adapter := NewWebAdapter(signatureAuth)

	// Tip: You do not need to subscribe to services you are making requests to, only those
	// 		that you are receiving requests from

	fmt.Println("adapter done")
	response, err := adapter.sampleSignedRequest("http://localhost/core/tps/account/token", "sample", "{\"auth_type\":\"signature\",\"creds\":{\"id\":\"072da518-68ee-11ec-b78b-00ffd2760de8\"}}")
	if err != nil {
		log.Printf("Error making sample signed request: %v", err)
	} else {
		log.Printf("Response: %s", response)
	}
}
