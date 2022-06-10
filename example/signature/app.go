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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/rokwire/core-auth-library-go/authservice"
	"github.com/rokwire/core-auth-library-go/internal/testutils"
	"github.com/rokwire/core-auth-library-go/sigauth"
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

func (we WebAdapter) sampleSignedRequest(url string, param string, body []byte) (string, error) {
	client := &http.Client{}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
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
		signedRequest, err := sigauth.ParseHTTPRequest(req)
		if err != nil {
			log.Printf("error parsing http request: %v", err)
		}

		serviceID, err := we.signatureAuth.CheckRequestServiceSignature(signedRequest, services)
		if err != nil {
			log.Printf("Authentication error: %v\n", err)
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		log.Printf("Authentication successful for service: %s", serviceID)
		handler(w, req)
	}
}

// NewWebAdapter creates new WebAdapter instance
func NewWebAdapter(signatureAuth *sigauth.SignatureAuth) WebAdapter {
	return WebAdapter{signatureAuth: signatureAuth}
}

func main() {
	// Define list of services to load public keys for. For signature auth, this includes all services
	// 	that this service will receive signed requests from.
	services := []string{"auth"}

	// Instantiate an AuthService to maintain basic auth data
	authService := authservice.AuthService{
		ServiceID:   "example",
		ServiceHost: "http://localhost:5000",
		FirstParty:  true,
		AuthBaseURL: "http://localhost/core",
	}

	// Instantiate a remote ServiceRegLoader to load auth service registration records from auth service
	serviceRegLoader, err := authservice.NewRemoteServiceRegLoader(&authService, services)
	if err != nil {
		log.Fatalf("Error initializing remote service registration loader: %v", err)
	}

	// Instantiate a ServiceRegManager to manage service registration records
	serviceRegManager, err := authservice.NewServiceRegManager(&authService, serviceRegLoader)
	if err != nil {
		log.Fatalf("Error initializing service registration manager: %v", err)
	}

	privKey := testutils.GetSamplePrivKey()

	// TODO: Load service private key

	// Instantiate SignatureAuth instance to perform token validation
	signatureAuth, err := sigauth.NewSignatureAuth(privKey, serviceRegManager, false)
	if err != nil {
		log.Fatalf("Error initializing signature auth: %v", err)
	}

	// Instantiate a remote ServiceAccountLoader to load auth service account data from auth service
	accountID := "0ba899ed-ac7a-11ec-b09f-00ffd2760de8"
	serviceAccountLoader, err := authservice.NewRemoteServiceAccountLoader(&authService, accountID, signatureAuth)
	if err != nil {
		log.Fatalf("Error initializing remote service account loader: %v", err)
	}

	// Instantiate a remote ServiceAccountManager to manage service account-related data
	serviceAccountManager, err := authservice.NewServiceAccountManager(&authService, serviceAccountLoader)
	if err != nil {
		log.Fatalf("Error initializing service account manager: %v", err)
	}

	appID := "9766"
	orgID := "0a2eff20-e2cd-11eb-af68-60f81db5ecc0"

	// Instantiate and start a new WebAdapter
	adapter := NewWebAdapter(signatureAuth)

	// Tip: You do not need to subscribe to services you are making requests to, only those
	// 		that you are receiving requests from

	req := map[string]interface{}{
		"account_id": accountID,
		"app_id":     appID,
		"org_id":     orgID,
		"auth_type":  "signature",
	}

	reqData, _ := json.Marshal(req)

	fmt.Println("adapter done")
	response, err := adapter.sampleSignedRequest("http://localhost/core/bbs/access-token", "sample", reqData)
	if err != nil {
		log.Printf("Error making sample signed request: %v", err)
	} else {
		log.Printf("Response: %s", response)
	}

	// Tip: This sends the same request as the manually signed request above
	token, err := serviceAccountManager.GetAccessToken(appID, orgID)
	if err != nil {
		log.Printf("Error loading access token: %v", err)
	} else {
		log.Printf("Response: %s", token.String())
	}
}
