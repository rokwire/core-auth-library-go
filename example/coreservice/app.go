// Copyright 2022 Board of Trustees of the University of Illinois.
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
	"log"

	"github.com/rokwire/core-auth-library-go/authservice"
	"github.com/rokwire/core-auth-library-go/coreservice"
	"github.com/rokwire/logging-library-go/logs"
)

func main() {
	// Instantiate an AuthService to maintain basic auth data
	authService := authservice.AuthService{
		ServiceID:   "example",
		ServiceHost: "http://localhost:5000",
		FirstParty:  true,
		AuthBaseURL: "http://localhost/core",
	}

	// Instantiate a remote ServiceAccountLoader to load auth service account data from auth service
	staticTokenAuth := authservice.StaticTokenServiceAuth{ServiceToken: "exampleToken"}
	serviceAccountLoader, err := authservice.NewRemoteServiceAccountLoader(&authService, "exampleAccountID", staticTokenAuth)
	if err != nil {
		log.Fatalf("Error initializing remote service account loader: %v", err)
	}

	// Instantiate a remote ServiceAccountManager to manage service account-related data
	serviceAccountManager, err := authservice.NewServiceAccountManager(&authService, serviceAccountLoader)
	if err != nil {
		log.Fatalf("Error initializing service account manager: %v", err)
	}

	// Instantiate a CoreService to utilize certain core services, such as reading deleted account IDs
	deletedAccountsConfig := coreservice.DeletedAccountsConfig{
		Callback: printDeletedAccountIDs,
	}
	logger := logs.NewLogger(authService.ServiceID, nil)
	coreService, err := coreservice.NewCoreService(serviceAccountManager, &deletedAccountsConfig, logger)
	if err != nil {
		log.Printf("Error initializing core service: %v", err)
	}

	coreService.StartDeletedAccountsTimer()
}

func printDeletedAccountIDs(accountIDs []string) error {
	log.Printf("Deleted account IDs: %v\n", accountIDs)
	return nil
}
