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
	// Instantiate a remote ServiceAccountLoader to load auth service account-related data from auth service
	serviceAccountLoaderConfig := authservice.RemoteServiceAccountLoaderConfig{
		ServiceToken: "sample_token",
	}
	serviceAccountLoader, err := authservice.NewRemoteServiceAccountLoader(serviceAccountLoaderConfig, true)
	if err != nil {
		log.Fatalf("Error initializing remote service account loader: %v", err)
	}

	authService, err := authservice.NewAuthService("http://localhost/core", "sample", "http://localhost:5000", nil, serviceAccountLoader)
	if err != nil {
		log.Fatalf("Error initializing auth service: %v", err)
	}

	serviceAccountLoader.SetAuthService(authService)

	// Instantiate a CoreService to utilize certain core services, such as reading deleted account IDs
	deletedAccountsConfig := coreservice.DeletedAccountsConfig{
		Callback: printDeletedAccountIDs,
	}
	logger := logs.NewLogger("example", nil)
	coreService, err := coreservice.NewCoreService(authService, &deletedAccountsConfig, true, logger)
	if err != nil {
		log.Printf("Error initializing core service: %v", err)
	}

	coreService.StartDeletedAccountsTimer()
}

func printDeletedAccountIDs(accountIDs []string) error {
	log.Printf("Deleted account IDs: %v\n", accountIDs)
	return nil
}
