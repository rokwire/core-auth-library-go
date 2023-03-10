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

package coreservice

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/rokwire/core-auth-library-go/v3/authservice"
	"github.com/rokwire/core-auth-library-go/v3/authutils"
	"github.com/rokwire/logging-library-go/v2/logs"
)

// CoreService contains configurations and helper functions required to utilize certain core services
type CoreService struct {
	serviceAccountManager *authservice.ServiceAccountManager

	deletedAccountsConfig *DeletedAccountsConfig

	logger *logs.Logger
}

// StartDeletedAccountsTimer starts a timer that periodically retrieves deleted account IDs
func (c *CoreService) StartDeletedAccountsTimer() {
	//cancel if active
	if c.deletedAccountsConfig.timer != nil {
		c.deletedAccountsConfig.timerDone <- true
		c.deletedAccountsConfig.timer.Stop()
	}

	c.getDeletedAccountsWithCallback(c.deletedAccountsConfig.Callback)
}

func (c *CoreService) getDeletedAccountsWithCallback(callback func([]string) error) {
	accountIDs, err := c.getDeletedAccounts()
	if err != nil && c.logger != nil {
		c.logger.Error(err.Error())
	}

	err = callback(accountIDs)
	if err != nil && c.logger != nil {
		c.logger.Errorf("received error from callback function: %v", err)
	}

	duration := time.Hour * time.Duration(int64(c.deletedAccountsConfig.Period))
	c.deletedAccountsConfig.timer = time.NewTimer(duration)
	select {
	case <-c.deletedAccountsConfig.timer.C:
		// timer expired
		c.deletedAccountsConfig.timer = nil

		c.getDeletedAccountsWithCallback(callback)
	case <-c.deletedAccountsConfig.timerDone:
		// timer aborted
		c.deletedAccountsConfig.timer = nil
	}
}

func (c *CoreService) getDeletedAccounts() ([]string, error) {
	accountIDs := make([]string, 0)

	req, err := c.buildDeletedAccountsRequest()
	if err != nil {
		return nil, fmt.Errorf("error building deleted accounts request: %v", err)
	}

	responses := c.serviceAccountManager.MakeRequests(req, nil)
	for _, reqResp := range responses {
		if reqResp.Error != nil && c.logger != nil {
			c.logger.Errorf("error making deleted accounts request: %v", reqResp.Error)
			continue
		}

		body, err := authutils.ReadResponseBody(reqResp.Response)
		if err != nil {
			return nil, fmt.Errorf("error reading deleted accounts response body: %v", err)
		}

		var deleted []string
		err = json.Unmarshal(body, &deleted)
		if err != nil {
			return nil, fmt.Errorf("error unmarshaling deleted accounts response body: %v", err)
		}

		accountIDs = append(accountIDs, deleted...)
	}

	return accountIDs, nil
}

func (c *CoreService) buildDeletedAccountsRequest() (*http.Request, error) {
	req, err := http.NewRequest("GET", c.serviceAccountManager.AuthService.AuthBaseURL+c.deletedAccountsConfig.path, nil)
	if err != nil {
		return nil, fmt.Errorf("error formatting request to get deleted accounts: %v", err)
	}

	return req, nil
}

// NewCoreService creates and configures a new CoreService instance
func NewCoreService(serviceAccountManager *authservice.ServiceAccountManager, deletedAccountsConfig *DeletedAccountsConfig, logger *logs.Logger) (*CoreService, error) {
	if serviceAccountManager == nil {
		return nil, errors.New("service account manager is missing")
	}

	if deletedAccountsConfig != nil {
		deletedAccountsConfig.path = "/tps/deleted-accounts"
		if serviceAccountManager.AuthService.FirstParty {
			deletedAccountsConfig.path = "/bbs/deleted-accounts"
		}

		if deletedAccountsConfig.Callback != nil {
			deletedAccountsConfig.timerDone = make(chan bool)
			if deletedAccountsConfig.Period == 0 {
				deletedAccountsConfig.Period = 2
			}
		}
	}

	core := CoreService{serviceAccountManager: serviceAccountManager, deletedAccountsConfig: deletedAccountsConfig, logger: logger}

	return &core, nil
}

// DeletedAccountsConfig represents a configuration for getting deleted accounts from a remote core service
type DeletedAccountsConfig struct {
	Callback func([]string) error // Function to call once the deleted accounts are received
	Period   uint                 // How often to request deleted account list in hours (the default is 2)

	path      string
	timerDone chan bool
	timer     *time.Timer
}
