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
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/rokwire/core-auth-library-go/authservice"
	"github.com/rokwire/logging-library-go/logs"
)

// CoreService contains configurations and helper functions required to utilize certain core services
type CoreService struct {
	authService *authservice.AuthService

	deletedAccountsConfig *DeletedAccountsConfig

	logger *logs.Logger
}

func (c *CoreService) getDeletedAccountsWithRetry() ([]string, error) {
	if err := c.authService.CheckServiceAccountLoader(); err != nil {
		return nil, fmt.Errorf("error getting deleted accounts: %v", err)
	}

	accountIDs, err := c.requestDeletedAccounts()
	if err != nil {
		if strings.HasPrefix(err.Error(), "error getting deleted accounts: 401") {
			// access token may have expired, so get a new one and try once more
			tokenErr := c.authService.ServiceAccountLoader.GetAccessToken()
			if tokenErr != nil {
				return nil, fmt.Errorf("error getting new access token - %v - after %v", tokenErr, err)
			}

			accountIDs, err = c.requestDeletedAccounts()
			if err != nil {
				return nil, err
			}

			return accountIDs, nil
		}

		return nil, err
	}

	return accountIDs, nil
}

func (c *CoreService) requestDeletedAccounts() ([]string, error) {
	if err := c.authService.CheckServiceAccountLoader(); err != nil {
		return nil, fmt.Errorf("error requesting deleted accounts: %v", err)
	}

	client := &http.Client{}
	req, err := http.NewRequest("GET", c.authService.GetHost()+c.deletedAccountsConfig.Path, nil)
	if err != nil {
		return nil, fmt.Errorf("error formatting request to get deleted accounts: %v", err)
	}

	req.Header.Set("Authorization", c.authService.ServiceAccountLoader.AccessTokenString())

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error requesting deleted accounts: %v", err)
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading body of deleted accounts response: %v", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("error getting deleted accounts: %d - %s", resp.StatusCode, string(body))
	}

	var deletedAccounts []string
	err = json.Unmarshal(body, &deletedAccounts)
	if err != nil {
		return nil, fmt.Errorf("error on unmarshal deleted accounts response: %v", err)
	}

	return deletedAccounts, nil
}

// StartDeletedAccountsTimer starts a timer that periodically retrieves deleted account IDs
func (c *CoreService) StartDeletedAccountsTimer() {
	//cancel if active
	if c.deletedAccountsConfig.timer != nil {
		c.deletedAccountsConfig.timerDone <- true
		c.deletedAccountsConfig.timer.Stop()
	}

	c.getDeletedAccounts(c.deletedAccountsConfig.Callback)
}

func (c *CoreService) getDeletedAccounts(callback func([]string) error) {
	accountIDs, err := c.getDeletedAccountsWithRetry()
	if err != nil && c.logger != nil {
		c.logger.Error(err.Error())
	}

	err = callback(accountIDs)
	if err != nil && c.logger != nil {
		c.logger.Errorf("Received error from callback function: %v", err)
	}

	duration := time.Hour * time.Duration(int64(c.deletedAccountsConfig.Period))
	c.deletedAccountsConfig.timer = time.NewTimer(duration)
	select {
	case <-c.deletedAccountsConfig.timer.C:
		// timer expired
		c.deletedAccountsConfig.timer = nil

		c.getDeletedAccounts(callback)
	case <-c.deletedAccountsConfig.timerDone:
		// timer aborted
		c.deletedAccountsConfig.timer = nil
	}
}

// NewCoreService creates and configures a new RemoteServiceAccountLoaderImpl instance for the provided auth services url
func NewCoreService(authService *authservice.AuthService, deletedAccountsConfig *DeletedAccountsConfig, firstParty bool, logger *logs.Logger) (*CoreService, error) {
	if authService == nil {
		return nil, errors.New("auth service is missing")
	}

	if deletedAccountsConfig != nil {
		checkDeletedAccountsConfig(deletedAccountsConfig, firstParty)
	}

	core := CoreService{authService: authService, deletedAccountsConfig: deletedAccountsConfig, logger: logger}

	return &core, nil
}

func checkDeletedAccountsConfig(config *DeletedAccountsConfig, firstParty bool) {
	if config.Path == "" {
		if firstParty {
			config.Path = "/bbs/deleted-accounts"
		} else {
			config.Path = "/tps/deleted-accounts"
		}
	}

	if config.Callback != nil {
		config.timerDone = make(chan bool)
		if config.Period == 0 {
			config.Period = 2
		}
	}
}

//DeletedAccountsConfig represents a configuration for getting deleted accounts from a remote host
type DeletedAccountsConfig struct {
	Path     string               // Path to auth service deleted accounts API
	Callback func([]string) error // Function to call once the deleted accounts are received
	Period   uint                 // How often to request deleted account list (in hours)

	timerDone chan bool
	timer     *time.Timer
}
