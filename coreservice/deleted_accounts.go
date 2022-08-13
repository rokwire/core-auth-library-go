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
	"fmt"
	"net/http"
	"time"

	"github.com/rokwire/core-auth-library-go/v2/authutils"
)

// StartDeletedAccountsTimer starts a timer that periodically retrieves deleted account IDs
func (c *CoreService) StartDeletedAccountsTimer() {
	config := c.configs["deleted-accounts"]
	if config == nil {
		c.logger.Error("core service is missing a deleted accounts config")
	}

	//cancel timer if active
	config.checkTimer()
	c.getDeletedAccountsWithCallback(config)
}

func (c *CoreService) getDeletedAccountsWithCallback(config CoreOperationConfig) {
	path := config.getMetadata()["path"]
	accountIDs, err := c.getDeletedAccounts(path)
	if err != nil && c.logger != nil {
		c.logger.Error(err.Error())
	}

	//do callback
	err = config.makeCallback(accountIDs, err)
	if err != nil {
		c.logger.Error(err.Error())
	}

	//start timer
	config.startTimer(c.getDeletedAccountsWithCallback)
}

func (c *CoreService) getDeletedAccounts(path string) ([]string, error) {
	accountIDs := make([]string, 0)

	req, err := c.buildDeletedAccountsRequest(path)
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

func (c *CoreService) buildDeletedAccountsRequest(path string) (*http.Request, error) {
	req, err := http.NewRequest("GET", c.serviceAccountManager.AuthService.AuthBaseURL+path, nil)
	if err != nil {
		return nil, fmt.Errorf("error formatting request to get deleted accounts: %v", err)
	}

	return req, nil
}

// DeletedAccountsConfig represents a configuration for getting deleted accounts from a remote core service
type DeletedAccountsConfig struct {
	Callback func([]string, error) // Function to call once the deleted accounts are received
	Period   uint                  // How often to request deleted account list in hours (the default is 2)

	path      string
	timerDone chan bool
	timer     *time.Timer
}

func (dac *DeletedAccountsConfig) setup(firstParty bool) {
	dac.path = "/tps/deleted-accounts"
	if firstParty {
		dac.path = "/bbs/deleted-accounts"
	}

	if dac.Callback != nil {
		dac.timerDone = make(chan bool)
		if dac.Period == 0 {
			dac.Period = 2
		}
	}
}

func (dac *DeletedAccountsConfig) getMetadata() map[string]string {
	return map[string]string{"id": "deleted-accounts", "path": dac.path}
}

func (dac *DeletedAccountsConfig) makeCallback(data interface{}, err error) error {
	accountIDs, ok := data.([]string)
	if !ok {
		return fmt.Errorf("failed to parse data as list of account IDs: %v", data)
	}

	dac.Callback(accountIDs, err)
	return nil
}

func (dac *DeletedAccountsConfig) startTimer(onExpired func(CoreOperationConfig)) {
	duration := time.Hour * time.Duration(int64(dac.Period))
	dac.timer = time.NewTimer(duration)
	select {
	case <-dac.timer.C:
		// timer expired
		dac.timer = nil

		onExpired(dac)
	case <-dac.timerDone:
		// timer aborted
		dac.timer = nil
	}
}

func (dac *DeletedAccountsConfig) checkTimer() {
	if dac.timer != nil {
		dac.StopTimer()
	}
}

// StopTimer stops the deleted accounts timer
func (dac *DeletedAccountsConfig) StopTimer() {
	dac.timerDone <- true
	dac.timer.Stop()
}
