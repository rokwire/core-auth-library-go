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
	"time"

	"github.com/rokwire/core-auth-library-go/authservice"
	"github.com/rokwire/logging-library-go/logs"
)

// CoreService contains configurations and helper functions required to utilize certain core services
type CoreService struct {
	serviceAccountManager authservice.ServiceAccountManager

	deletedAccountsConfig *DeletedAccountsConfig

	logger *logs.Logger
}

func (c *CoreService) getDeletedAccounts() ([]string, error) {
	idChan := make(chan []string)
	errChan := make(chan error)
	accountIDs := make([]string, 0)
	errStr := ""

	for _, pair := range c.serviceAccountManager.CachedAppOrgPairs() {
		go c.getDeletedAccountsAsync(pair, idChan, errChan)
	}

	for i := 0; i < len(r.appOrgPairs); i++ {
		partialAccountIDs := <-idChan
		partialErr := <-errChan
		if partialErr != nil {
			if len(errStr) > 0 {
				errStr += ", " + partialErr.Error()
			} else {
				errStr += partialErr.Error()
			}
		} else if partialAccountIDs != nil {
			accountIDs = append(accountIDs, partialAccountIDs...)
		}
	}

	if errStr != "" {
		return accountIDs, errors.New(errStr)
	}
	return accountIDs, nil
}

func (c *CoreService) getDeletedAccountsAsync(appOrgPair AppOrgPair, c chan []string, e chan error) {
	var req *http.Request
	var resp *http.Response
	var body []byte
	var deleted []string
	var err error

	if req, err = r.buildDeletedAccountsRequest(); err == nil {
		if resp, err = r.MakeRequest(req, appOrgPair.AppID, appOrgPair.OrgID); err == nil {
			if body, err = r.ReadResponse(resp); err == nil {
				err = json.Unmarshal(body, &deleted)
			}
		}
	}

	c <- deleted
	e <- err
}

func (c *CoreService) buildDeletedAccountsRequest() (*http.Request, error) {
	req, err := http.NewRequest("GET", r.config.AuthServicesHost+r.config.DeletedAccountsPath, nil)
	if err != nil {
		return nil, fmt.Errorf("error formatting request to get deleted accounts: %v", err)
	}

	return req, nil
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

		c.getDeletedAccounts(callback)
	case <-c.deletedAccountsConfig.timerDone:
		// timer aborted
		c.deletedAccountsConfig.timer = nil
	}
}

// NewCoreService creates and configures a new CoreService instance
func NewCoreService(serviceAccountManager authservice.ServiceAccountManager, deletedAccountsConfig *DeletedAccountsConfig, firstParty bool, logger *logs.Logger) (*CoreService, error) {
	if serviceAccountManager == nil {
		return nil, errors.New("service account manager is missing")
	}

	if deletedAccountsConfig != nil {
		if deletedAccountsConfig.Host == "" {
			return nil, errors.New("deleted accounts host is missing")
		}
		checkDeletedAccountsConfig(deletedAccountsConfig, firstParty)
	}

	core := CoreService{serviceAccountManager: serviceAccountManager, deletedAccountsConfig: deletedAccountsConfig, logger: logger}

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
	Host     string               //URL of accounts host
	Path     string               // Path to deleted accounts API
	Callback func([]string) error // Function to call once the deleted accounts are received
	Period   uint                 // How often to request deleted account list (in hours)

	timerDone chan bool
	timer     *time.Timer
}
