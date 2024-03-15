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
	"net/url"
	"time"

	"github.com/rokwire/core-auth-library-go/v3/authservice"
	"github.com/rokwire/core-auth-library-go/v3/authutils"
	"github.com/rokwire/logging-library-go/v2/logs"
)

// CoreService contains configurations and helper functions required to utilize certain core services
type CoreService struct {
	serviceAccountManager *authservice.ServiceAccountManager

	deletedMembershipsConfig *DeletedMembershipsConfig

	logger *logs.Logger
}

// StartDeletedMembershipsTimer starts a timer that periodically retrieves IDs for accounts with deleted app memberships
func (c *CoreService) StartDeletedMembershipsTimer() {
	//cancel if active
	if c.deletedMembershipsConfig.timer != nil {
		c.deletedMembershipsConfig.timerDone <- true
		c.deletedMembershipsConfig.timer.Stop()
	}

	c.getDeletedMembershipsWithCallback(c.deletedMembershipsConfig.Callback)
}

func (c *CoreService) getDeletedMembershipsWithCallback(callback func([]DeletedOrgAppMemberships) error) {
	memberships, err := c.getDeletedMemberships()
	if err != nil && c.logger != nil {
		c.logger.Error(err.Error())
	}

	err = callback(memberships)
	if err != nil && c.logger != nil {
		c.logger.Errorf("received error from callback function: %v", err)
	}

	duration := time.Hour * time.Duration(int64(c.deletedMembershipsConfig.Period))
	c.deletedMembershipsConfig.timer = time.NewTimer(duration)
	select {
	case <-c.deletedMembershipsConfig.timer.C:
		// timer expired
		c.deletedMembershipsConfig.timer = nil

		c.getDeletedMembershipsWithCallback(callback)
	case <-c.deletedMembershipsConfig.timerDone:
		// timer aborted
		c.deletedMembershipsConfig.timer = nil
	}
}

func (c *CoreService) getDeletedMemberships() ([]DeletedOrgAppMemberships, error) {
	allDeleted := make([]DeletedOrgAppMemberships, 0)

	req, err := c.buildDeletedMembershipsRequest()
	if err != nil {
		return nil, fmt.Errorf("error building deleted memberships request: %v", err)
	}

	responses := c.serviceAccountManager.MakeRequests(req, nil)
	for _, reqResp := range responses {
		if reqResp.Error != nil && c.logger != nil {
			c.logger.Errorf("error making deleted memberships request: %v", reqResp.Error)
			continue
		}

		body, err := authutils.ReadResponseBody(reqResp.Response)
		if err != nil {
			return nil, fmt.Errorf("error reading deleted memberships response body: %v", err)
		}

		var deleted []DeletedOrgAppMemberships
		err = json.Unmarshal(body, &deleted)
		if err != nil {
			return nil, fmt.Errorf("error unmarshaling deleted memberships response body: %v", err)
		}

		allDeleted = append(allDeleted, deleted...)
	}

	return allDeleted, nil
}

func (c *CoreService) buildDeletedMembershipsRequest() (*http.Request, error) {
	deletedMembershipsURL := c.serviceAccountManager.AuthService.AuthBaseURL + c.deletedMembershipsConfig.path
	query := url.Values{}
	query.Set("service_id", c.serviceAccountManager.AuthService.ServiceID)

	req, err := http.NewRequest(http.MethodGet, deletedMembershipsURL+"?"+query.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("error formatting request to get deleted memberships: %v", err)
	}

	return req, nil
}

// NewCoreService creates and configures a new CoreService instance
func NewCoreService(serviceAccountManager *authservice.ServiceAccountManager, deletedMembershipsConfig *DeletedMembershipsConfig, logger *logs.Logger) (*CoreService, error) {
	if serviceAccountManager == nil {
		return nil, errors.New("service account manager is missing")
	}

	if deletedMembershipsConfig != nil {
		deletedMembershipsConfig.path = "/tps/deleted-memberships"
		if serviceAccountManager.AuthService.FirstParty {
			deletedMembershipsConfig.path = "/bbs/deleted-memberships"
		}

		if deletedMembershipsConfig.Callback != nil {
			deletedMembershipsConfig.timerDone = make(chan bool)
			if deletedMembershipsConfig.Period == 0 {
				deletedMembershipsConfig.Period = 2
			}
		}
	}

	core := CoreService{serviceAccountManager: serviceAccountManager, deletedMembershipsConfig: deletedMembershipsConfig, logger: logger}

	return &core, nil
}

// DeletedMembershipsConfig represents a configuration for getting deleted account app memberships from a remote core service
type DeletedMembershipsConfig struct {
	Callback func([]DeletedOrgAppMemberships) error // Function to call once the deleted memberships are received
	Period   uint                                   // How often to request deleted memberships in hours (the default is 2)

	path      string
	timerDone chan bool
	timer     *time.Timer
}

// DeletedOrgAppMemberships represents a list of tenant (organization) accounts for which the app membership for the given app ID has been deleted
type DeletedOrgAppMemberships struct {
	Memberships []DeletedMembershipContext `json:"memberships"`
	AppID       string                     `json:"app_id"`
	OrgID       string                     `json:"org_id"`
}

// DeletedMembershipContext represents a single deleted account app membership with delete context
type DeletedMembershipContext struct {
	AccountID string                 `json:"account_id"`
	Context   map[string]interface{} `json:"context"`
}
