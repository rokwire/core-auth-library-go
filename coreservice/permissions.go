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
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/rokwire/core-auth-library-go/v2/authutils"
)

// RegisterPermissions sends a request to the Core Building Block to update service permissions
func (c *CoreService) RegisterPermissions() {
	config := c.configs["permissions"]
	if config == nil {
		c.logger.Error("core service is missing a permissions config")
	}

	metadata := config.getMetadata()
	success, err := c.updatePermissions(metadata["path"], metadata["policy_path"])

	//do callback
	err = config.makeCallback(success, err)
	if err != nil {
		c.logger.Error(err.Error())
	}
}

func (c *CoreService) updatePermissions(path string, policyPath string) (bool, error) {
	req, err := c.buildPermissionsRequest(path, policyPath)
	if err != nil {
		return false, fmt.Errorf("error building update permissions request: %v", err)
	}

	appOrgPairs := c.serviceAccountManager.AppOrgPairs()
	if len(appOrgPairs) == 0 {
		return false, errors.New("this service has not been granted access to any app org pairs")
	}
	response, err := c.serviceAccountManager.MakeRequest(req, appOrgPairs[0].AppID, appOrgPairs[0].OrgID)
	if err != nil {
		return false, fmt.Errorf("error making update permissions request: %v", err)
	}

	var body []byte
	success := response.StatusCode == http.StatusOK
	if !success {
		body, err = authutils.ReadResponseBody(response)
		if err != nil {
			return false, fmt.Errorf("error reading update permissions response body: %v", err)
		}

		err = errors.New(string(body))
	}

	return success, err
}

func (c *CoreService) buildPermissionsRequest(path string, policyPath string) (*http.Request, error) {
	csvFile, err := os.Open(policyPath)
	if err != nil {
		return nil, fmt.Errorf("error opening auth policy file %s: %v", policyPath, err)
	}
	reader := csv.NewReader(csvFile)
	permissionData, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("error reading auth policy file %s: %v", policyPath, err)
	}

	namesParsed := make([]string, 0)
	permissions := make([]permission, 0)
	for _, pData := range permissionData {
		name := strings.TrimSpace(pData[1])
		if !authutils.ContainsString(namesParsed, name) {
			permissions = append(permissions, permission{Name: name, Description: strings.TrimSpace(pData[4])})
		}
	}

	data, err := json.Marshal(permissions)
	if err != nil {
		return nil, fmt.Errorf("error marshaling request body to get access token: %v", err)
	}
	req, err := http.NewRequest("PUT", c.serviceAccountManager.AuthService.AuthBaseURL+path, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("error formatting request to get deleted accounts: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	return req, nil
}

type permission struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// PermissionsConfig represents a configuration for registering permissions with a remote core service
type PermissionsConfig struct {
	Callback   func(bool, error) // Function to call once the response is received
	PolicyPath string

	path string
}

func (pc *PermissionsConfig) setup(firstParty bool) {
	pc.path = "/tps/permissions"
	if firstParty {
		pc.path = "/bbs/permissions"
	}
}

func (pc *PermissionsConfig) getMetadata() map[string]string {
	return map[string]string{"id": "permissions", "path": pc.path, "policy_path": pc.PolicyPath}
}

func (pc *PermissionsConfig) makeCallback(data interface{}, err error) error {
	success, ok := data.(bool)
	if !ok {
		return fmt.Errorf("failed to parse data as success flag: %v", data)
	}

	pc.Callback(success, err)
	return nil
}

func (pc *PermissionsConfig) startTimer(onExpired func(CoreOperationConfig)) {}

func (pc *PermissionsConfig) checkTimer() {}
