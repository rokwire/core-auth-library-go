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
	"errors"

	"github.com/rokwire/core-auth-library-go/v2/authservice"
	"github.com/rokwire/logging-library-go/logs"
)

// CoreService contains configurations and helper functions required to utilize certain core services
type CoreService struct {
	serviceAccountManager *authservice.ServiceAccountManager

	configs map[string]CoreOperationConfig

	logger *logs.Logger
}

// NewCoreService creates and configures a new CoreService instance
func NewCoreService(serviceAccountManager *authservice.ServiceAccountManager, logger *logs.Logger, configs ...CoreOperationConfig) (*CoreService, error) {
	if serviceAccountManager == nil {
		return nil, errors.New("service account manager is missing")
	}

	configMap := make(map[string]CoreOperationConfig)
	for _, config := range configs {
		if config != nil {
			config.setup(serviceAccountManager.AuthService.FirstParty)
			metadata := config.getMetadata()
			configMap[metadata["id"]] = config
		}
	}

	core := CoreService{serviceAccountManager: serviceAccountManager, configs: configMap, logger: logger}
	return &core, nil
}

// CoreOperationConfig defines a set of functions a configuration must perform to facilitate interactions with the Core Building Block
type CoreOperationConfig interface {
	setup(firstParty bool)
	getMetadata() map[string]string
	makeCallback(data interface{}, err error) error
	startTimer(onExpired func(CoreOperationConfig))
	checkTimer()
}
