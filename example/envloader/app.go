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
	"github.com/rokwire/core-auth-library-go/v2/envloader"
	"github.com/rokwire/logging-library-go/logs"
)

var (
	// Version : version of this executable
	Version string
	// Build : build date of this executable
	Build string
)

func main() {
	if len(Version) == 0 {
		Version = "dev"
	}

	logger := logs.NewLogger("sample", nil)
	envLoader := envloader.NewEnvLoader(Version, logger)

	envVar := envLoader.GetEnvVar("SAMPLE_ENV_VAR", false)
	requiredVar := envLoader.GetEnvVar("REQUIRED_ENV_VAR", true)

	logger.Infof("SAMPLE_ENV_VAR = %s, REQUIRED_ENV_VAR = %s", envVar, requiredVar)
}
