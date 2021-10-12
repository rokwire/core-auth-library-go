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

package envloader

import (
	"encoding/base64"
	"encoding/json"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
)

// -------------------- EnvLoader --------------------

// EnvLoader is an interface to assist with environment variable loading
type EnvLoader interface {
	// GetEnvVar returns the environment variable value with the specified key
	// 	If required and key is not found, a fatal log will be generated. Otherwise an empty string is returned
	GetEnvVar(key string, required bool) string
	// GetAndLogEnvVar returns and logs the environment variable value with the specified key
	// 	If required and key is not found, a fatal log will be generated. Otherwise an empty string is returned
	// 	If sensitive, the value of the environment variable will not be logged
	GetAndLogEnvVar(key string, required bool, sensitive bool) string
}

// NewEnvLoader initializes and returns an EnvLoader, using AWSSecretsManagerEnvLoader if configured
func NewEnvLoader(version string, logger *logs.Logger) EnvLoader {
	secretName := os.Getenv("APP_SECRET_ARN")
	region := os.Getenv("AWS_REGION")
	if secretName != "" && region != "" {
		return NewAWSSecretsManagerEnvLoader(secretName, region, version, logger)
	}
	return NewLocalEnvLoader(version, logger)
}

// -------------------- LocalEnvLoader --------------------

// LocalEnvLoader is an EnvLoader implementation which loads variables from the local system environment
type LocalEnvLoader struct {
	logger  *logs.Logger
	version string
}

// GetEnvVar implements EnvLoader
func (l *LocalEnvLoader) GetEnvVar(key string, required bool) string {
	value, exist := os.LookupEnv(key)
	if !exist {
		if required {
			l.logger.Fatal("No environment variable " + key)
		} else {
			l.logger.Error("No environment variable " + key)
		}
	}
	return value
}

// GetAndLogEnvVar implements EnvLoader
func (l *LocalEnvLoader) GetAndLogEnvVar(key string, required bool, sensitive bool) string {
	value := l.GetEnvVar(key, required)
	logEnvVar(key, value, sensitive, l.version, l.logger)
	return value
}

// NewLocalEnvLoader instantiates a new LocalEnvLoader instance
func NewLocalEnvLoader(version string, logger *logs.Logger) *LocalEnvLoader {
	return &LocalEnvLoader{version: version, logger: logger}
}

// -------------------- AWSSecretsManagerEnvLoader --------------------

// AWSSecretsManagerEnvLoader is an EnvLoader implementation which loads variables from an AWS SecretsManager secret
type AWSSecretsManagerEnvLoader struct {
	logger  *logs.Logger
	version string

	secrets map[string]string
}

// GetEnvVar implements EnvLoader
func (a *AWSSecretsManagerEnvLoader) GetEnvVar(key string, required bool) string {
	value, exist := a.secrets[key]
	if !exist {
		if required {
			a.logger.Fatal("No environment variable " + key)
		} else {
			a.logger.Error("No environment variable " + key)
		}
	}
	return value
}

// GetAndLogEnvVar implements EnvLoader
func (l *AWSSecretsManagerEnvLoader) GetAndLogEnvVar(key string, required bool, sensitive bool) string {
	value := l.GetEnvVar(key, required)
	logEnvVar(key, value, sensitive, l.version, l.logger)
	return value
}

// NewLocalEnvLoader instantiates a new AWSSecretsManagerEnvLoader instance
func NewAWSSecretsManagerEnvLoader(secretName string, region string, version string, logger *logs.Logger) *AWSSecretsManagerEnvLoader {
	if secretName == "" {
		logger.Fatal("Secret name cannot be empty")
	}

	if region == "" {
		logger.Fatal("Region cannot be empty")
	}

	s, err := session.NewSession(&aws.Config{
		Region: &region,
	})
	if err != nil {
		logger.Fatalf("Error creating AWS session - SecretName: %s, Region: %s, Error: %v", secretName, region, err)
	}

	svc := secretsmanager.New(s)
	input := &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(secretName),
		VersionStage: aws.String("AWSCURRENT"),
	}

	result, err := svc.GetSecretValue(input)
	if err != nil {
		logger.Fatalf("Error loading secrets manager secret - Name: %s, Region: %s, Error: %v", secretName, region, err)
	}

	var secretConfigs map[string]string
	var secretString, decodedBinarySecret string
	if result.SecretString != nil {
		secretString = *result.SecretString
		err := json.Unmarshal([]byte(secretString), &secretConfigs)
		if err != nil {
			logger.Fatalf("Failed to unmarshal secrets: %v", err)
		}
	} else {
		decodedBinarySecretBytes := make([]byte, base64.StdEncoding.DecodedLen(len(result.SecretBinary)))
		len, err := base64.StdEncoding.Decode(decodedBinarySecretBytes, result.SecretBinary)
		if err != nil {
			logger.Fatalf("Secrets Base64 Decode Error: %v", err)
		}
		decodedBinarySecret = string(decodedBinarySecretBytes[:len])
		err = json.Unmarshal([]byte(decodedBinarySecret), &secretConfigs)
		if err != nil {
			logger.Fatalf("Failed to unmarshal secrets: %v", err)
		}
	}

	if secretConfigs == nil {
		logger.Fatal("Secrets are nil")
	}

	return &AWSSecretsManagerEnvLoader{secrets: secretConfigs, version: version, logger: logger}
}

func logEnvVar(name string, value string, sensitive bool, version string, logger *logs.Logger) {
	if version == "dev" {
		if sensitive {
			logger.InfoWithFields("ENV_VAR", logutils.Fields{"name": name})
		} else {
			logger.InfoWithFields("ENV_VAR", logutils.Fields{"name": name, "value": value})
		}
	}
}
