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

package testutils

import (
	"fmt"

	"github.com/rokwire/core-auth-library-go/v3/authservice"
	"github.com/rokwire/core-auth-library-go/v3/authservice/mocks"
	"github.com/rokwire/core-auth-library-go/v3/keys"
)

// GetSampleRSAPubKeyPem returns a sample RSA public key PEM
//
//	Matches GetSampleRSAPrivKeyPem
func GetSampleRSAPubKeyPem() string {
	return `-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq2gWKpPRb2xQRee4OXbg
KMzGAy8aPcAqgfL8xmi7tozoi917QHL4qi4PHn/7v0K6eAKdq1Vh6dlLmcWbl1Gy
4IDkf8bDAmUKdezWw6jrnKTW+XZ8S5lsqNSYH07R7aRxJPlugta13fMWphs58LTo
whQcu1zBCqjEAUooqyWq3XDmic4wbVIp5HvlaayZ7Q+ifDliULxSRqAAUrQZ5DQv
gtnZ3Dq/93gGbAjnpXl3txfgeQH5NpJN6fFsjm48PFP+Byw5VOslOBh6dtaI6ldR
Am8DIClWwZ9867p8gpeZpvBsE/sIXUEs/r608oZf6+D3OfIfQUkCq9Knxjgdho8E
SwIDAQAB
-----END RSA PUBLIC KEY-----`
}

// GetSampleES256PubKeyPem returns a sample EC P-256 public key PEM
//
//	Matches GetSampleES256PrivKeyPem
func GetSampleES256PubKeyPem() string {
	return `-----BEGIN EC PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE3ZqNXCKDxk6eoi8kBs3L18mJ8OIh
wnakdI4vwpWHIgQUgouS33b6D+mt8FZYcCvnzsll1kLcf+iL2jtLJjpGXQ==
-----END EC PUBLIC KEY-----`
}

// GetSampleEdPubKeyPem returns a sample Ed public key PEM
//
//	Matches GetSampleEdPrivKeyPem
func GetSampleEdPubKeyPem() string {
	return `-----BEGIN EdDSA PUBLIC KEY-----
MCowBQYDK2VwAyEAtlAhVIrYwUQUzRb/BiiwPLX8N4brzA+xl3n0VdxqrU8=
-----END EdDSA PUBLIC KEY-----`
}

// GetSamplePubKey returns a sample PubKey
func GetSamplePubKey(alg string) (*keys.PubKey, error) {
	key := keys.PubKey{Alg: alg}
	switch alg {
	case keys.RS256, keys.RS384, keys.RS512, keys.PS256, keys.PS384, keys.PS512:
		key.KeyPem = GetSampleRSAPubKeyPem()
	case keys.ES256:
		key.KeyPem = GetSampleES256PubKeyPem()
	case keys.EdDSA:
		key.KeyPem = GetSampleEdPubKeyPem()
	default:
		return nil, fmt.Errorf("unsupported algorithm %s", alg)
	}

	err := key.Decode()
	if err != nil {
		return nil, err
	}

	return &key, nil
}

// GetSamplePubKeyFingerprint returns a sample RSA public key fingerprint
func GetSamplePubKeyFingerprint(keyType string) string {
	switch keyType {
	case keys.KeyTypeRSA:
		return "SHA256:I3HxcO3FpUM6MG7+rCASuePfl92JEcdz2htV7SP0Y20="
	case keys.KeyTypeEC:
		return "SHA256:+cXb9HRXd4/9aDaUUz6sEeZALYQUanD1II7IsO+eSVw="
	case keys.KeyTypeEdDSA:
		return "SHA256:D71hsVhSaq3v6SjAISLH24whiI1Ka1wR1IBQoPSfjI4="
	default:
		return ""
	}
}

// GetSampleRSAPrivKeyPem returns a sample RSA private key PEM
//
//	Matches GetSamplePubKeyPem
func GetSampleRSAPrivKeyPem() string {
	return `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAq2gWKpPRb2xQRee4OXbgKMzGAy8aPcAqgfL8xmi7tozoi917
QHL4qi4PHn/7v0K6eAKdq1Vh6dlLmcWbl1Gy4IDkf8bDAmUKdezWw6jrnKTW+XZ8
S5lsqNSYH07R7aRxJPlugta13fMWphs58LTowhQcu1zBCqjEAUooqyWq3XDmic4w
bVIp5HvlaayZ7Q+ifDliULxSRqAAUrQZ5DQvgtnZ3Dq/93gGbAjnpXl3txfgeQH5
NpJN6fFsjm48PFP+Byw5VOslOBh6dtaI6ldRAm8DIClWwZ9867p8gpeZpvBsE/sI
XUEs/r608oZf6+D3OfIfQUkCq9Knxjgdho8ESwIDAQABAoIBAApl4Pruq2Avy2hD
WjzXUX6O+q/W5yfVZPor1Cxx8sLsSqZDJobcJOoDGSKzKriALCOEmj/V5H/CyCk2
0q1ppNtcXS3omTCVNrW9FEOblzNthxS1eCPRnul9ABG4/rK7fvTDdt/UCCoxdyZW
4uj9KIFBgcxoxLDaxjG6HrwrugNssME6LnuA1DQQROIaV8qM60ygRBSRNGDSBHFf
oUrjG6hHXEFClVyLuYGz4OS6HKwKPitFwPYTyL4axMXfY2BrmVOYpRmhu+LgOLPW
NZFj6E9ffFp+Gz49vcM+ceT7is111Qd70eKBLOgzIco46VFEkPpRM0ecUyxWUN4b
AGDjvS0CgYEAtuHyttEByqGI5mm5Uqq8r/E0ktaw/ijTNA65iKCAVxZy1nOkditx
riwH1tfrigSdcSy+FsYyqYjjCuKvgKJXZixKIoXjN75sAxJs8FV8yM0VrOuuyYHu
pTsdslgLRT2eGW+BreVZ9QsgZr3RLmOVUgnpPP+l5cmJoaZsxT95RYUCgYEA7++R
DnRwlklyBH2WdZiXXn5VfVr4c4+m5mbm9pDg1Y+JTfZVbH3L8A3yWuSf9KHuLOBg
Z4VNus3PIiTBSbC/C8j3MUUU4hIg/PANbMPy58abkoqynhQoe5nXUVyx/pqrYLXQ
flrzUh3dxOiHNdqBDBuGBzmb59eNBcjICyEQI48CgYBvCarjQu1yiTdkpoZl4dJk
hO/lw8J83m61qccOZFzoA3JAMMCHGwOPu54a3Mhe6URqhb74dugltT4cytvCH08v
cu6kHWSC4PQVvWc1WMJF7PcfIY3jPSeXXNhAA2L8bFgEm4ZB/gHrXREUMGXEY6Qy
xl+9sH6akQ4mfrSF4m8QPQKBgFw0Qxk78/w9EzzYilZ8okbk47N9nxbBsJDAIKfG
OzC2rTwxmthLa3C/20/EphebluzV+RYvKxTLfHsRhtnruy8rNptPgdvyvYyWL4KJ
trINJ8Hj3QpUks4U66LPrXM7Ovq6Q/oat4DqC0xdU4CFjKv7c8EZCWnJ8t6zLvTf
6tTPAoGBAJz9PPAeCrPlbdPT2VixLRBZ535GWUDsA72XIWYDG8JgqV+8mbfON5AG
XRkS0kCJMoyX5SP+YehH2tVXrthtsUmn7xoppOoccRBvEwD9f5hGKCbLa14vZXha
Rv8MYg+8RiGNsPSmC6qTu9ykuRn3a2DF6/vlrZuWlnRnkI6EF91Q
-----END RSA PRIVATE KEY-----`
}

// GetSampleES256PrivKeyPem returns a sample EC P-256 private key PEM
//
//	Matches GetSampleES256PubKeyPem
func GetSampleES256PrivKeyPem() string {
	return `-----BEGIN EC PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgRdUWPcrKaQSrE0oq
s56u8pWgkr3R+7x9HfpC50CmB/ShRANCAATdmo1cIoPGTp6iLyQGzcvXyYnw4iHC
dqR0ji/ClYciBBSCi5LfdvoP6a3wVlhwK+fOyWXWQtx/6IvaO0smOkZd
-----END EC PRIVATE KEY-----`
}

// GetSampleEdPrivKeyPem returns a sample Ed private key PEM
//
//	Matches GetSampleEdPubKeyPem
func GetSampleEdPrivKeyPem() string {
	return `-----BEGIN EdDSA PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIDYv4zWzHL+ta4KYtqGPrxeTUeIRjDsUaN0DPNIHFeQ8
-----END EdDSA PRIVATE KEY-----`
}

// GetSamplePrivKey returns a sample PrivKey
func GetSamplePrivKey(alg string) (*keys.PrivKey, error) {
	privKey := keys.PrivKey{Alg: alg}
	switch alg {
	case keys.RS256, keys.RS384, keys.RS512, keys.PS256, keys.PS384, keys.PS512:
		privKey.KeyPem = GetSampleRSAPrivKeyPem()
	case keys.ES256:
		privKey.KeyPem = GetSampleES256PrivKeyPem()
	case keys.EdDSA:
		privKey.KeyPem = GetSampleEdPrivKeyPem()
	default:
		return nil, fmt.Errorf("unsupported algorithm %s", alg)
	}

	err := privKey.Decode()
	if err != nil {
		return nil, err
	}

	return &privKey, nil
}

// SetupTestAuthService returns a test AuthService
func SetupTestAuthService(serviceID string, serviceHost string) *authservice.AuthService {
	return &authservice.AuthService{ServiceID: serviceID, ServiceHost: serviceHost}
}

// SetupMockServiceRegLoader returns a mock ServiceRegLoader
func SetupMockServiceRegLoader(authService *authservice.AuthService, subscribed []string, result []authservice.ServiceReg, err error) *mocks.ServiceRegLoader {
	mockLoader := mocks.NewServiceRegLoader(authService, subscribed)
	mockLoader.On("LoadServices").Return(result, err)
	return mockLoader
}

// SetupTestServiceRegManager returns a test ServiceRegManager
func SetupTestServiceRegManager(authService *authservice.AuthService, mockDataLoader *mocks.ServiceRegLoader) (*authservice.ServiceRegManager, error) {
	return authservice.NewTestServiceRegManager(authService, mockDataLoader)
}

// SetupMockServiceAccountTokenLoader returns a mock ServiceAccountLoader which loads a single access token
func SetupMockServiceAccountTokenLoader(authService *authservice.AuthService, appID string, orgID string, token *authservice.AccessToken, err error) *mocks.ServiceAccountLoader {
	mockLoader := mocks.NewServiceAccountLoader(authService)
	mockLoader.On("LoadAccessToken", appID, orgID).Return(token, err)
	return mockLoader
}

// SetupMockServiceAccountTokensLoader returns a mock ServiceAccountLoader which loads a set of access tokens
func SetupMockServiceAccountTokensLoader(authService *authservice.AuthService, tokens map[authservice.AppOrgPair]authservice.AccessToken, err error) *mocks.ServiceAccountLoader {
	mockLoader := mocks.NewServiceAccountLoader(authService)
	mockLoader.On("LoadAccessTokens").Return(tokens, err)
	return mockLoader
}

// SetupTestServiceAccountManager returns a test ServiceAccountManager
func SetupTestServiceAccountManager(authService *authservice.AuthService, mockDataLoader *mocks.ServiceAccountLoader, loadTokens bool) (*authservice.ServiceAccountManager, error) {
	return authservice.NewTestServiceAccountManager(authService, mockDataLoader, loadTokens)
}

// SetupExampleMockServiceRegLoader returns an example mock ServiceRegLoader
func SetupExampleMockServiceRegLoader() (*mocks.ServiceRegLoader, error) {
	samplePubKey, err := GetSamplePubKey(keys.RS256)
	if err != nil {
		return nil, fmt.Errorf("error getting sample pubkey: %v", err)
	}
	testServiceReg := authservice.ServiceReg{ServiceID: "sample", Host: "https://sample.rokwire.com", PubKey: nil}
	authServiceReg := authservice.ServiceReg{ServiceID: "auth", Host: "https://auth.rokwire.com", PubKey: samplePubKey}
	serviceRegsValid := []authservice.ServiceReg{authServiceReg, testServiceReg}

	mockLoader := mocks.NewServiceRegLoader(SetupTestAuthService("sample", "https://sample.rokwire.com"), nil)
	mockLoader.On("LoadServices").Return(serviceRegsValid, nil)

	return mockLoader, nil
}
